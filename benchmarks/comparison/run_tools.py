"""Run every tool on every case and keep what each one reported, normalised.

Our scanner sees the pull request (base -> head), the way its GitHub Action runs.
The other tools scan the head, the way they run in CI. Each finding is kept with
its rule id, file, line and resource, and whether it lands on the case's target.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
CORPUS = BENCH / "corpus"
# The scanner under test; TFPDF_SCANNER points at another build, such as a fix branch.
SCANNER = Path(os.environ.get("TFPDF_SCANNER", BENCH / "scanner/.venv/bin/tf-predeploy-firewall"))
TFLINT = BENCH / "bin/tflint"
TFLINT_CONFIG = BENCH / "tflint.hcl"
CHECKOV = Path.home() / ".local/bin/checkov"
PLUGIN_CACHE = BENCH / "plugin-cache"

ENV = dict(os.environ, TF_PLUGIN_CACHE_DIR=str(PLUGIN_CACHE), CHECKOV_RUN_SCA_PACKAGE_SCAN_V2="false",
           BC_SKIP_MAPPING="TRUE", TFLINT_PLUGIN_DIR=str(BENCH / "tflint-plugins"))


def run(command, cwd=None, timeout=600):
    started = time.perf_counter()
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, env=ENV,
                               timeout=timeout)
    return completed, time.perf_counter() - started


def block_spans(path):
    """Map each top-level block address to its (first, last) line in a .tf file."""
    spans = {}
    lines = path.read_text().splitlines()
    depth = 0
    current = None
    for number, line in enumerate(lines, start=1):
        if depth == 0:
            match = re.match(r'\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"', line)
            module = re.match(r'\s*module\s+"([^"]+)"', line)
            if match:
                prefix = "data." if match.group(1) == "data" else ""
                current = (f"{prefix}{match.group(2)}.{match.group(3)}", number)
            elif module:
                current = (f"module.{module.group(1)}", number)
        depth += line.count("{") - line.count("}")
        if depth == 0 and current:
            spans[current[0]] = (current[1], number)
            current = None
    return spans


def on_target(label, head, finding):
    target = label["target"]
    file = (finding.get("file") or "").lstrip("./").lstrip("/")
    if target.startswith("file:"):
        return file.endswith(target[5:])
    if finding.get("resource") == target:
        return True
    line = finding.get("line")
    if not line or not file.endswith(".tf"):
        return False
    path = head / Path(file).name
    if not path.is_file() or Path(file).parent.name not in ("", "head", head.name):
        # A file the case does not contain: a downloaded module's, reported by validate.
        return False
    span = block_spans(path).get(target)
    return bool(span and span[0] <= line <= span[1])


def make_repository(case_dir, workspace):
    repository = workspace / "repository"
    shutil.copytree(case_dir / "base", repository)
    for command in (["git", "init", "-q", "-b", "main"],
                    ["git", "config", "user.email", "bench@example.com"],
                    ["git", "config", "user.name", "bench"],
                    ["git", "add", "-A"], ["git", "commit", "-q", "-m", "base"]):
        subprocess.run(command, cwd=repository, check=True, capture_output=True)
    for path in repository.iterdir():
        if path.name != ".git":
            path.unlink()
    for path in (case_dir / "head").iterdir():
        shutil.copy(path, repository / path.name)
    subprocess.run(["git", "add", "-A"], cwd=repository, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "head"], cwd=repository, check=True,
                   capture_output=True)
    return repository


def ours(case_dir, workspace):
    repository = make_repository(case_dir, workspace)
    sarif = workspace / "ours.sarif"
    completed, seconds = run([str(SCANNER), "--repo-dir", str(repository), "--base-ref", "HEAD~1",
                              "--head-ref", "HEAD", "--license-key", "", "--format", "text",
                              "--sarif-output", str(sarif)])
    findings = []
    if sarif.exists():
        for result in json.loads(sarif.read_text())["runs"][0]["results"]:
            location = result["locations"][0]["physicalLocation"]
            logical = (result["locations"][0].get("logicalLocations") or [{}])[0]
            findings.append(dict(id=result["ruleId"], level=result.get("level"),
                                 file=location["artifactLocation"]["uri"],
                                 line=location.get("region", {}).get("startLine"),
                                 resource=logical.get("fullyQualifiedName") or logical.get("name"),
                                 message=result["message"]["text"][:240]))
    return findings, seconds, completed


def checkov(head, workspace):
    completed, seconds = run([str(CHECKOV), "-d", str(head), "--framework", "terraform", "secrets",
                              "-o", "json", "--quiet", "--skip-download", "--compact"])
    findings = []
    try:
        reports = json.loads(completed.stdout)
    except json.JSONDecodeError:
        reports = []
    for report in reports if isinstance(reports, list) else [reports]:
        for check in report.get("results", {}).get("failed_checks", []):
            findings.append(dict(id=check["check_id"], file=check["file_path"],
                                 line=(check.get("file_line_range") or [None])[0],
                                 resource=check.get("resource"),
                                 message=check.get("check_name", "")[:240]))
    return findings, seconds, completed


def trivy(head, workspace):
    completed, seconds = run(["trivy", "fs", "--scanners", "misconfig,secret", "--format", "json",
                              "--quiet", "--skip-check-update", str(head)])
    findings = []
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report = {}
    for result in report.get("Results") or []:
        for item in result.get("Misconfigurations") or []:
            cause = item.get("CauseMetadata", {})
            findings.append(dict(id=item.get("AVDID") or item.get("ID"), level=item.get("Severity"),
                                 file=result["Target"], line=cause.get("StartLine"),
                                 resource=cause.get("Resource"),
                                 message=item.get("Title", "")[:240]))
        for item in result.get("Secrets") or []:
            findings.append(dict(id=item.get("RuleID"), level=item.get("Severity"),
                                 file=result["Target"], line=item.get("StartLine"),
                                 resource=None, message=item.get("Title", "")[:240]))
    return findings, seconds, completed


def tflint(head, workspace):
    completed, seconds = run([str(TFLINT), "--chdir", str(head), "--config", str(TFLINT_CONFIG),
                              "--format", "json", "--force"])
    findings = []
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report = {}
    for issue in report.get("issues") or []:
        span = issue.get("range", {})
        findings.append(dict(id=issue["rule"]["name"], level=issue["rule"].get("severity"),
                             file=span.get("filename"), line=span.get("start", {}).get("line"),
                             resource=None, message=issue.get("message", "")[:240]))
    for error in report.get("errors") or []:
        span = error.get("range") or {}
        findings.append(dict(id="tflint-error", file=span.get("filename"),
                             line=(span.get("start") or {}).get("line"), resource=None,
                             message=error.get("message", "")[:240]))
    return findings, seconds, completed


def validate(head, workspace):
    copy = workspace / "validate"
    shutil.copytree(head, copy)
    init, init_seconds = run(["terraform", "init", "-backend=false", "-input=false", "-no-color"],
                             cwd=copy)
    completed, seconds = run(["terraform", "validate", "-json", "-no-color"], cwd=copy)
    findings = []
    if init.returncode != 0:
        findings.append(dict(id="init-failed", file=None, line=None, resource=None,
                             message=init.stderr.strip().splitlines()[-1][:240] if init.stderr else ""))
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report = {}
    for diagnostic in report.get("diagnostics") or []:
        span = diagnostic.get("range") or {}
        findings.append(dict(id=diagnostic.get("summary", "")[:80], level=diagnostic.get("severity"),
                             file=span.get("filename"), line=(span.get("start") or {}).get("line"),
                             resource=diagnostic.get("address"),
                             message=diagnostic.get("detail", "")[:240]))
    return findings, init_seconds + seconds, completed


TOOLS = {"ours": None, "checkov": checkov, "trivy": trivy, "tflint": tflint, "validate": validate}


def main():
    selected = [argument for argument in sys.argv[1:] if not argument.startswith("--")] or list(TOOLS)
    labels = json.loads((CORPUS / "labels.json").read_text())
    output = BENCH / "results.json"
    results = json.loads(output.read_text()) if output.exists() else {}
    for label in labels:
        case_dir = CORPUS / label["name"]
        head = case_dir / "head"
        for tool in selected:
            if tool in results.get(label["name"], {}) and "--redo" not in sys.argv:
                continue
            with tempfile.TemporaryDirectory(prefix="bench-") as temporary:
                workspace = Path(temporary)
                if tool == "ours":
                    findings, seconds, completed = ours(case_dir, workspace)
                else:
                    findings, seconds, completed = TOOLS[tool](head, workspace)
            for finding in findings:
                finding["on_target"] = on_target(label, head, finding)
            results.setdefault(label["name"], {})[tool] = dict(
                findings=findings, seconds=round(seconds, 2), exit=completed.returncode,
                stderr=completed.stderr[-600:])
            print(f"{label['name']:40} {tool:9} {len(findings):3} findings "
                  f"{sum(f['on_target'] for f in findings):2} on target  {seconds:5.1f}s", flush=True)
        output.write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
