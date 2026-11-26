"""Time each tool on whole public repositories, and keep what our scanner reported.

Every tool scans the repository in its whole-repository mode. The timing is the
median of three runs, wall clock, on this machine. terraform validate is left out:
it needs `terraform init` per root module and does not scan a repository as a whole.
"""

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH))
from run_tools import CHECKOV, ENV, SCANNER, TFLINT, TFLINT_CONFIG  # noqa: E402

REPOS = sorted(path for path in (BENCH / "repos").iterdir() if path.is_dir())


def commands(repository):
    return {
        "ours": [str(SCANNER), "--repo-dir", str(repository), "--full-repo-scan", "--license-key", "",
                 "--format", "text", "--sarif-output", str(BENCH / f"sarif/{repository.name}.sarif")],
        "checkov": [str(CHECKOV), "-d", str(repository), "--framework", "terraform", "secrets",
                    "-o", "json", "--quiet", "--skip-download", "--compact"],
        "trivy": ["trivy", "fs", "--scanners", "misconfig,secret", "--format", "json", "--quiet",
                  "--skip-check-update", str(repository)],
        # TFLint lints one module directory per run; --recursive walks them all.
        "tflint": [str(TFLINT), "--chdir", str(repository), "--config", str(TFLINT_CONFIG),
                   "--recursive", "--format", "json", "--force"],
    }


def count(tool, stdout, repository):
    try:
        if tool == "ours":
            sarif = json.loads((BENCH / f"sarif/{repository.name}.sarif").read_text())
            return len(sarif["runs"][0]["results"])
        data = json.loads(stdout)
        if tool == "checkov":
            reports = data if isinstance(data, list) else [data]
            return sum(len(report.get("results", {}).get("failed_checks", [])) for report in reports)
        if tool == "trivy":
            return sum(len(result.get("Misconfigurations") or []) + len(result.get("Secrets") or [])
                       for result in data.get("Results") or [])
        if tool == "tflint":
            return len(data.get("issues") or [])
    except (json.JSONDecodeError, FileNotFoundError, KeyError):
        return None
    return None


def main():
    (BENCH / "sarif").mkdir(exist_ok=True)
    # Tools named on the command line are re-timed; the others keep their last results.
    selected = sys.argv[1:]
    output = BENCH / "repos.json"
    results = json.loads(output.read_text()) if selected and output.exists() else {}
    for repository in REPOS:
        for tool, command in commands(repository).items():
            if selected and tool not in selected:
                continue
            durations = []
            for _ in range(3):
                started = time.perf_counter()
                completed = subprocess.run(command, capture_output=True, text=True, env=ENV,
                                           timeout=1800)
                durations.append(time.perf_counter() - started)
            findings = count(tool, completed.stdout, repository)
            results.setdefault(repository.name, {})[tool] = dict(
                seconds=round(statistics.median(durations), 2), findings=findings,
                exit=completed.returncode, stderr=completed.stderr[-400:])
            print(f"{repository.name:58} {tool:8} {statistics.median(durations):7.2f}s "
                  f"{findings} findings (exit {completed.returncode})", flush=True)
        (BENCH / "repos.json").write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
