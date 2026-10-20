"""Files and values the scanner could not analyse are reported, never treated as clean."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tfpdf.cli import terraformscan
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Category, Severity
from tfpdf.rules import builtin_pack, default_rules, incomplete, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema

_ENTRY = [sys.executable, "-c", "from tfpdf.cli.main import run; run()"]

# An unclosed block that also hides a setting the scanner would otherwise report.
_BROKEN = b'resource "aws_s3_bucket" "logs" {\n  bucket        = "logs"\n  force_destroy = true\n'


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _git(directory: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=directory, capture_output=True, check=True)


def _repository(directory: Path, files: dict[str, bytes]) -> Path:
    _git(directory, "init", "-q", "-b", "main")
    _git(directory, "config", "user.email", "test@example.com")
    _git(directory, "config", "user.name", "test")
    for name, content in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _git(directory, "add", "-A")
    _git(directory, "commit", "-q", "-m", "files")
    return directory


def _scan(repository: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GITHUB_", "GITLAB_", "CI_", "TFPDF_", "SCANNER_"))
    }
    return subprocess.run(
        [*_ENTRY, "--repo-dir", str(repository), "--full-repo-scan", "--config", os.devnull],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )


def test_the_built_in_definitions_carry_the_severities_the_code_uses() -> None:
    """The findings are built in code; their pack definitions document them. Both must agree."""
    pack = builtin_pack()
    expected = {
        "unparsable_file": incomplete.UNPARSABLE_FILE_SEVERITY,
        "unparsable_base_file": incomplete.UNPARSABLE_BASE_FILE_SEVERITY,
        "unsupported_file_format": incomplete.UNSUPPORTED_FILE_FORMAT_SEVERITY,
    }
    for rule_id, severity in expected.items():
        rule = pack.by_id(rule_id)
        assert rule is not None
        assert rule.severity == severity
        assert rule.category == "incomplete_analysis"


def test_an_unparsable_file_is_a_high_finding_on_the_error_line(kb: KnowledgeBase) -> None:
    result = run([ChangedFile(path="main.tf", head_content=_BROKEN)], kb, default_rules())

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category is Category.INCOMPLETE_ANALYSIS
    assert finding.rule_name == "unparsable_file"
    assert finding.severity is Severity.HIGH
    assert finding.line == 1
    assert "could not parse file as HCL" in finding.message
    assert "nothing in it was checked" in finding.message


def test_an_unparsable_base_revision_is_reported_and_the_head_still_checked(
    kb: KnowledgeBase,
) -> None:
    head = (
        b'resource "aws_s3_bucket" "logs" {\n  bucket        = "logs"\n  force_destroy = true\n}\n'
    )
    result = run(
        [ChangedFile(path="main.tf", head_content=head, base_content=_BROKEN)],
        kb,
        default_rules(),
    )

    rule_names = sorted(finding.rule_name for finding in result.findings)
    assert "unparsable_base_file" in rule_names
    assert "s3_force_destroy" in rule_names, "the head revision is still checked"
    base_finding = next(f for f in result.findings if f.rule_name == "unparsable_base_file")
    assert base_finding.severity is Severity.LOW


def test_the_category_can_be_suppressed_on_the_reported_line(kb: KnowledgeBase) -> None:
    source = b"# tf-firewall-ignore: incomplete_analysis\n" + _BROKEN
    result = run([ChangedFile(path="main.tf", head_content=source)], kb, default_rules())
    assert result.findings == []


@pytest.mark.parametrize(
    ("name", "content", "file_format"),
    [
        ("terraform.tfvars", b"this is = not ( valid", "HCL"),
        ("prod.tfvars.json", b"{not json", "JSON"),
    ],
)
def test_an_unparsable_variable_file_is_a_finding(
    tmp_path: Path, name: str, content: bytes, file_format: str
) -> None:
    repository = _repository(tmp_path, {name: content})
    warnings: list[str] = []

    findings = terraformscan.scan_tfvars(
        str(repository), terraformscan.Mode(full_repo=True), warnings.append
    )

    assert [finding.rule_name for finding in findings] == ["unparsable_file"]
    assert f"could not parse file as {file_format}" in findings[0].message
    assert warnings == []


def test_an_unparsable_terragrunt_file_is_a_finding(tmp_path: Path) -> None:
    repository = _repository(tmp_path, {"live/terragrunt.hcl": b"inputs = {\n"})

    findings = terraformscan.scan_terragrunt(
        str(repository), terraformscan.Mode(full_repo=True), lambda _message: None
    )

    assert [finding.rule_name for finding in findings] == ["unparsable_file"]
    assert findings[0].file == "live/terragrunt.hcl"


def test_a_terraform_json_file_is_reported_in_every_scan_mode(tmp_path: Path) -> None:
    repository = _repository(tmp_path, {"main.tf": b""})
    (repository / "generated.tf.json").write_text('{"resource": {}}')

    uncommitted = terraformscan.report_terraform_json(
        str(repository), terraformscan.Mode(uncommitted=True)
    )
    _git(repository, "add", "-A")
    staged = terraformscan.report_terraform_json(str(repository), terraformscan.Mode(staged=True))
    _git(repository, "commit", "-q", "-m", "json")
    changed = terraformscan.report_terraform_json(
        str(repository), terraformscan.Mode(base_ref="HEAD~1", head_ref="HEAD")
    )
    full = terraformscan.report_terraform_json(str(repository), terraformscan.Mode(full_repo=True))

    for findings in (uncommitted, staged, changed, full):
        assert [(f.file, f.rule_name, f.severity) for f in findings] == [
            ("generated.tf.json", "unsupported_file_format", Severity.MEDIUM)
        ]


def test_an_unparsable_file_blocks_the_scan(tmp_path: Path) -> None:
    """The regression this category exists for: a syntax error used to pass the scan."""
    repository = _repository(tmp_path, {"main.tf": _BROKEN})

    process = _scan(repository)

    assert process.returncode == 1, process.stdout + process.stderr
    assert "File not analysed" in process.stdout
    assert "Merge blocked" in process.stdout


def test_a_terraform_json_file_is_reported_without_blocking(tmp_path: Path) -> None:
    repository = _repository(tmp_path, {"main.tf.json": b'{"resource": {}}'})

    process = _scan(repository)

    assert process.returncode == 0, process.stdout + process.stderr
    assert "Terraform JSON syntax (.tf.json) is not analysed" in process.stdout
