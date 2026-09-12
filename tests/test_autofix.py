from unittest.mock import Mock

import pytest

from tfpdf.cli import autofix
from tfpdf.cli.arguments import build_parser
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Finding, Severity


@pytest.mark.parametrize(
    "before,after",
    [
        ("a\nb\n", "x\na\nb\n"),
        ("a\nb\n", "a\nx\nb\n"),
        ("a\nb\n", "a\nb\nx\n"),
        ("a\nb\n", "a\n"),
        ("a\nb\nc\n", "x\nb\ny\n"),
    ],
)
def test_github_replacement_reconstructs_corrected_file(before, after):
    fix = autofix.replacement(before, after)
    lines = before.splitlines()
    lines[fix.start_line - 1 : fix.end_line] = fix.lines
    assert lines == after.splitlines()


@pytest.mark.parametrize("answer,accepted", [("y", True), ("n", False), ("", False)])
def test_local_writes_only_after_acceptance(tmp_path, monkeypatch, answer, accepted):
    path = tmp_path / "main.tf"
    path.write_bytes(b"before\n")
    monkeypatch.setattr(autofix.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: answer)
    autofix.accept_local(path, b"before\n", "after\n")
    assert path.read_bytes() == (b"after\n" if accepted else b"before\n")


def test_stale_file_is_not_overwritten(tmp_path, monkeypatch):
    path = tmp_path / "main.tf"
    path.write_bytes(b"user edit")
    monkeypatch.setattr(autofix.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "y")
    with pytest.raises(ValueError, match="differs"):
        autofix.accept_local(path, b"scanned", "after")
    assert path.read_bytes() == b"user edit"


def test_noninteractive_never_prompts_or_writes(tmp_path, monkeypatch):
    path = tmp_path / "main.tf"
    path.write_bytes(b"before")
    monkeypatch.setattr(autofix.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("prompt")))
    autofix.accept_local(path, b"before", "after")
    assert path.read_bytes() == b"before"


@pytest.fixture
def proposal(tmp_path, monkeypatch):
    source = b'resource "aws_s3_bucket" "main" {\n  force_destroy = true\n}\n'
    corrected = source.decode().replace("true", "false")
    (tmp_path / "main.tf").write_bytes(source)
    args = build_parser().parse_args(
        ["--autofix", "--uncommitted", "--repo-dir", str(tmp_path), "--license-key", "test-key"]
    )
    finding = Finding(
        file="main.tf",
        line=2,
        category="test",
        severity=Severity.HIGH,
        resource="aws_s3_bucket.main",
        message="unsafe",
    )
    monkeypatch.setattr(
        autofix.terraformscan,
        "changed_terraform",
        lambda *_: [ChangedFile(path="main.tf", head_content=source)],
    )
    request = Mock(return_value={"fixed_code": corrected})
    monkeypatch.setattr(autofix, "send_json", request)
    return args, finding, request, source, corrected


def test_pr_proposes_without_writing_and_uses_authenticated_endpoint(proposal):
    args, finding, request, source, corrected = proposal
    autofix.propose(args, [finding], True)
    assert finding.fix.lines == ["  force_destroy = false"]
    assert finding.suggestion == corrected
    assert (autofix.Path(args.repo_dir) / "main.tf").read_bytes() == source
    assert request.call_args.args[1].endswith("/v1/autofix")
    assert request.call_args.args[2] == {"Authorization": "Bearer test-key"}
    assert request.call_args.args[3]["code_to_fix"] == source.decode()


@pytest.mark.parametrize("code", [None, "", "```hcl\nx\n```", 'resource "broken" {'])
def test_bad_model_output_leaves_findings_and_files_unchanged(proposal, code):
    args, finding, request, source, _ = proposal
    request.return_value = {"fixed_code": code}
    autofix.propose(args, [finding], True)
    assert finding.fix is None
    assert (autofix.Path(args.repo_dir) / "main.tf").read_bytes() == source


def test_waived_findings_do_not_call_service(proposal):
    args, finding, request, _, _ = proposal
    finding.waived = True
    autofix.propose(args, [finding], True)
    request.assert_not_called()


def test_missing_license_does_not_call_service(proposal):
    args, finding, request, _, _ = proposal
    args.license_key = ""
    autofix.propose(args, [finding], True)
    request.assert_not_called()


def test_pipeline_publishes_proposals_without_changing_blocking_verdict(proposal, monkeypatch):
    from tfpdf.cli import pipeline
    from tfpdf.cli.config import Config

    args, finding, _, _, _ = proposal
    monkeypatch.setattr(pipeline, "_collect_findings", lambda *_: [finding])
    monkeypatch.setattr(pipeline, "apply_waivers", lambda findings, *_: findings)
    monkeypatch.setattr(pipeline, "report_usage", lambda *_: False)
    publish = Mock()
    monkeypatch.setattr(pipeline, "_publish_reports", publish)
    assert pipeline.execute_scan(args, Config(), True) == 1
    assert publish.call_args.args[2][0].fix is not None
    assert publish.call_args.args[3] is True


def test_server_refusal_preserves_existing_fix(proposal):
    from tfpdf._httpjson import HTTPError
    from tfpdf.report.finding import Fix

    args, finding, request, source, _ = proposal
    original_fix = Fix(2, 2, ["  force_destroy = false"])
    finding.fix = original_fix
    request.side_effect = HTTPError("403 Growth plan required")
    autofix.propose(args, [finding], True)
    assert finding.fix is original_fix
    assert (autofix.Path(args.repo_dir) / "main.tf").read_bytes() == source
