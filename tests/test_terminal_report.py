"""Terminal rendering tests, including preservation of Markdown output for redirected streams and
PR reports.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.report.terminal import render_terminal, wants_color


def _finding(
    file: str = "main.tf",
    line: int = 1,
    message: str = "quelque chose",
    severity: Severity = Severity.MEDIUM,
    rule_name: str = "une_regle",
    resource: str = "aws_s3_bucket.b",
    category: Category = Category.MISSING_LIFECYCLE,
) -> Finding:
    return Finding(
        file=file,
        line=line,
        category=category,
        severity=severity,
        resource=resource,
        message=message,
        rule_name=rule_name,
    )


def _plain(findings: list[Finding], **kwargs: object) -> str:
    return render_terminal(
        findings,
        Severity.HIGH,
        False,
        color=False,
        width=100,
        **kwargs,  # type: ignore[arg-type]
    )


# Terminal readability.


def test_the_explanation_appears_once_per_rule_not_once_per_finding() -> None:
    """Print repeated rule explanations once per group."""
    long_message = "aws_cloudwatch_log_group is a stateful resource with no guard"
    findings = [_finding(file=f"f{i}.tf", line=i, message=long_message) for i in range(9)]

    out = _plain(findings)

    assert out.count("is a stateful resource with no guard") == 1
    for i in range(9):
        assert f"f{i}.tf:{i}" in out


def test_two_rules_of_the_same_category_do_not_share_a_heading() -> None:
    """Include rule identity so detectors sharing a category have distinct headings."""
    out = _plain(
        [
            _finding(rule_name="missing_lifecycle", message="pas de garde"),
            _finding(rule_name="s3_force_destroy", line=2, message="force_destroy est vrai"),
        ]
    )
    assert "s3_force_destroy" in out


def test_only_what_differs_between_findings_is_repeated() -> None:
    """Show only per-finding details that the shared explanation does not cover."""
    out = _plain(
        [
            _finding(message='"name" is ForceNew on aws_iam_role and may recreate it', line=1),
            _finding(message='"hash_key" is ForceNew on aws_iam_role and may recreate it', line=2),
        ]
    )
    lines = [line for line in out.splitlines() if "main.tf:" in line]
    assert lines[0].endswith('"name"')
    assert lines[1].endswith('"hash_key"')


def test_a_quoted_subject_is_only_used_when_every_line_has_one() -> None:
    """Use quoted-subject shortening consistently across every row in a group."""
    out = _plain(
        [
            _finding(message='"name" is ForceNew on aws_iam_role', line=1),
            _finding(message="something entirely different here", line=2),
        ]
    )
    assert '"name"' in out
    assert "something entirely different" in out


def test_a_difference_already_visible_in_the_resource_is_not_repeated() -> None:
    """Omit details already visible in the resource address."""
    out = _plain(
        [
            _finding(resource="aws_dynamodb_table.main", message="aws_dynamodb_table has no guard"),
            _finding(resource="aws_s3_bucket.b", line=2, message="aws_s3_bucket has no guard"),
        ]
    )
    for line in (line for line in out.splitlines() if ".tf:" in line):
        assert not line.rstrip().endswith("_table")
        assert not line.rstrip().endswith("_bucket")


def test_a_lone_finding_says_its_message_once_and_no_more() -> None:
    out = _plain([_finding(message="un seul cas")])
    assert out.count("un seul cas") == 1


def test_nothing_found_says_so_in_one_line() -> None:
    assert _plain([]).strip() == "No findings."


def test_a_blocked_scan_says_it_at_the_top() -> None:
    out = render_terminal([_finding(severity=Severity.CRITICAL)], Severity.HIGH, True, color=False)
    assert "blocked" in out.splitlines()[0]


def test_waived_findings_are_shown_apart_and_not_counted() -> None:
    """Keep waived findings visible but outside the blocking count."""
    waived = _finding(line=2)
    waived.waived = True
    out = _plain([_finding(), waived])
    assert out.splitlines()[0].startswith("1 finding(s)")
    assert "waived" in out


def test_severities_come_worst_first() -> None:
    out = _plain(
        [
            _finding(severity=Severity.LOW, rule_name="a", message="basse"),
            _finding(severity=Severity.CRITICAL, rule_name="b", message="haute", line=2),
        ]
    )
    assert out.index("haute") < out.index("basse")


# --- couleur ----------------------------------------------------------------


def test_no_color_is_obeyed_whatever_its_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """NO_COLOR is enabled by presence, regardless of value."""
    for value in ("", "0", "false", "1"):
        monkeypatch.setenv("NO_COLOR", value)
        assert wants_color(None) is False


def test_a_redirected_output_carries_no_escape_sequences() -> None:
    """Redirected output must not contain ANSI escape sequences."""
    assert "\033" not in _plain([_finding()])


# Preserve existing output contracts.


def test_a_pipe_still_receives_the_markdown_byte_for_byte(tmp_path: Path) -> None:
    """Pipes retain the existing Markdown format; automatic terminal rendering is TTY-only."""
    (tmp_path / "main.tf").write_bytes(
        b'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  force_destroy = true\n}\n'
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tfpdf.cli.main",
            "--repo-dir",
            str(tmp_path),
            "--full-repo-scan",
            "--post-comment=false",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).parent.parent / "src")},
    )
    # Captured subprocess output is not a TTY and must retain Markdown.
    assert "<!-- tf-predeploy-firewall:report -->" in result.stdout
    assert "| Severity | File | Line |" in result.stdout
