"""Port de internal/report/report_test.go, cas pour cas."""

from __future__ import annotations

import pytest

from tfpdf.report import MARKER, Category, Finding, Severity, render_markdown


def test_render_markdown_no_findings() -> None:
    out = render_markdown([], Severity.HIGH, False)
    assert MARKER in out, "expected the HTML marker to be present"
    assert "No risk patterns" in out


def test_render_markdown_blocked_message() -> None:
    findings = [
        Finding(
            file="main.tf",
            line=3,
            category=Category.TUTORIAL_PATTERN,
            severity=Severity.CRITICAL,
            resource="aws_db_instance.x",
            message="password in plaintext",
        )
    ]
    out = render_markdown(findings, Severity.HIGH, True)
    assert "Merge blocked" in out
    assert "main.tf" in out


def test_render_markdown_not_blocked() -> None:
    findings = [
        Finding(
            file="main.tf",
            line=5,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            resource="aws_db_instance.y",
            message="no prevent_destroy",
        )
    ]
    out = render_markdown(findings, Severity.HIGH, False)
    assert "Merge blocked" not in out
    assert "⚠️" in out, "expected the warning emoji for non-blocking findings"


def test_render_markdown_suggestion_rendered_as_collapsible_code_block() -> None:
    findings = [
        Finding(
            file="main.tf",
            line=5,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            resource="aws_db_instance.y",
            message="no prevent_destroy",
        ),
        Finding(
            file="main.tf",
            line=9,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            resource="aws_db_instance.z",
            message="no prevent_destroy",
            suggestion="lifecycle {\n  prevent_destroy = true\n}",
        ),
    ]
    out = render_markdown(findings, Severity.HIGH, False)

    assert "### Suggested fixes" in out
    assert "```hcl" in out
    assert "prevent_destroy = true" in out
    assert "<details>" in out
    assert out.count("<details>") == 1, "only aws_db_instance.z has a suggestion"


def test_render_markdown_no_suggestion_section_when_none_have_suggestions() -> None:
    findings = [
        Finding(
            file="main.tf",
            line=5,
            category=Category.UNKNOWN_ATTRIBUTE,
            severity=Severity.MEDIUM,
            resource="aws_instance.x",
            message="unknown attr",
        )
    ]
    assert "Suggested fixes" not in render_markdown(findings, Severity.HIGH, False)


def test_render_markdown_waived_finding_excluded_from_table_and_blocking() -> None:
    findings = [
        Finding(
            file="main.tf",
            line=3,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.CRITICAL,
            resource="aws_db_instance.legacy",
            message="no prevent_destroy",
            waived=True,
            waiver_note="legacy repo, ticketed for cleanup in INFRA-42",
        )
    ]
    # blocked=False here simulates the caller (the CLI) having already excluded
    # the waived finding before computing the block decision — render_markdown
    # itself does not recompute `blocked`, it just must not contradict it by
    # putting a waived finding in the blocking table.
    out = render_markdown(findings, Severity.HIGH, False)
    assert "Merge blocked" not in out
    assert "No blocking findings" in out
    assert "INFRA-42" in out
    assert out.count("aws_db_instance.legacy") == 1, (
        "the waived finding belongs in the waived section only"
    )


def test_render_markdown_mixed_active_and_waived_findings() -> None:
    findings = [
        Finding(
            file="main.tf",
            line=3,
            category=Category.TUTORIAL_PATTERN,
            severity=Severity.CRITICAL,
            resource="aws_db_instance.x",
            message="password in plaintext",
        ),
        Finding(
            file="main.tf",
            line=8,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            resource="aws_db_instance.y",
            message="no prevent_destroy",
            waived=True,
            waiver_note="accepted, sandbox repo",
        ),
    ]
    out = render_markdown(findings, Severity.HIGH, True)
    assert "Merge blocked" in out, "the active critical finding alone breaches it"
    # The section covers findings accepted for any reason — a dashboard waiver
    # or a committed baseline — so its wording is deliberately not "waived".
    assert "1 accepted finding" in out
    assert "accepted, sandbox repo" in out


@pytest.mark.parametrize(
    ("s", "other", "want"),
    [
        (Severity.CRITICAL, Severity.HIGH, True),
        (Severity.HIGH, Severity.HIGH, True),
        (Severity.MEDIUM, Severity.HIGH, False),
        (Severity.LOW, Severity.CRITICAL, False),
    ],
)
def test_severity_at_least(s: Severity, other: Severity, want: bool) -> None:
    assert s.at_least(other) is want
