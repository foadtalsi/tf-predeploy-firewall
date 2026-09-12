"""Compare reports against frozen Go-generated oracles, including escaping, Unicode, waivers,
documentation links, and fix markers.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from tfpdf.report import (
    Category,
    Finding,
    Fix,
    Severity,
    gitlab_suggestion_body,
    render_code_quality,
    render_markdown,
    render_rule_docs,
    render_sarif,
    review_comment_body,
    sarif,
)

ORACLES = Path(__file__).parent / "data" / "oracles"
DATA = Path(__file__).parent / "data"


def _oracle_findings() -> list[Finding]:
    """Recreate the finding inputs used to generate the historical Go oracles."""
    return [
        Finding(
            file="rds.tf",
            line=12,
            category=Category.TUTORIAL_PATTERN,
            severity=Severity.CRITICAL,
            resource="aws_db_instance.prod",
            message='password = "hunter2" — hardcoded credential (a & b < c > d)',
            doc_url=(
                "https://registry.terraform.io/providers/hashicorp/aws/5.31.0"
                "/docs/resources/db_instance"
            ),
            fix=Fix(
                start_line=12,
                end_line=12,
                lines=["  password = var.db_password"],
                note='You also need to declare `variable "db_password"`.',
            ),
        ),
        Finding(
            file="s3.tf",
            line=3,
            category=Category.PUBLIC_EXPOSURE,
            severity=Severity.HIGH,
            resource="aws_s3_bucket_public_access_block.logs",
            message="block_public_acls = false — bucket ACLs may grant public read",
            suggestion="block_public_acls = true\nblock_public_policy = true",
        ),
        Finding(
            file="iam.tf",
            line=40,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            resource="aws_db_instance.legacy",
            message="no prevent_destroy guard",
            waived=True,
            waiver_note="legacy repo, ticketed as INFRA-42",
        ),
        Finding(
            file="main.tf",
            line=1,
            category="custom:no-iam-users",
            severity=Severity.LOW,
            resource="aws_iam_user.bob",
            message="Use aws_iam_role instead",
            fix=Fix(
                start_line=1,
                end_line=4,
                lines=['resource "aws_iam_role" "bob" {', '  name = "bob"', "}"],
            ),
        ),
    ]


@pytest.fixture
def stamped_version() -> Iterator[None]:
    """Match the driver version embedded in the oracle."""
    before = sarif.TOOL_VERSION
    sarif.set_tool_version("1.4.2")
    yield
    sarif.set_tool_version(before)


@pytest.mark.usefixtures("stamped_version")
def test_sarif_matches_the_go_implementation() -> None:
    """Compare the complete SARIF document, including help text and JSON formatting."""
    want = (ORACLES / "oracle_sarif.json").read_bytes()
    expected = json.loads(want)
    driver = expected["runs"][0]["tool"]["driver"]
    driver["rules"] = [rule for rule in driver["rules"] if rule["id"] != "cost_impact"]
    assert json.loads(render_sarif(_oracle_findings())) == expected


def test_code_quality_matches_the_go_implementation() -> None:
    want = (ORACLES / "oracle_codequality.json").read_bytes()
    assert render_code_quality(_oracle_findings()) == want


def test_code_quality_escapes_html_the_way_go_does() -> None:
    """Compare bytes because JSON round trips would hide different HTML escaping."""
    out = render_code_quality(_oracle_findings()).decode()
    assert "\\u0026" in out and "\\u003c" in out and "\\u003e" in out
    assert "—" in out, "non-ASCII stays raw UTF-8, as Go emits it"


def test_markdown_matches_the_go_implementation() -> None:
    want = (ORACLES / "oracle_markdown.md").read_text(encoding="utf-8")
    assert render_markdown(_oracle_findings(), Severity.HIGH, True) == want


def test_review_bodies_match_the_go_implementation() -> None:
    """Pin both suggestion syntaxes and their hashed markers to prevent duplicate posts after
    upgrades.
    """
    parts: list[str] = []
    for f in _oracle_findings():
        if f.fix is None:
            continue  # the guard the CLI applies; see the note in test_go_defect
        parts.append(f"=== {f.resource}\n")
        parts.append(review_comment_body(f))
        parts.append("--- gitlab\n")
        parts.append(gitlab_suggestion_body(f))

    want = (ORACLES / "oracle_review.txt").read_text(encoding="utf-8")
    assert "".join(parts) == want


def test_rule_docs_match_the_committed_go_generated_file(
    pytestconfig: pytest.Config,
) -> None:
    """Compare generated rule documentation with historical fixtures, excluding deliberate changes
    such as removed categories and the generator header. --update-docs writes only
    docs/rules.md.
    """
    got = render_rule_docs()

    if pytestconfig.getoption("--update-docs"):
        out = Path(__file__).parent.parent / "docs" / "rules.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(got, encoding="utf-8")
        pytest.skip(f"wrote {out}")

    want = (DATA / "rules.md").read_text(encoding="utf-8")

    got_preamble, got_body = got.split("-->", 1)
    want_preamble, want_body = want.split("-->", 1)

    # Assert both generator headers so intentional provenance differences stay explicit.
    assert "tfpdf/ruledef/rules.py" in got_preamble
    assert "pytest --update-docs" in got_preamble
    assert "internal/ruledef/rules.yaml" in want_preamble

    want_body = re.sub(r"## cost_impact.*?\n---\n\n", "", want_body, flags=re.S)
    assert got_body == want_body
