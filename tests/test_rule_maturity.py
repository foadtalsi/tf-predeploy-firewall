"""Only stable rules block by default; the others report and wait for evidence."""

from __future__ import annotations

import pytest

from tfpdf import ruledef
from tfpdf.cli.pipeline import blocked_by, mark_findings_of_unenforced_rules
from tfpdf.report import render_markdown, render_terminal
from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.rules import builtin_pack


def _pack(maturity: str) -> ruledef.Pack:
    return ruledef.load(
        f"""
version: 1
rules:
  - id: candidate_rule
    category: public_exposure
    severity: high
    maturity: {maturity}
    match:
      scope: attribute
      attr_names: [publicly_accessible]
      literal: true
      value_matches: "^true$"
    message: "{{resource}} is public"
"""
    )


def _finding(rule_name: str = "candidate_rule") -> Finding:
    return Finding(
        file="main.tf",
        line=3,
        category=Category.PUBLIC_EXPOSURE,
        rule_name=rule_name,
        severity=Severity.HIGH,
        resource="aws_db_instance.db",
        message="aws_db_instance.db is public",
    )


def test_every_built_in_rule_declares_a_known_maturity() -> None:
    for rule in builtin_pack().rules:
        assert rule.maturity in ruledef.VALID_MATURITIES, rule.id


def test_an_unknown_maturity_is_refused() -> None:
    with pytest.raises(ruledef.RulePackError, match="maturity must be one of"):
        _pack("beta")


def test_a_pack_without_maturity_keeps_blocking() -> None:
    """External packs written before the field existed must behave exactly as before."""
    pack = ruledef.load(
        """
version: 1
rules:
  - id: legacy_rule
    category: public_exposure
    severity: high
    match:
      scope: attribute
      attr_names: [acl]
      literal: true
    message: "{resource}"
"""
    )
    rule = pack.by_id("legacy_rule")
    assert rule is not None
    assert rule.maturity == "stable"


def test_maturity_survives_the_yaml_export() -> None:
    exported = ruledef.load(ruledef.builtin_yaml())
    rule = exported.by_id("unresolved_guard_value")
    assert rule is not None
    assert rule.maturity == "experimental"


@pytest.mark.parametrize(
    ("maturity", "enforce_rules", "blocks"),
    [
        ("stable", [], True),
        ("validated", [], False),
        ("validated", ["candidate_rule"], True),
        ("experimental", [], False),
        ("experimental", ["candidate_rule"], False),
    ],
)
def test_only_enforced_rules_block(maturity: str, enforce_rules: list[str], blocks: bool) -> None:
    findings = [_finding()]
    mark_findings_of_unenforced_rules(findings, _pack(maturity), enforce_rules)

    assert blocked_by(findings, Severity.HIGH) is blocks
    assert findings[0].advisory is not blocks


def test_findings_from_outside_the_pack_keep_blocking() -> None:
    """Custom rules and variable-file checks have no pack entry, and block as they always did."""
    findings = [_finding("custom:no-public"), _finding("tfvars_credential_value")]
    mark_findings_of_unenforced_rules(findings, _pack("experimental"), [])

    assert not any(finding.advisory for finding in findings)
    assert blocked_by(findings, Severity.HIGH)


def test_reports_say_an_unenforced_finding_does_not_block() -> None:
    finding = _finding()
    finding.advisory = True

    markdown = render_markdown([finding], Severity.HIGH, blocked=False)
    terminal = render_terminal([finding], Severity.HIGH, blocked=False, color=False)

    assert "none from an enforced rule reaches the `high` blocking threshold" in markdown
    assert "rule not enforced yet: reported, never blocks" in markdown
    assert "nothing enforced reaches high" in terminal
    assert "not enforced yet, never blocks" in terminal


def test_the_blocked_headline_names_the_highest_enforced_severity() -> None:
    advisory = _finding()
    advisory.severity = Severity.CRITICAL
    advisory.advisory = True
    enforced = _finding("public_data_store")

    markdown = render_markdown([advisory, enforced], Severity.HIGH, blocked=True)

    assert "findings at or above `high` severity" in markdown
