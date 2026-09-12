"""Plan replacement, drift, and blast-radius checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf import planjson, schema
from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.rules import (
    BlastRadiusRule,
    ChangedAttrKey,
    ConfirmedReplaceRule,
    DriftRule,
    deduplicate_force_new_against_plan,
)

PLANS = Path(__file__).parent / "data" / "plans"


@pytest.fixture(scope="module")
def kb() -> schema.KnowledgeBase:
    return schema.load()


# sample_plan.json:
#   aws_db_instance.prod    -> replace (delete+create), critical resource type
#   aws_s3_bucket.logs      -> destroy-only, critical resource type
#   aws_security_group.web  -> pure update (description text differs)
#   aws_iam_role.app        -> no-op
@pytest.fixture(scope="module")
def sample_plan() -> planjson.PlanFile:
    return planjson.load(str(PLANS / "sample_plan.json"))


@pytest.fixture(scope="module")
def edge_case_plan() -> planjson.PlanFile:
    return planjson.load(str(PLANS / "sensitive_and_modules_plan.json"))


# cost_impact_plan.json:
#   aws_instance.web       create m5.2xlarge           -> +$280/mo
#   aws_instance.upsized   update t3.micro -> m5.large -> +$62.5/mo
#   aws_nat_gateway.old    destroy-only (flat $32)     -> -$32/mo
#   aws_iam_role.app       no-op                       -> $0
#   data.aws_ami.al2023    data source read            -> skipped
# Total delta: 280 + 62.5 - 32 = 310.5


def test_confirmed_replace_rule(kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile) -> None:
    findings = ConfirmedReplaceRule().check("plan.json", sample_plan.resource_changes, kb)
    by_resource = {f.resource: f for f in findings}

    assert "aws_db_instance.prod" in by_resource, "expected a finding for the replace"
    assert by_resource["aws_db_instance.prod"].severity is Severity.CRITICAL

    assert "aws_s3_bucket.logs" in by_resource, "expected a finding for the destroy"
    assert by_resource["aws_s3_bucket.logs"].severity is Severity.CRITICAL

    assert "aws_iam_role.app" not in by_resource, "no finding for a no-op"
    assert "aws_security_group.web" not in by_resource, "no finding for a pure update"


def test_blast_radius_rule_below_threshold(
    kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile
) -> None:
    # sample_plan.json has 2 destroy/replace actions; threshold 10 => no finding.
    assert BlastRadiusRule(threshold=10).check("plan.json", sample_plan.resource_changes, kb) == []


def test_blast_radius_rule_above_threshold(
    kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile
) -> None:
    findings = BlastRadiusRule(threshold=2).check("plan.json", sample_plan.resource_changes, kb)
    assert len(findings) == 1, findings
    assert findings[0].category is Category.LARGE_BLAST_RADIUS


def test_blast_radius_rule_disabled(
    kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile
) -> None:
    assert BlastRadiusRule(threshold=0).check("plan.json", sample_plan.resource_changes, kb) == []


def test_drift_rule_flags_untouched_sensitive_attr(
    kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile
) -> None:
    """A plan update to a sensitive attribute absent from changed_attrs represents unexplained
    drift.
    """
    findings = DriftRule().check("plan.json", sample_plan.resource_changes, {}, kb)
    assert any(
        f.resource == "aws_security_group.web" and f.category is Category.UNEXPECTED_DRIFT
        for f in findings
    ), findings


def test_drift_rule_suppressed_when_pr_explains_change(
    kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile
) -> None:
    """An attribute explicitly changed by the pull request is intentional rather than drift."""
    changed: dict[str, set[ChangedAttrKey]] = {"aws_security_group.web": {"name"}}
    findings = DriftRule().check("plan.json", sample_plan.resource_changes, changed, kb)
    assert not [f for f in findings if f.resource == "aws_security_group.web"]


def test_drift_rule_matches_module_address_against_bare_changed_attrs(
    kb: schema.KnowledgeBase, edge_case_plan: planjson.PlanFile
) -> None:
    """Match module-qualified plan addresses against normalized type.name changed-attribute keys."""
    changed: dict[str, set[ChangedAttrKey]] = {"aws_db_instance.primary": {"availability_zone"}}
    findings = DriftRule().check("plan.json", edge_case_plan.resource_changes, changed, kb)
    assert not [f for f in findings if f.resource == "module.db.aws_db_instance.primary"]


def test_drift_rule_flags_module_address_when_not_explained(
    kb: schema.KnowledgeBase, edge_case_plan: planjson.PlanFile
) -> None:
    findings = DriftRule().check("plan.json", edge_case_plan.resource_changes, {}, kb)
    assert any(f.resource == "module.db.aws_db_instance.primary" for f in findings)


def test_drift_rule_redacts_sensitive_values(
    kb: schema.KnowledgeBase, edge_case_plan: planjson.PlanFile
) -> None:
    findings = DriftRule().check("plan.json", edge_case_plan.resource_changes, {}, kb)
    kms = [f for f in findings if f.resource == "aws_kms_key.secret"]
    assert kms, "expected a drift finding for aws_kms_key.secret"
    assert "s3cr3t-value-here" not in kms[0].message, "sensitive value leaked"
    assert "redacted" in kms[0].message


def test_drift_rule_skips_data_sources(
    kb: schema.KnowledgeBase, edge_case_plan: planjson.PlanFile
) -> None:
    findings = DriftRule().check("plan.json", edge_case_plan.resource_changes, {}, kb)
    assert not [f for f in findings if f.resource == "data.aws_db_instance.lookup"]


def test_confirmed_replace_rule_skips_data_sources(kb: schema.KnowledgeBase) -> None:
    """Exclude data-source reads regardless of their reported actions."""
    changes = [
        planjson.ResourceChange(
            address="data.aws_db_instance.lookup",
            mode="data",
            type="aws_db_instance",
            change=planjson.Change(actions=["delete"]),
        )
    ]
    assert ConfirmedReplaceRule().check("plan.json", changes, kb) == []


def test_deduplicate_force_new_against_plan() -> None:
    static_findings = [
        Finding(
            file="",
            line=0,
            resource="aws_db_instance.prod",
            category=Category.FORCE_NEW_CHANGE,
            severity=Severity.HIGH,
            message="heuristic guess",
        ),
        Finding(
            file="",
            line=0,
            resource="aws_instance.web",
            category=Category.FORCE_NEW_CHANGE,
            severity=Severity.HIGH,
            message="unrelated heuristic guess",
        ),
        Finding(
            file="",
            line=0,
            resource="aws_db_instance.prod",
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            message="unrelated category",
        ),
    ]
    plan_findings = [
        Finding(
            file="",
            line=0,
            resource="aws_db_instance.prod",
            category=Category.CONFIRMED_REPLACE,
            severity=Severity.CRITICAL,
            message="confirmed by plan",
        )
    ]

    out = deduplicate_force_new_against_plan(static_findings, plan_findings)
    assert len(out) == 2, out
    assert not [
        f
        for f in out
        if f.resource == "aws_db_instance.prod" and f.category is Category.FORCE_NEW_CHANGE
    ]


def test_deduplicate_force_new_against_plan_no_op_without_confirmed_replace() -> None:
    static_findings = [
        Finding(
            file="",
            line=0,
            resource="aws_db_instance.prod",
            category=Category.FORCE_NEW_CHANGE,
            severity=Severity.HIGH,
            message="heuristic guess",
        )
    ]
    assert len(deduplicate_force_new_against_plan(static_findings, [])) == 1


# --- pinned beyond the Go suite ---------------------------------------------


def test_drift_compares_numbers_the_way_go_decodes_them(
    kb: schema.KnowledgeBase,
) -> None:
    """Treat JSON 5 and 5.0 as equal, matching Go decoding rather than Python string rendering."""
    changes = [
        planjson.ResourceChange(
            address="aws_db_instance.x",
            mode="managed",
            type="aws_db_instance",
            change=planjson.Change(
                actions=["update"],
                before={"allocated_storage": 5},
                after={"allocated_storage": 5.0},
            ),
        )
    ]
    assert DriftRule().check("plan.json", changes, {}, kb) == []
