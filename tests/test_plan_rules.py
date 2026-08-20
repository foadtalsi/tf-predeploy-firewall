"""Port de internal/rules/rule_plan_test.go, rule_plan_edgecases_test.go et
rule_plan_cost_impact_test.go, cas pour cas.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf import planjson, schema
from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.rules import (
    BlastRadiusRule,
    ChangedAttrKey,
    ConfirmedReplaceRule,
    CostImpactRule,
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
@pytest.fixture(scope="module")
def cost_plan() -> planjson.PlanFile:
    return planjson.load(str(PLANS / "cost_impact_plan.json"))


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
    """aws_security_group.web est une pure mise à jour qui change « name » ; la
    liste ForceNew curée a « name » au premier niveau pour ce type. Aucun
    changed_attrs fourni veut dire que le diff .tf de la PR n'y a jamais touché
    => dérive."""
    findings = DriftRule().check("plan.json", sample_plan.resource_changes, {}, kb)
    assert any(
        f.resource == "aws_security_group.web" and f.category is Category.UNEXPECTED_DRIFT
        for f in findings
    ), findings


def test_drift_rule_suppressed_when_pr_explains_change(
    kb: schema.KnowledgeBase, sample_plan: planjson.PlanFile
) -> None:
    """Le même plan, mais cette fois le diff de la PR A touché « name » — un
    changement intentionnel, pas une dérive."""
    changed: dict[str, set[ChangedAttrKey]] = {"aws_security_group.web": {"name"}}
    findings = DriftRule().check("plan.json", sample_plan.resource_changes, changed, kb)
    assert not [f for f in findings if f.resource == "aws_security_group.web"]


def test_drift_rule_matches_module_address_against_bare_changed_attrs(
    kb: schema.KnowledgeBase, edge_case_plan: planjson.PlanFile
) -> None:
    """changed_attrs utilise la clé « type.nom » nue que produit l'analyseur
    HCL — sans préfixe de module — parce que le diff .tf de cette PR A touché
    availability_zone."""
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
    """Une source de données ne peut en pratique jamais apparaître avec des
    actions delete ou replace, mais la règle filtre par mode indépendamment des
    actions, en défense en profondeur."""
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


def test_cost_impact_rule_disabled(kb: schema.KnowledgeBase, cost_plan: planjson.PlanFile) -> None:
    assert CostImpactRule(threshold_usd=0).check("plan.json", cost_plan.resource_changes, kb) == []


def test_cost_impact_rule_below_threshold(
    kb: schema.KnowledgeBase, cost_plan: planjson.PlanFile
) -> None:
    # Total delta is 310.5; a threshold above that must not trigger.
    assert (
        CostImpactRule(threshold_usd=1000).check("plan.json", cost_plan.resource_changes, kb) == []
    )


def test_cost_impact_rule_above_threshold(
    kb: schema.KnowledgeBase, cost_plan: planjson.PlanFile
) -> None:
    findings = CostImpactRule(threshold_usd=100).check("plan.json", cost_plan.resource_changes, kb)
    assert len(findings) == 1, findings
    assert findings[0].category is Category.COST_IMPACT
    assert "aws_instance.web" in findings[0].message
    assert "aws_instance.upsized" in findings[0].message


def test_cost_impact_rule_severity_escalates_at_five_x_threshold(
    kb: schema.KnowledgeBase, cost_plan: planjson.PlanFile
) -> None:
    # Total delta 310.5 >= 5*50 (250) => high.
    high = CostImpactRule(threshold_usd=50).check("plan.json", cost_plan.resource_changes, kb)
    assert len(high) == 1 and high[0].severity is Severity.HIGH

    # Total delta 310.5 < 5*100 (500) => medium.
    medium = CostImpactRule(threshold_usd=100).check("plan.json", cost_plan.resource_changes, kb)
    assert len(medium) == 1 and medium[0].severity is Severity.MEDIUM


def test_cost_impact_rule_skips_data_sources_and_no_ops(
    kb: schema.KnowledgeBase, cost_plan: planjson.PlanFile
) -> None:
    findings = CostImpactRule(threshold_usd=1).check("plan.json", cost_plan.resource_changes, kb)
    assert len(findings) == 1, findings
    assert "aws_iam_role.app" not in findings[0].message
    assert "aws_ami" not in findings[0].message


def test_cost_impact_rule_unpriced_resource_type_contributes_zero(
    kb: schema.KnowledgeBase,
) -> None:
    changes = [
        planjson.ResourceChange(
            address="aws_cloudfront_distribution.cdn",
            mode="managed",
            type="aws_cloudfront_distribution",
            change=planjson.Change(actions=["create"], before=None, after={"enabled": True}),
        )
    ]
    assert CostImpactRule(threshold_usd=1).check("plan.json", changes, kb) == []


# --- pinned beyond the Go suite ---------------------------------------------


def test_a_created_flat_rate_resource_is_charged_its_full_cost(
    kb: schema.KnowledgeBase,
) -> None:
    """Une création a `"before": null`, ce qui n'est pas un objet vide.

    Go modélise les deux états par des maps nullables et facture 0 $ pour le
    côté qui n'existe pas. Décoder `null` en `{}` — le Python évident —
    chercherait l'attribut de tarification dans un dictionnaire vide, retomberait
    sur le coût de base fixe des *deux* côtés, et calculerait un écart nul : un
    plan qui crée une passerelle NAT ne rapporterait aucun impact de coût. Rien
    dans la suite Go ne couvre ceci, parce qu'en Go cela ne peut pas arriver.

    Analysé depuis du vrai JSON plutôt que construit à la main : le décodage est
    l'étape qui perdait la distinction, donc un test qui construirait l'objet
    directement passerait dans les deux cas.
    """
    pf = planjson.parse(
        """
        {"format_version": "1.2", "resource_changes": [
          {"address": "aws_nat_gateway.new", "mode": "managed",
           "type": "aws_nat_gateway", "name": "new",
           "change": {"actions": ["create"], "before": null, "after": {}}}
        ]}
        """
    )
    assert pf.resource_changes[0].change.before is None, "null must survive the decode"

    findings = CostImpactRule(threshold_usd=1).check("plan.json", pf.resource_changes, kb)
    assert len(findings) == 1, "creating a flat-rate resource must cost its base rate"
    assert "aws_nat_gateway.new" in findings[0].message


def test_the_cost_total_is_rounded_the_way_go_rounds_it() -> None:
    """`%.0f` sur une valeur qui se termine par .5.

    Le `decimal.shouldRoundUp` de Go arrondit une égalité exacte vers le pair, et
    le `format` de Python aussi — les deux s'accordent, ce qui est la raison pour
    laquelle aucun helper n'existe pour cela. Les totaux de plan tombent souvent
    sur .5 (celui de la fixture vaut 310,5), donc l'accord est épinglé plutôt que
    supposé.
    """
    assert f"{310.5:.0f}" == "310"
    assert f"{249.5:.0f}" == "250"
    assert f"{2.5:.0f}" == "2"
    assert f"{3.5:.0f}" == "4"


def test_drift_compares_numbers_the_way_go_decodes_them(
    kb: schema.KnowledgeBase,
) -> None:
    """Go décode chaque nombre JSON en float64, si bien qu'un plan dont le
    before vaut `5` et l'after `5.0` ne montre aucun changement. Python garde
    l'un en entier et l'autre en flottant, et comparer le `str()` de chacun
    rapporterait une dérive sur un attribut auquel rien n'a touché."""
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
