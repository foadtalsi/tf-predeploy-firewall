"""Règles de phase 2 : ce que `terraform plan` dit qu'il va réellement se passer."""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import ignore, planjson
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase
from .changedattrs import ChangedAttrKey, bare_resource_address
from .engine import attach_doc_urls
from .goformat import sprint


@dataclass(slots=True)
class PlanRuleConfig:
    """Configure les règles de phase 2 fondées sur le plan."""

    #: The number of destroy/replace actions that triggers the blast-radius
    #: rule. Zero disables it.
    blast_radius_threshold: int = 0
    #: Suppresses these categories, same as the static scan.
    global_ignore: list[Category | str] = field(default_factory=list)


def run_plan_rules(
    plan_path: str,
    pf: planjson.PlanFile,
    changed_attrs: dict[str, set[ChangedAttrKey]],
    kb: KnowledgeBase | None,
    config: PlanRuleConfig,
) -> list[Finding]:
    """Exécute chaque règle de phase 2 contre un plan `terraform show -json` analysé."""
    findings: list[Finding] = []
    findings += ConfirmedReplaceRule().check(plan_path, pf.resource_changes, kb)
    findings += DriftRule().check(plan_path, pf.resource_changes, changed_attrs, kb)
    findings += BlastRadiusRule(threshold=config.blast_radius_threshold).check(
        plan_path, pf.resource_changes, kb
    )

    # No per-line inline ignore directives apply to plan-derived findings —
    # there is no .tf source line to attach a comment to — so only the
    # config-level ignore list applies here.
    kept = ignore.apply(findings, {}, config.global_ignore)
    attach_doc_urls(kept, kb)
    return kept


def deduplicate_force_new_against_plan(
    static_findings: list[Finding], plan_findings: list[Finding]
) -> list[Finding]:
    """Retire les découvertes force-new de phase 1 pour toute ressource dont le plan a déjà
    confirmé le remplacement."""
    confirmed = {
        bare_resource_address(finding.resource)
        for finding in plan_findings
        if finding.category == Category.CONFIRMED_REPLACE
    }
    if not confirmed:
        return static_findings

    return [
        finding
        for finding in static_findings
        if not (
            finding.category == Category.FORCE_NEW_CHANGE
            and bare_resource_address(finding.resource) in confirmed
        )
    ]


class ConfirmedReplaceRule:
    """Signale toute ressource que Terraform a réellement décidé de détruire — suppression pure,
    ou remplacement par suppression puis création — sur un type de ressource critique ou à
    état."""

    def check(
        self,
        plan_path: str,
        changes: list[planjson.ResourceChange],
        knowledge_base: KnowledgeBase | None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for resource_change in changes:
            if not resource_change.is_managed():
                continue  # data source reads are never destroyed/replaced
            critical = knowledge_base is not None and knowledge_base.is_critical(
                resource_change.type
            )

            if resource_change.change.is_destroy_only():
                if not critical:
                    continue
                findings.append(
                    Finding(
                        file=plan_path,
                        line=1,
                        category=Category.CONFIRMED_REPLACE,
                        rule_name="confirmed_replace",
                        severity=Severity.CRITICAL,
                        resource=resource_change.address,
                        message=(
                            f"terraform plan confirms {resource_change.type} will be DESTROYED with "
                            "no replacement — this is a stateful/critical resource type; "
                            "verify this is intentional before merging"
                        ),
                    )
                )
            elif resource_change.change.is_replace():
                findings.append(
                    Finding(
                        file=plan_path,
                        line=1,
                        category=Category.CONFIRMED_REPLACE,
                        rule_name="confirmed_replace",
                        severity=Severity.CRITICAL if critical else Severity.HIGH,
                        resource=resource_change.address,
                        message=(
                            f"terraform plan confirms {resource_change.type} will be destroyed and "
                            "recreated (replace) — data loss risk if this resource holds "
                            "state"
                        ),
                    )
                )

        return findings


class DriftRule:
    """Signale une mise à jour de plan où la valeur d'un attribut sensible change alors que le
    diff .tf de cette PR n'y a jamais touché."""

    def check(
        self,
        plan_path: str,
        changes: list[planjson.ResourceChange],
        changed_attrs: dict[str, set[ChangedAttrKey]],
        knowledge_base: KnowledgeBase | None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for resource_change in changes:
            if not resource_change.is_managed() or not resource_change.change.is_pure_update():
                continue
            spec = (
                knowledge_base.force_new(resource_change.type)
                if knowledge_base is not None
                else None
            )
            if spec is None or not spec.top_level:
                continue

            # `changed_attrs` is keyed by the bare "type.name" address the HCL
            # parser produces; a plan address may carry a module path or an
            # instance key, neither of which the static scan has any concept of.
            touched_by_pr = changed_attrs.get(bare_resource_address(resource_change.address))

            # A nil state on either side reads as "attribute absent", which is
            # what Go's lookup against a nil map returns.
            state_before = resource_change.change.before or {}
            state_after = resource_change.change.after or {}

            for attr_name in spec.top_level:
                if attr_name not in state_before or attr_name not in state_after:
                    continue
                before, after = state_before[attr_name], state_after[attr_name]
                if sprint(before) == sprint(after):
                    continue
                if touched_by_pr is not None and attr_name in touched_by_pr:
                    continue  # this PR's diff explains the change; not drift

                before_str, after_str = sprint(before), sprint(after)
                if resource_change.change.is_sensitive_attr(attr_name):
                    before_str = after_str = "(sensitive value, redacted)"

                findings.append(
                    Finding(
                        file=plan_path,
                        line=1,
                        category=Category.UNEXPECTED_DRIFT,
                        rule_name="unexpected_drift",
                        severity=Severity.MEDIUM,
                        resource=resource_change.address,
                        message=(
                            f'terraform plan shows "{attr_name}" changing from '
                            f"{before_str} to {after_str} on {resource_change.type}, but this PR's "
                            ".tf diff doesn't touch that attribute — the change is "
                            "coming from elsewhere (state drift, a provider default, or "
                            "an out-of-band edit); verify before merging"
                        ),
                    )
                )

        return findings


@dataclass(slots=True)
class BlastRadiusRule:
    """Signale un plan dont le nombre d'actions de destruction ou de
    remplacement dépasse un seuil configurable — signe que quelque chose (une
    refonte de module, une montée de version de fournisseur, une ressource
    déplacée sans bloc `moved`) s'apprête à toucher bien plus d'infrastructure
    qu'une PR ordinaire ne devrait."""

    #: The number of destroy+replace actions that triggers the finding. Zero or
    #: negative disables the rule.
    threshold: int = 0

    def check(
        self,
        plan_path: str,
        changes: list[planjson.ResourceChange],
        knowledge_base: KnowledgeBase | None,
    ) -> list[Finding]:
        if self.threshold <= 0:
            return []

        destructive = [
            resource_change.address
            for resource_change in changes
            if resource_change.is_managed()
            and (resource_change.change.is_destroy_only() or resource_change.change.is_replace())
        ]

        if len(destructive) < self.threshold:
            return []

        severity = Severity.CRITICAL if len(destructive) >= self.threshold * 2 else Severity.HIGH

        return [
            Finding(
                file=plan_path,
                line=1,
                category=Category.LARGE_BLAST_RADIUS,
                rule_name="large_blast_radius",
                severity=severity,
                resource=f"{len(destructive)} resources",
                message=(
                    f"this plan destroys or replaces {len(destructive)} resources "
                    f"(threshold: {self.threshold}) — blast radius is unusually large "
                    "for a single PR; double check this isn't an unintended module move "
                    "or provider upgrade side-effect. Affected: " + _join_truncated(destructive, 10)
                ),
            )
        ]


def _join_truncated(items: list[str], limit: int) -> str:
    if len(items) <= limit:
        return ", ".join(items)
    return f"{', '.join(items[:limit])}, and {len(items) - limit} more"
