"""Règles de phase 2 : ce que `terraform plan` dit qu'il va réellement se
passer.

Porte internal/rules/planengine.go, rule_plan_confirmed_replace.go,
rule_plan_drift.go, rule_plan_blast_radius.go et rule_plan_cost_impact.go.

Tout ce que font les règles de phase 1 est une lecture de la source. Tout ce que
font celles-ci est une lecture de la décision de Terraform lui-même, fournie par
l'utilisateur sous forme de sortie `terraform show -json` — cet outil n'exécute
jamais Terraform et ne touche jamais lui-même à des identifiants cloud. Cette
différence explique que ces découvertes n'aient pas de numéro de ligne : un plan
n'a aucune position dans une source .tf sur laquelle pointer, elles sont donc
rattachées au fichier de plan, ligne 1.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import ignore, planjson
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase, PricingSpec
from .changedattrs import ChangedAttrKey, bare_resource_address
from .engine import attach_doc_urls
from .goformat import sprint


@dataclass(slots=True)
class PlanRuleConfig:
    """Configure les règles de phase 2 fondées sur le plan."""

    #: The number of destroy/replace actions that triggers the blast-radius
    #: rule. Zero disables it.
    blast_radius_threshold: int = 0
    #: The estimated monthly cost increase (USD) that triggers the cost rule.
    #: Zero disables it.
    cost_impact_threshold_usd: float = 0.0
    #: Suppresses these categories, same as the static scan.
    global_ignore: list[Category | str] = field(default_factory=list)


def run_plan_rules(
    plan_path: str,
    pf: planjson.PlanFile,
    changed_attrs: dict[str, set[ChangedAttrKey]],
    kb: KnowledgeBase | None,
    cfg: PlanRuleConfig,
) -> list[Finding]:
    """Exécute chaque règle de phase 2 contre un plan `terraform show -json`
    analysé.

    `plan_path` rattache les découvertes à un pseudo-fichier. `changed_attrs`
    doit venir du résultat de la passe statique, pour que la règle de dérive
    puisse distinguer un changement volontaire de la PR d'une dérive
    inexpliquée.
    """
    findings: list[Finding] = []
    findings += ConfirmedReplaceRule().check(plan_path, pf.resource_changes, kb)
    findings += DriftRule().check(plan_path, pf.resource_changes, changed_attrs, kb)
    findings += BlastRadiusRule(threshold=cfg.blast_radius_threshold).check(
        plan_path, pf.resource_changes, kb
    )
    findings += CostImpactRule(threshold_usd=cfg.cost_impact_threshold_usd).check(
        plan_path, pf.resource_changes, kb
    )

    # No per-line inline ignore directives apply to plan-derived findings —
    # there is no .tf source line to attach a comment to — so only the
    # config-level ignore list applies here.
    kept = ignore.apply(findings, {}, cfg.global_ignore)
    attach_doc_urls(kept, kb)
    return kept


def deduplicate_force_new_against_plan(
    static_findings: list[Finding], plan_findings: list[Finding]
) -> list[Finding]:
    """Retire les découvertes force-new de phase 1 pour toute ressource dont le
    plan a déjà confirmé le remplacement.

    Les deux règles se déclenchent pour le même problème de fond — « ce
    changement d'attribut détruit et recrée la ressource » — et une fois qu'un
    plan l'a confirmé, répéter la supposition heuristique n'est que du bruit
    par-dessus une certitude.
    """
    confirmed = {
        bare_resource_address(f.resource)
        for f in plan_findings
        if f.category == Category.CONFIRMED_REPLACE
    }
    if not confirmed:
        return static_findings

    return [
        f
        for f in static_findings
        if not (
            f.category == Category.FORCE_NEW_CHANGE
            and bare_resource_address(f.resource) in confirmed
        )
    ]


class ConfirmedReplaceRule:
    """Signale toute ressource que Terraform a réellement décidé de détruire —
    suppression pure, ou remplacement par suppression puis création — sur un
    type de ressource critique ou à état.

    Contrairement à la règle force-new de phase 1, qui devine à partir d'une
    liste curée d'attributs ForceNew, ceci n'est pas une heuristique : c'est ce
    que Terraform lui-même fera à l'apply.
    """

    def check(
        self,
        plan_path: str,
        changes: list[planjson.ResourceChange],
        kb: KnowledgeBase | None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rc in changes:
            if not rc.is_managed():
                continue  # data source reads are never destroyed/replaced
            critical = kb is not None and kb.is_critical(rc.type)

            if rc.change.is_destroy_only():
                if not critical:
                    continue
                findings.append(
                    Finding(
                        file=plan_path,
                        line=1,
                        category=Category.CONFIRMED_REPLACE,
                        severity=Severity.CRITICAL,
                        resource=rc.address,
                        message=(
                            f"terraform plan confirms {rc.type} will be DESTROYED with "
                            "no replacement — this is a stateful/critical resource type; "
                            "verify this is intentional before merging"
                        ),
                    )
                )
            elif rc.change.is_replace():
                findings.append(
                    Finding(
                        file=plan_path,
                        line=1,
                        category=Category.CONFIRMED_REPLACE,
                        severity=Severity.CRITICAL if critical else Severity.HIGH,
                        resource=rc.address,
                        message=(
                            f"terraform plan confirms {rc.type} will be destroyed and "
                            "recreated (replace) — data loss risk if this resource holds "
                            "state"
                        ),
                    )
                )

        return findings


class DriftRule:
    """Signale une mise à jour de plan où la valeur d'un attribut sensible
    change alors que le diff .tf de cette PR n'y a jamais touché.

    Cela veut dire que le changement vient d'ailleurs : une valeur par défaut
    modifiée à la main, une montée de version du fournisseur qui déplace une
    valeur calculée, ou un état ayant déjà dérivé lors d'un changement hors
    bande antérieur. Dans tous les cas, l'auteur de la PR doit savoir que son
    apply fera plus que ce qu'il a écrit.

    La portée est délibérément étroite : uniquement les attributs déjà curés
    comme ForceNew, c'est-à-dire ceux dont on sait qu'ils comptent, et
    uniquement les mises à jour sur place — un remplacement ou une destruction
    est déjà couvert par la règle de remplacement confirmé et ne serait ici que
    du bruit.
    """

    def check(
        self,
        plan_path: str,
        changes: list[planjson.ResourceChange],
        changed_attrs: dict[str, set[ChangedAttrKey]],
        kb: KnowledgeBase | None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rc in changes:
            if not rc.is_managed() or not rc.change.is_pure_update():
                continue
            spec = kb.force_new(rc.type) if kb is not None else None
            if spec is None or not spec.top_level:
                continue

            # `changed_attrs` is keyed by the bare "type.name" address the HCL
            # parser produces; a plan address may carry a module path or an
            # instance key, neither of which the static scan has any concept of.
            touched_by_pr = changed_attrs.get(bare_resource_address(rc.address))

            # A nil state on either side reads as "attribute absent", which is
            # what Go's lookup against a nil map returns.
            state_before = rc.change.before or {}
            state_after = rc.change.after or {}

            for attr_name in spec.top_level:
                if attr_name not in state_before or attr_name not in state_after:
                    continue
                before, after = state_before[attr_name], state_after[attr_name]
                if sprint(before) == sprint(after):
                    continue
                if touched_by_pr is not None and attr_name in touched_by_pr:
                    continue  # this PR's diff explains the change; not drift

                before_str, after_str = sprint(before), sprint(after)
                if rc.change.is_sensitive_attr(attr_name):
                    before_str = after_str = "(sensitive value, redacted)"

                findings.append(
                    Finding(
                        file=plan_path,
                        line=1,
                        category=Category.UNEXPECTED_DRIFT,
                        severity=Severity.MEDIUM,
                        resource=rc.address,
                        message=(
                            f'terraform plan shows "{attr_name}" changing from '
                            f"{before_str} to {after_str} on {rc.type}, but this PR's "
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
        kb: KnowledgeBase | None,
    ) -> list[Finding]:
        if self.threshold <= 0:
            return []

        destructive = [
            rc.address
            for rc in changes
            if rc.is_managed() and (rc.change.is_destroy_only() or rc.change.is_replace())
        ]

        if len(destructive) < self.threshold:
            return []

        severity = Severity.CRITICAL if len(destructive) >= self.threshold * 2 else Severity.HIGH

        return [
            Finding(
                file=plan_path,
                line=1,
                category=Category.LARGE_BLAST_RADIUS,
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


@dataclass(slots=True, frozen=True)
class _ResourceCostDelta:
    """La contribution d'une ressource, conservée pour le message."""

    address: str
    delta: float


@dataclass(slots=True)
class CostImpactRule:
    """Estime le DELTA de coût mensuel qu'un plan provoquera et le signale
    quand il franchit un seuil configurable.

    Les coûts viennent des données de tarification curées — des estimations
    délibérément grossières et indépendantes de la région. Le but est un
    avertissement précoce en relecture, « cette PR augmente sensiblement la
    facture », et non un devis exact à la facturation près : c'est à cela que
    servent Infracost ou le calculateur AWS, après la fusion.

    Modèle du delta, par ressource gérée du plan :
      * création      +coût(après)
      * destruction   -coût(avant)
      * remplacement  coût(après) - coût(avant), généralement 0 sauf si
        l'attribut moteur de prix a changé, par exemple un instance_type revu
        à la hausse
      * mise à jour   coût(après) - coût(avant)

    Les types de ressources absents de la table de tarification contribuent
    0 $ : les types inconnus sont ignorés plutôt que devinés, comme pour tout
    autre fichier de données curées de ce projet.
    """

    #: The monthly cost increase (USD) that triggers a finding. Zero or
    #: negative disables the rule.
    threshold_usd: float = 0.0

    def check(
        self,
        plan_path: str,
        changes: list[planjson.ResourceChange],
        kb: KnowledgeBase | None,
    ) -> list[Finding]:
        if self.threshold_usd <= 0:
            return []

        total = 0.0
        deltas: list[_ResourceCostDelta] = []

        for rc in changes:
            if not rc.is_managed():
                continue
            spec = kb.pricing_for(rc.type) if kb is not None else None
            if spec is None:
                continue

            before_cost = _cost_of_state(spec, rc.change.before)
            after_cost = _cost_of_state(spec, rc.change.after)

            if rc.change.is_destroy_only():
                delta = -before_cost
            elif rc.change.is_no_op():
                continue
            else:
                # create (before absent -> 0), replace, or update: the generic
                # after-minus-before form covers all three.
                delta = after_cost - before_cost
            if delta == 0:
                continue
            total += delta
            deltas.append(_ResourceCostDelta(address=rc.address, delta=delta))

        if total < self.threshold_usd:
            return []

        severity = Severity.HIGH if total >= self.threshold_usd * 5 else Severity.MEDIUM

        return [
            Finding(
                file=plan_path,
                line=1,
                category=Category.COST_IMPACT,
                severity=severity,
                resource=f"+${total:.0f}/month (estimated)",
                message=(
                    f"this plan increases the estimated AWS bill by ~${total:.0f}/month "
                    f"(threshold: ${self.threshold_usd:.0f}) — rough on-demand estimate, "
                    "not a quote. Top contributors: " + _top_contributors(deltas, 5)
                ),
            )
        ]


def _cost_of_state(spec: PricingSpec, state: dict[str, object] | None) -> float:
    """Estime le coût mensuel d'un côté — avant ou après — d'un changement. Un
    état absent, c'est-à-dire une ressource qui n'existe pas de ce côté, vaut
    0 $."""
    if state is None:
        return 0.0
    attr_value = ""
    if spec.attribute:
        v = state.get(spec.attribute)
        if isinstance(v, str):
            attr_value = v
    return spec.monthly_cost(attr_value)


def _top_contributors(deltas: list[_ResourceCostDelta], n: int) -> str:
    """Met en forme les n plus grosses contributions positives, pour que le
    relecteur voie immédiatement CE QUI coûte cher."""
    parts: list[str] = []
    for d in sorted(deltas, key=lambda d: d.delta, reverse=True):
        if d.delta <= 0 or len(parts) >= n:
            break
        parts.append(f"{d.address} (+${d.delta:.0f})")
    if not parts:
        return "(none individually significant)"
    return ", ".join(parts)
