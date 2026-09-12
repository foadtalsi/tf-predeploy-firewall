"""Estimation du coût des changements Terraform sans plan."""

from __future__ import annotations

from .. import cloudname
from ..parser import Kind, Resource
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase, PricingSpec
from .base import FileInput


class StaticCostRule:
    """Estime le coût mensuel des ressources directement depuis le diff .tf, en
    utilisant la même tarification par type que la règle de coût fondée sur le
    plan — pour la majorité des dépôts qui ne branchent jamais de JSON de plan
    sur le scan.

    En fournir un est strictement meilleur (cela voit les count, for_each et
    valeurs calculées), ce qui est pourquoi le CLI n'exécute cette règle que
    lorsqu'aucun plan n'est donné : une même PR ne doit pas être facturée deux
    fois par deux estimateurs qui pourraient être en désaccord.

    Ce qu'une estimation à partir de la seule source peut honnêtement affirmer,
    et rien de plus :

      - Une ressource NOUVELLE d'un type tarifé coûte environ son prix
        catalogue. Rapportée quand cela franchit le seuil.
      - Un attribut moteur de prix MODIFIÉ (instance_type et consorts) déplace
        l'estimation de A vers B. Rapporté quand la hausse franchit le seuil —
        les baisses ne sont jamais des découvertes, dépenser moins n'a pas
        besoin d'une barrière.

    Les multiplicateurs count et for_each sont délibérément ignorés plutôt que
    devinés : sous-estimer le coût d'une flotte est mauvais, mais inventer un
    nombre est pire.
    """

    __slots__ = ("threshold_usd",)

    def __init__(self, threshold_usd: float) -> None:
        #: The estimated monthly increase that triggers a finding. Zero
        #: disables the rule (it shouldn't be constructed at all then; the
        #: guard is defence in depth).
        self.threshold_usd = threshold_usd

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        if self.threshold_usd <= 0 or knowledge_base is None:
            return []

        findings: list[Finding] = []
        for resource in file_input.head_resources:
            if resource.kind is not Kind.RESOURCE:
                continue
            spec = knowledge_base.pricing_for(resource.type)
            if spec is None:
                continue

            attr_value = _pricing_attr_value(resource, spec)
            new_cost = spec.monthly_cost(attr_value)

            base = file_input.base_resources.get(resource.address())
            if base is None:
                if new_cost >= self.threshold_usd:
                    findings.append(
                        Finding(
                            file=file_input.path,
                            line=resource.def_range.start.line,
                            category=Category.COST_IMPACT,
                            rule_name="static_cost",
                            severity=Severity.MEDIUM,
                            resource=resource.address(),
                            cloud_name=cloudname.of(resource),
                            message=(
                                f"new {resource.type} adds an estimated ${new_cost:.0f}/month"
                                f"{_describe_pricing_driver(spec, attr_value)} — static "
                                "list-price estimate, not a quote; count/for_each not included"
                            ),
                        )
                    )
                continue

            old_cost = spec.monthly_cost(_pricing_attr_value(base, spec))
            if new_cost - old_cost >= self.threshold_usd:
                findings.append(
                    Finding(
                        file=file_input.path,
                        line=_pricing_attr_line(resource, spec),
                        category=Category.COST_IMPACT,
                        rule_name="static_cost",
                        severity=Severity.MEDIUM,
                        resource=resource.address(),
                        cloud_name=cloudname.of(resource),
                        message=(
                            f"{resource.type} estimated cost rises from ${old_cost:.0f} to "
                            f"${new_cost:.0f}/month"
                            f"{_describe_pricing_driver(spec, attr_value)} — static "
                            "list-price estimate, not a quote"
                        ),
                    )
                )
        return findings


def _pricing_attr_value(resource: Resource, spec: PricingSpec) -> str:
    """La valeur littérale de l'attribut moteur de prix, « » quand il n'y en a
    pas ou qu'elle n'est pas connue statiquement — `monthly_cost` retombe alors
    sur le chiffre par défaut du type, ce qui est la réponse honnête pour une
    taille que le scanner ne peut pas voir."""
    if not spec.attribute:
        return ""
    attribute = resource.attributes.get(spec.attribute)
    if attribute is not None and attribute.is_literal:
        return attribute.raw_value
    return ""


def _pricing_attr_line(resource: Resource, spec: PricingSpec) -> int:
    """Ancre une découverte de changement de coût sur l'attribut qui a changé le
    nombre, avec repli sur l'en-tête de la ressource."""
    if spec.attribute:
        attribute = resource.attributes.get(spec.attribute)
        if attribute is not None:
            return attribute.range.start.line
    return resource.def_range.start.line


def _describe_pricing_driver(spec: PricingSpec, attr_value: str) -> str:
    if not spec.attribute or not attr_value:
        return ""
    return f' ({spec.attribute} = "{attr_value}")'
