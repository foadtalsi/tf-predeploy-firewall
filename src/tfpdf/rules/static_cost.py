"""Estimation du coût des changements Terraform sans plan."""

from __future__ import annotations

from .. import cloudname
from ..parser import Kind, Resource
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase, PricingSpec
from .base import FileInput


class StaticCostRule:
    """Estime les hausses de coût sans plan, pour les créations et changements tarifaires. Ignore
    count/for_each ; utiliser les règles de plan lorsqu'un plan existe."""

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
                if not new_cost >= self.threshold_usd:
                    continue
                line = resource.def_range.start.line
                message = (
                    f"new {resource.type} adds an estimated ${new_cost:.0f}/month"
                    f"{_describe_pricing_driver(spec, attr_value)} — static "
                    "list-price estimate, not a quote; count/for_each not included"
                )
            else:
                old_cost = spec.monthly_cost(_pricing_attr_value(base, spec))
                if not new_cost - old_cost >= self.threshold_usd:
                    continue
                line = _pricing_attr_line(resource, spec)
                message = (
                    f"{resource.type} estimated cost rises from ${old_cost:.0f} to "
                    f"${new_cost:.0f}/month"
                    f"{_describe_pricing_driver(spec, attr_value)} — static "
                    "list-price estimate, not a quote"
                )
            findings.append(
                Finding(
                    file=file_input.path,
                    line=line,
                    category=Category.COST_IMPACT,
                    rule_name="static_cost",
                    severity=Severity.MEDIUM,
                    resource=resource.address(),
                    cloud_name=cloudname.of(resource),
                    message=message,
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
