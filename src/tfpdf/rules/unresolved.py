"""Report guard attributes whose value the scanner could not evaluate.

A guard rule judges a value someone wrote: `publicly_accessible = true`, `storage_encrypted =
false`. When that value is an expression the scanner cannot resolve, such as a variable with no
default, the rule stays silent, which is right, because guessing produces false positives. But
silence there means "not checked", not "safe", and this detector says so.
"""

from __future__ import annotations

from .. import cloudname
from ..parser import Attribute, Resource
from ..report.finding import Category, Finding, Severity
from ..ruledef import Pack
from ..ruledef import Rule as RuleSpec
from ..schema import KnowledgeBase
from .base import FileInput
from .declarative import all_nested_blocks, matches_resource

#: The categories whose rules judge an explicitly written setting. Credential and tutorial rules
#: are left out on purpose: `password = var.db_password` is the correct way to write a password,
#: not a value that went unchecked.
GUARD_CATEGORIES = frozenset(
    {
        "public_exposure",
        "encryption_disabled",
        "audit_disabled",
        "permissive_iam",
        "missing_lifecycle",
    }
)

#: Long expressions are shortened in the message; the line number points at the full text.
_MAX_EXPRESSION_LENGTH = 60


def guard_rules(pack: Pack) -> list[RuleSpec]:
    """Return the declarative rules that judge the written value of a named attribute."""
    return [
        spec
        for spec in pack.rules
        if not spec.disabled
        and spec.category in GUARD_CATEGORIES
        and spec.match is not None
        and spec.match.literal is True
        and spec.match.attr_names
        and spec.match.value_re is not None
    ]


def expression_text(source: bytes, attribute: Attribute) -> str:
    """Return the expression to the right of `name =`, on one line, shortened if long."""
    span = source[attribute.range.start.byte : attribute.range.end.byte].decode(
        "utf-8", errors="replace"
    )
    _, separator, expression = span.partition("=")
    if not separator:
        return "its value"
    expression = " ".join(expression.split())
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        expression = expression[: _MAX_EXPRESSION_LENGTH - 1] + "…"
    return expression or "its value"


class UnresolvedGuardRule:
    """Report each guard attribute whose value is not statically known, once per attribute."""

    __slots__ = ("guards", "severity")

    def __init__(self, spec: RuleSpec, guards: list[RuleSpec]) -> None:
        self.severity = Severity(spec.severity)
        self.guards = guards

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for resource in file_input.head_resources:
            for name, attribute, guard_ids in self._unresolved_guards(resource):
                expression = expression_text(file_input.head_source, attribute)
                findings.append(
                    Finding(
                        file=file_input.path,
                        line=attribute.range.start.line,
                        category=Category.UNRESOLVED_VALUE,
                        rule_name="unresolved_guard_value",
                        cloud_name=cloudname.of(resource),
                        severity=self.severity,
                        resource=resource.address(),
                        message=(
                            f"{name} = {expression} could not be evaluated, so "
                            f"{', '.join(guard_ids)} did not check it — the setting is "
                            "unverified, not safe"
                        ),
                    )
                )
        return findings

    def _unresolved_guards(self, resource: Resource) -> list[tuple[str, Attribute, list[str]]]:
        """Return each non-literal attribute a guard rule would have judged, with those rules."""
        # Keyed by attribute identity: two guards on the same attribute make one finding.
        found: dict[int, tuple[str, Attribute, list[str]]] = {}
        for guard in self.guards:
            match = guard.match
            assert match is not None  # guard_rules keeps declarative rules only
            if not matches_resource(match, resource):
                continue
            candidates: list[tuple[str, Attribute]] = []
            if match.scope in ("attribute", "any_attribute"):
                candidates.extend(resource.attributes.items())
            if match.scope in ("block_attribute", "any_attribute"):
                for block in all_nested_blocks(resource):
                    if match.block_types and block.type not in match.block_types:
                        continue
                    candidates.extend(block.attributes.items())
            for name, attribute in candidates:
                if name not in match.attr_names or attribute.is_literal:
                    continue
                entry = found.setdefault(id(attribute), (name, attribute, []))
                entry[2].append(guard.id)
        return sorted(found.values(), key=lambda entry: entry[1].range.start.byte)
