"""Declarative custom detection rules loaded from local configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

from .parser import Attribute, Resource
from .report.finding import Finding, Severity
from .rules import FileInput
from .schema import KnowledgeBase

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class CustomRuleError(ValueError):
    """A custom ruleset that could not be parsed or validated."""


@dataclass(slots=True)
class Rule:
    """A custom detection rule as declared in YAML."""

    id: str = ""
    # Exact resource type, or * for every resource.
    resource_type: str = ""
    # Optional nested block type; omit to inspect top-level attributes.
    block: str = ""
    # Optional attribute name; omit to flag the resource or block itself.
    attribute: str = ""
    # Regex tested against the attribute's literal value.
    pattern: str = ""
    # Flag an absent attribute or a nonmatching value for must-have rules.
    negate: bool = False
    severity: str = ""
    message: str = ""

    compiled: re.Pattern[str] | None = field(default=None, repr=False)

    def validate(self) -> None:
        if not self.id:
            raise CustomRuleError("id is required")
        if not self.resource_type:
            raise CustomRuleError("resource_type is required")
        if self.severity not in VALID_SEVERITIES:
            raise CustomRuleError(
                f"severity must be one of low/medium/high/critical, got {self.severity!r}"
            )
        if not self.message:
            raise CustomRuleError("message is required")
        if not self.pattern and self.attribute:
            raise CustomRuleError(
                f"attribute {self.attribute!r} is set but pattern is empty — a pattern is "
                "required to evaluate the attribute's value (omit both to just flag the "
                "resource's/block's presence)"
            )
        if self.pattern:
            try:
                self.compiled = re.compile(self.pattern)
            except re.error as exc:
                raise CustomRuleError(f"invalid pattern: {exc}") from exc

    def check(self, path: str, resource: Resource) -> list[Finding]:
        if self.resource_type != "*" and self.resource_type != resource.type:
            return []

        if self.block:
            findings: list[Finding] = []
            for b in resource.blocks:
                if b.type != self.block:
                    continue
                finding = self._check_attrs(path, resource, b.attributes, b.range.start.line)
                if finding is not None:
                    findings.append(finding)
            return findings

        finding = self._check_attrs(
            path, resource, resource.attributes, resource.def_range.start.line
        )
        return [finding] if finding is not None else []

    def _check_attrs(
        self,
        path: str,
        res: Resource,
        attrs: dict[str, Attribute],
        fallback_line: int,
    ) -> Finding | None:
        """Evaluate a rule against resource attributes or a nested block's attributes."""
        line = fallback_line
        matched = False

        if not self.attribute:
            # Without an attribute filter, flag the resource or block itself.
            matched = True
        else:
            attribute = attrs.get(self.attribute)
            if attribute is not None and attribute.is_literal and self.compiled is not None:
                line = attribute.range.start.line
                matched = bool(self.compiled.search(attribute.raw_value)) != self.negate
            elif attribute is not None and not self.negate:
                # Skip unresolved expressions rather than guessing their values.
                matched = False
            elif attribute is None:
                # An absent attribute matches only a negated must-have rule.
                matched = self.negate

        if not matched:
            return None

        return Finding(
            file=path,
            line=line,
            # Custom categories use custom:<id> strings rather than the closed built-in Category
            # enum.
            category="custom:" + self.id,
            # Prefix custom rule IDs to prevent collisions with built-in IDs.
            rule_name="custom:" + self.id,
            severity=Severity(self.severity),
            resource=res.address(),
            message=self.message,
        )


@dataclass(slots=True)
class Config:
    """A complete custom ruleset loaded from YAML configuration."""

    rules: list[Rule] = field(default_factory=list)

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        """Run custom rules through the same engine interface as built-in rules."""
        findings: list[Finding] = []
        for resource in file_input.head_resources:
            for r in self.rules:
                findings.extend(r.check(file_input.path, resource))
        return findings

    def as_engine_rule(self) -> Config:
        """Return this ruleset as an engine rule; retained for Go API compatibility."""
        return self


def load(data: bytes | str) -> Config:
    """Parse and validate a custom ruleset."""
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise CustomRuleError(f"parsing custom rules: {exc}") from exc

    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise CustomRuleError("custom rules: top level is not a mapping")

    config = Config()
    for i, entry in enumerate(raw.get("custom_rules") or []):
        if not isinstance(entry, dict):
            raise CustomRuleError(f"custom rule {i}: not a mapping")
        rule = Rule(
            id=str(entry.get("id", "")),
            resource_type=str(entry.get("resource_type", "")),
            block=str(entry.get("block", "")),
            attribute=str(entry.get("attribute", "")),
            pattern=str(entry.get("pattern", "")),
            negate=bool(entry.get("negate", False)),
            severity=str(entry.get("severity", "")),
            message=str(entry.get("message", "")),
        )
        try:
            rule.validate()
        except CustomRuleError as exc:
            raise CustomRuleError(f"custom rule {i}: {exc}") from exc
        config.rules.append(rule)
    return config
