"""Serialize rules to editable YAML for --print-rules.

The output expands every rule's conditions without YAML aliases. Loading it
uses the same data-only path as any other external pack.
"""

from __future__ import annotations

from typing import Any

import yaml

from .ruledef import CategoryDoc, Fix, Match, Pack, Rule

# Explicit key order keeps exported YAML stable across runs.
_RULE_KEYS = (
    "id",
    "category",
    "severity",
    "engine",
    "group",
    "label",
    "disabled",
    "params",
    "match",
    "message",
    "suggestion",
    "fix",
)
_MATCH_KEYS = (
    "scope",
    "kinds",
    "resource_types",
    "block_types",
    "attr_names",
    "attr_name_matches",
    "attr_name_not_matches",
    "attr_name_contains",
    "literal",
    "min_length",
    "value_matches",
    "value_contains",
    "value_not_one_of",
    "name_matches",
    "confirm",
    "predicate",
)
_FIX_KEYS = ("action", "lines", "note", "skip_when_resolved")


class _Dumper(yaml.SafeDumper):
    """Render multiline strings in YAML block style for readability."""


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _represent_str)


def _fields(obj: Match | Fix | Rule, keys: tuple[str, ...], default: Any) -> dict[str, Any]:
    """Keep only nondefault fields so empty settings do not imply extra conditions."""
    out: dict[str, Any] = {}
    for key in keys:
        value = getattr(obj, key)
        if value == getattr(default, key):
            continue
        out[key] = value
    return out


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    out = _fields(rule, _RULE_KEYS, Rule())
    if rule.match is not None:
        out["match"] = _fields(rule.match, _MATCH_KEYS, Match())
    if rule.fix is not None:
        out["fix"] = _fields(rule.fix, _FIX_KEYS, Fix())
    return {key: out[key] for key in _RULE_KEYS if key in out}


def _doc_to_dict(doc: CategoryDoc) -> dict[str, Any]:
    return {
        key: getattr(doc, key)
        for key in ("category", "title", "full_description", "markdown")
        if getattr(doc, key)
    }


def to_yaml(pack: Pack) -> bytes:
    """Render YAML that load can reconstruct as an equivalent pack."""
    document: dict[str, Any] = {"version": pack.version}
    if pack.extends:
        document["extends"] = pack.extends
    document["rules"] = [_rule_to_dict(r) for r in pack.rules]
    if pack.docs:
        document["docs"] = [_doc_to_dict(d) for d in pack.docs]

    text = yaml.dump(
        document,
        Dumper=_Dumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    )
    return text.encode("utf-8")
