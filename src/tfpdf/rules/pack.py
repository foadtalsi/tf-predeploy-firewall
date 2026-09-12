"""Connect rule-pack definitions to executable detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from .. import ruledef
from ..ruledef import Pack, RulePackError
from ..ruledef import Rule as RuleSpec
from .base import Options, Rule, RuleSet
from .declarative import DeclarativeRule
from .detectors import (
    ForceNewChangeRule,
    IAMWildcardRule,
    MissingLifecycleRule,
    UnknownAttributeRule,
    UnpinnedVersionRule,
)
from .predicates import CONFIRM_PREDICATES, VALUE_PREDICATES, known_predicates

#: The rules this build reaches for by name. The .tfvars and terragrunt
#: scanners judge a value by exactly the same standard as a resource attribute,
#: and they do it by reading these definitions rather than by re-declaring the
#: patterns — two divergent definitions of "looks like a secret" would be a bug
#: waiting to happen.
REQUIRED_IDS = ("hardcoded_credential", "open_cidr")

CREDENTIAL_VALUE_GROUP = "credential_value"


class BrokenBuildError(RuntimeError):
    """An unusable built-in pack. Stop rather than report success without running rules."""


@dataclass(slots=True, frozen=True)
class _PackRefs:
    pack: Pack
    credential_name: re.Pattern[str] | None
    credential_values: tuple[RuleSpec, ...]
    open_cidr: str


def builtin_pack_source() -> bytes:
    """Return the built-in pack as YAML."""
    return ruledef.builtin_yaml()


@lru_cache(maxsize=1)
def _load_builtin() -> _PackRefs:
    try:
        pack = ruledef.builtin()
        pack.require_ids(*REQUIRED_IDS)
        _validate_predicates(pack)
        if not pack.group(CREDENTIAL_VALUE_GROUP):
            raise RulePackError(f"rule pack defines no {CREDENTIAL_VALUE_GROUP!r} group")
    except (RulePackError, OSError) as exc:
        raise BrokenBuildError(f"tf-predeploy-firewall: {exc}") from exc

    credential = pack.by_id("hardcoded_credential")
    open_cidr = pack.by_id("open_cidr")
    assert credential is not None and credential.match is not None  # require_ids
    assert open_cidr is not None and open_cidr.match is not None

    values = tuple(
        rule
        for rule in pack.group(CREDENTIAL_VALUE_GROUP)
        if rule.match and rule.match.value_re is not None
    )

    return _PackRefs(
        pack=pack,
        credential_name=credential.match.attr_name_re,
        credential_values=values,
        open_cidr=open_cidr.match.value_contains,
    )


def builtin_pack() -> Pack:
    """Return the pack shipped with this version."""
    return _load_builtin().pack


def _validate_predicates(p: Pack) -> None:
    """Reject predicates unsupported by this scanner version."""
    confirm, value = known_predicates()
    for rule in p.rules:
        if rule.match is None:
            continue
        if rule.match.confirm and rule.match.confirm not in CONFIRM_PREDICATES:
            raise RulePackError(
                f"rule {rule.id!r} names unknown confirm predicate {rule.match.confirm!r} "
                f"(available: {', '.join(confirm)})"
            )
        if rule.match.predicate and rule.match.predicate not in VALUE_PREDICATES:
            raise RulePackError(
                f"rule {rule.id!r} names unknown predicate {rule.match.predicate!r} "
                f"(available: {', '.join(value)})"
            )


@dataclass(slots=True, frozen=True)
class _BuiltRule:
    """An executable rule paired with its declaration for metadata-based filtering."""

    rule: Rule
    #: The definition, or a group's first member.
    spec: RuleSpec


def _build_rules(p: Pack) -> list[_BuiltRule]:
    out: list[_BuiltRule] = []
    emitted: set[str] = set()

    for spec in p.rules:
        if spec.group:
            if spec.group in emitted:
                continue  # the whole group was emitted with its first member
            emitted.add(spec.group)
            group = p.group(spec.group)
            first = group[0]
            assert first.match is not None  # index() rejects a non-declarative member
            out.append(
                _BuiltRule(rule=DeclarativeRule(specs=group, scope=first.match.scope), spec=first)
            )
        elif spec.match is not None:
            out.append(
                _BuiltRule(rule=DeclarativeRule(specs=[spec], scope=spec.match.scope), spec=spec)
            )
        else:
            rule = _compiled_engine(spec)
            if rule is not None:
                out.append(_BuiltRule(rule=rule, spec=spec))
    return out


def from_pack(p: Pack) -> list[Rule]:
    """Build rules in pack order, combining declarative alternatives into first-match groups."""
    return [b.rule for b in _build_rules(p)]


def default_rules(opts: Options | None = None) -> list[Rule]:
    """Return the built-in rules in pack order."""
    return from_pack(builtin_pack())


def rules_for_category(p: Pack, category: str) -> Rule:
    """Combine every rule in a category into one detector."""
    out = RuleSet(b.rule for b in _build_rules(p) if b.spec.category == category)
    if not out:
        raise RulePackError(f"pack defines no runnable rules for category {category!r}")
    return out


def _compiled_engine(spec: RuleSpec) -> Rule | None:
    """Build a static detector, returning None for plan rules and disabled rules."""
    engine = spec.engine
    if engine == "unknown_attribute":
        return UnknownAttributeRule()
    if engine == "force_new_change":
        return ForceNewChangeRule()
    if engine == "missing_lifecycle":
        return MissingLifecycleRule()
    if engine == "unpinned_version":
        return UnpinnedVersionRule()
    if engine == "iam_wildcard":
        return IAMWildcardRule()

    if engine in (
        "confirmed_replace",
        "unexpected_drift",
        "large_blast_radius",
    ):
        return None

    raise RulePackError(f"rule {spec.id!r} names unknown engine {spec.engine!r}")


# --- the shared value vocabulary -----------------------------------------


def is_credential_attr_name(name: str) -> bool:
    """Check whether an attribute name suggests credentials, such as password, api_key, or token."""
    pattern = _load_builtin().credential_name
    return pattern is not None and pattern.search(name) is not None


def match_credential_value_pattern(value: str) -> tuple[str, bool]:
    """Match a value against known credential formats. Return (pattern label, True), or ("",
    False).
    """
    from .entropy import byte_len

    for spec in _load_builtin().credential_values:
        matcher = spec.match
        assert matcher is not None and matcher.value_re is not None  # filtered at load
        if matcher.min_length > 0 and byte_len(value) < matcher.min_length:
            continue
        found = matcher.value_re.search(value)
        if found is None or not found.group(0):
            continue
        if matcher.confirm and not CONFIRM_PREDICATES[matcher.confirm](found.group(0)):
            continue
        return spec.label, True
    return "", False


def is_open_cidr(value: str) -> bool:
    """Check whether a value matches the pack's unrestricted CIDR pattern."""
    return value == _load_builtin().open_cidr
