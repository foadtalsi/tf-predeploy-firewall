"""Compare repository provider constraints with available schema versions."""

from __future__ import annotations

import re
from dataclasses import dataclass

# A missing comparison operator means equality, as in Terraform's "3.1.0" constraint.
_TERM = re.compile(r"^\s*(>=|<=|!=|~>|>|<|=)?\s*v?([0-9]+(?:\.[0-9]+)*)\s*$")

# Match both provider object declarations and legacy name = "version" declarations.
_ENTRY_BLOCK = re.compile(r"([a-z][a-z0-9_-]*)\s*=\s*\{(.*?)\}", re.DOTALL)
_ENTRY_SHORT = re.compile(r'([a-z][a-z0-9_-]*)\s*=\s*"([^"]*)"')
_VERSION_IN_ENTRY = re.compile(r'version\s*=\s*"([^"]*)"')


def parse_version(text: str) -> tuple[int, ...]:
    """Parse 6.59.0 into (6, 59, 0), retaining component count for pessimistic constraints (~>)."""
    return tuple(int(part) for part in text.split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Compare versions after zero-padding, treating 3 and 3.0.0 as equal."""
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


@dataclass(frozen=True, slots=True)
class Term:
    operator: str
    version: tuple[int, ...]

    def allows(self, candidate: tuple[int, ...]) -> bool:
        order = _compare(candidate, self.version)
        if self.operator == ">=":
            return order >= 0
        if self.operator == ">":
            return order > 0
        if self.operator == "<=":
            return order <= 0
        if self.operator == "<":
            return order < 0
        if self.operator == "!=":
            return order != 0
        if self.operator == "=":
            return order == 0
        if self.operator == "~>":
            # The written component count determines the upper bound: ~> 3.0 excludes 4.0, while
            # ~> 3.0.1 excludes 3.1.0.
            if order < 0:
                return False
            ceiling = self.version[:-1]
            if not ceiling:
                # With no earlier component to pin, ~> 3 permits 3 and later versions here.
                return True
            bumped = (*ceiling[:-1], ceiling[-1] + 1)
            return _compare(candidate, bumped) < 0
        return True


def parse_constraint(text: str) -> list[Term]:
    """Parse comma-separated constraint terms, all of which must hold. Ignore unrecognized terms
    rather than incorrectly suppressing findings.
    """
    terms: list[Term] = []
    for piece in text.split(","):
        found = _TERM.match(piece)
        if found is None:
            continue
        terms.append(Term(found.group(1) or "=", parse_version(found.group(2))))
    return terms


def allows(constraint: str, version: str) -> bool:
    """Check whether a version satisfies the constraint. Empty or unreadable constraints allow all
    versions.
    """
    terms = parse_constraint(constraint)
    if not terms:
        return True
    candidate = parse_version(version)
    return all(term.allows(candidate) for term in terms)


def constraints_in(source: bytes) -> dict[str, str]:
    """Return required_providers constraints keyed by local provider name."""
    text = source.decode("utf-8", errors="replace")
    found: dict[str, str] = {}
    index = 0
    while True:
        start = text.find("required_providers", index)
        if start < 0:
            return found
        open_index = text.find("{", start)
        if open_index < 0:
            return found
        depth = 0
        end = open_index
        for position in range(open_index, len(text)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    end = position
                    break
        else:
            return found
        body = text[open_index + 1 : end]
        for match in _ENTRY_BLOCK.finditer(body):
            version = _VERSION_IN_ENTRY.search(match.group(2))
            if version is not None:
                found.setdefault(match.group(1), version.group(1))
        # Exclude object bodies from shorthand matching so version is not mistaken for a
        # provider name.
        without_blocks = _ENTRY_BLOCK.sub("", body)
        for match in _ENTRY_SHORT.finditer(without_blocks):
            found.setdefault(match.group(1), match.group(2))
        index = end + 1


def provider_of(resource_type: str) -> str:
    """Return the prefix before the first underscore, such as aws for aws_eip."""
    prefix, separator, _ = resource_type.partition("_")
    return prefix if separator else ""
