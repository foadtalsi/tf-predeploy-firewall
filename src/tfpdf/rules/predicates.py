"""The fixed predicate vocabulary available to declarative rules."""

from __future__ import annotations

from collections.abc import Callable

from .entropy import looks_like_secret, shannon_entropy


def looks_like_base64_secret(match: str) -> bool:
    """Check whether a 40-character base64 string plausibly represents random secret material
    rather than a path or identifier.
    """
    has_upper = has_lower = has_digit = False
    for r in match:
        if "A" <= r <= "Z":
            has_upper = True
        elif "a" <= r <= "z":
            has_lower = True
        elif "0" <= r <= "9":
            has_digit = True
    if not (has_upper and has_lower and has_digit):
        return False
    return shannon_entropy(match) >= 4.2


def _hex_entropy(m: str) -> bool:
    return shannon_entropy(m) >= 3.0


#: Run against the substring a rule's `value_matches` found, not the whole
#: value: the point is to judge the candidate the regex picked out. This is
#: what separates a 40-character secret from a 40-character path.
CONFIRM_PREDICATES: dict[str, Callable[[str], bool]] = {
    # Mixed case with digits is what base64 of random bytes looks like and what
    # a lowercase file path never is; the entropy floor then rejects the
    # structured strings that happen to mix case anyway.
    "base64_secret": looks_like_base64_secret,
    # Hex tops out at 4 bits per character, so this floor is low by design — it
    # exists to reject the degenerate runs (forty a's) that satisfy a hex
    # character class while carrying no randomness at all.
    "hex_entropy": _hex_entropy,
}

#: Run against the whole value and return a measurement the message can quote
#: back. A rule that accuses someone on a statistic has to be able to show the
#: statistic.
VALUE_PREDICATES: dict[str, Callable[[str], tuple[float, bool]]] = {
    "looks_like_secret": looks_like_secret,
}


def known_predicates() -> tuple[list[str], list[str]]:
    """Return predicate names accepted during rule-pack validation."""
    return sorted(CONFIRM_PREDICATES), sorted(VALUE_PREDICATES)
