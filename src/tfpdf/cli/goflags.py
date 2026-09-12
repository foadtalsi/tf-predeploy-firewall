"""Accepte les options longues à un tiret des anciens workflows. Les booléens sont traités dans
arguments.py."""

from __future__ import annotations

import re

#: A single-dash long option, with or without an attached value. Deliberately
#: requires a letter after the dash, so a bare "-", a "--" separator and a
#: negative number are all left alone.
_SINGLE_DASH_LONG = re.compile(r"^-([a-zA-Z][a-zA-Z0-9-]*)(=.*)?$", re.DOTALL)


def normalize_argv(argv: list[str]) -> list[str]:
    """Réécrit les options longues à tiret simple, à la Go, sous la forme à double tiret."""
    normalized: list[str] = []
    for index, argument in enumerate(argv):
        if argument == "--":
            normalized.extend(argv[index:])
            break
        match = _SINGLE_DASH_LONG.match(argument)
        # A one-letter option is left as-is: this CLI has none, and rewriting
        # "-h" would break the one short flag argparse provides itself.
        if match is not None and len(match.group(1)) > 1:
            normalized.append("-" + argument)
        else:
            normalized.append(argument)
    return normalized
