"""Load the built-in rule pack independently of the engine. Keeping it in ruledef avoids a circular
import between rules and report.
"""

from __future__ import annotations

from functools import lru_cache

from . import rules as _rules
from .ruledef import Pack, RulePackError
from .toyaml import to_yaml


@lru_cache(maxsize=1)
def builtin() -> Pack:
    """Build and validate the shared built-in pack once, avoiding repeated regex compilation."""
    try:
        return _rules.build()
    except RulePackError as exc:
        raise RulePackError(f"the embedded rule pack is invalid: {exc}") from exc


def builtin_yaml() -> bytes:
    """Render the built-in pack as editable YAML for --print-rules. User-provided packs are always
    loaded as data, never imported as Python.
    """
    return to_yaml(builtin())
