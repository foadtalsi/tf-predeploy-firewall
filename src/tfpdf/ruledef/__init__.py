"""Le format déclaratif des règles. Port de internal/ruledef."""

from .builtin import builtin, builtin_yaml
from .merge import MergeReport, merge
from .ruledef import (
    EXTENDS_BUILTIN,
    FORMAT_VERSION,
    VALID_FIX_ACTIONS,
    VALID_SCOPES,
    VALID_SEVERITIES,
    CategoryDoc,
    Fix,
    Match,
    Pack,
    Rule,
    RulePackError,
    load,
)

__all__ = [
    "EXTENDS_BUILTIN",
    "FORMAT_VERSION",
    "VALID_FIX_ACTIONS",
    "VALID_SCOPES",
    "VALID_SEVERITIES",
    "CategoryDoc",
    "Fix",
    "Match",
    "MergeReport",
    "Pack",
    "Rule",
    "RulePackError",
    "builtin",
    "builtin_yaml",
    "load",
    "merge",
]
