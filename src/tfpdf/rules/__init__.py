"""Les détecteurs de motifs de risque et le moteur qui les exécute sur un
diff analysé.

Port de internal/rules.
"""

from .base import FileInput, Options, Rule, RuleSet, RunOptions
from .changedattrs import ChangedAttrKey, bare_resource_address, changed_attrs_for_resource
from .declarative import DeclarativeRule
from .detectors import (
    ForceNewChangeRule,
    IAMWildcardRule,
    MissingLifecycleRule,
    StaticCostRule,
    UnknownAttributeRule,
    UnpinnedVersionRule,
)
from .engine import Result, ScopeCache, attach_doc_urls, run
from .entropy import looks_like_secret, shannon_entropy
from .goformat import sprint
from .pack import (
    BrokenBuildError,
    builtin_pack,
    default_rules,
    from_pack,
    is_credential_attr_name,
    is_open_cidr,
    match_credential_value_pattern,
    rules_for_category,
)
from .plan import (
    BlastRadiusRule,
    ConfirmedReplaceRule,
    CostImpactRule,
    DriftRule,
    PlanRuleConfig,
    deduplicate_force_new_against_plan,
    run_plan_rules,
)

__all__ = [
    "BlastRadiusRule",
    "BrokenBuildError",
    "ChangedAttrKey",
    "ConfirmedReplaceRule",
    "CostImpactRule",
    "DeclarativeRule",
    "DriftRule",
    "FileInput",
    "ForceNewChangeRule",
    "IAMWildcardRule",
    "MissingLifecycleRule",
    "Options",
    "PlanRuleConfig",
    "Result",
    "Rule",
    "RuleSet",
    "RunOptions",
    "ScopeCache",
    "StaticCostRule",
    "UnknownAttributeRule",
    "UnpinnedVersionRule",
    "attach_doc_urls",
    "bare_resource_address",
    "builtin_pack",
    "changed_attrs_for_resource",
    "deduplicate_force_new_against_plan",
    "default_rules",
    "from_pack",
    "is_credential_attr_name",
    "is_open_cidr",
    "looks_like_secret",
    "match_credential_value_pattern",
    "rules_for_category",
    "run",
    "run_plan_rules",
    "shannon_entropy",
    "sprint",
]
