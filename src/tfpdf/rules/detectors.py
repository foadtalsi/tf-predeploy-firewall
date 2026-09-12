"""Compatibility imports for detectors implemented in neighboring modules."""

from .iam import IAMWildcardRule
from .lifecycle import MissingLifecycleRule
from .schema_checks import ForceNewChangeRule, UnknownAttributeRule
from .version_pinning import UnpinnedVersionRule

__all__ = [
    "ForceNewChangeRule",
    "IAMWildcardRule",
    "MissingLifecycleRule",
    "UnknownAttributeRule",
    "UnpinnedVersionRule",
]
