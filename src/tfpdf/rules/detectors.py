"""Détecteurs compilés, regroupés par responsabilité dans les modules voisins.

Les imports historiques restent disponibles ici.
"""

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
