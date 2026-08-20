"""Le plan de contrôle optionnel : décompte d'usage, politique
d'organisation, dérogations, et livraison des packs de règles étendus.

Port de internal/licensing. Entièrement sur adhésion — sans clé d'API
configurée, rien ici n'est invoqué.
"""

from .client import (
    DEFAULT_API_BASE,
    Client,
    FindingSummary,
    LicensingError,
    ScanResult,
    new_client,
)
from .policy import Policy, policy_from_json
from .rulepacks import (
    PACK_CACHE_TTL_SECONDS,
    PACK_FETCH_TIMEOUT,
    NoPackAvailableError,
    RulePack,
    cache_fresh,
    fetch_rule_pack,
    pack_cache_dir,
    pack_file_name,
    read_cached_pack,
    write_cached_pack,
)
from .waivers import Waiver, waivers_from_json

__all__ = [
    "DEFAULT_API_BASE",
    "PACK_CACHE_TTL_SECONDS",
    "PACK_FETCH_TIMEOUT",
    "Client",
    "FindingSummary",
    "LicensingError",
    "NoPackAvailableError",
    "Policy",
    "RulePack",
    "ScanResult",
    "Waiver",
    "cache_fresh",
    "fetch_rule_pack",
    "new_client",
    "pack_cache_dir",
    "pack_file_name",
    "policy_from_json",
    "read_cached_pack",
    "waivers_from_json",
    "write_cached_pack",
]
