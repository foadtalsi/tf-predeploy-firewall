"""Detect providers used by scanned files and select available extended schema packs."""

from __future__ import annotations

import re
import sys

from ..diff import ChangedFile
from ..schema import Coverage

#: Every provider a rule pack exists for — both the free pack shipped with the
#: distribution and the extended one the control plane serves. Auto-detection
#: is filtered through it so a repo full of `random_pet` and `tls_private_key`
#: resources does not trigger a doomed pack fetch (and its warning) per
#: provider per scan. `--providers` overrides the filter for anyone who knows
#: better.
#:
#: A provider belongs here only once its packs actually ship. Listing one ahead
#: of its pack produces the worst outcome available: the scan warns that
#: coverage "falls back to the embedded pack" for a provider that has no
#: embedded pack, which reads as degraded coverage where there is none at all.
FETCHABLE_PROVIDERS = frozenset({"aws", "azurerm"})

#: Providers that declare no cloud infrastructure worth a rule pack, so their
#: absence from one is not a coverage gap worth reporting. `random`, `tls`,
#: `null` and their kind appear in almost every repo and will never have a
#: pack; warning about them on every scan would train people to skip the line
#: that matters.
SCHEMALESS_PROVIDERS = frozenset(
    {
        "random",
        "tls",
        "null",
        "local",
        "time",
        "external",
        "http",
        "template",
        "archive",
        "cloudinit",
        "dns",
        "terraform",
    }
)

#: Pulls the provider prefix out of resource and data block headers:
#: `resource "aws_db_instance" …` → aws. The convention — everything before the
#: first underscore names the provider — is universal across registry
#: providers because the registry itself enforces it.
_PROVIDER_PREFIX = re.compile(rb'^\s*(?:resource|data)\s+"([a-z][a-z0-9]*)_', re.MULTILINE)


def resolve_providers(flag_value: str, files: list[ChangedFile]) -> list[str]:
    """Resolve --providers from an explicit list or detected providers with available packs."""
    if flag_value != "auto":
        return [provider.strip() for provider in flag_value.split(",") if provider.strip()]
    return [provider for provider in detect_providers(files) if provider in FETCHABLE_PROVIDERS]


def detect_providers(files: list[ChangedFile]) -> list[str]:
    """Return all provider prefixes in scanned files, before filtering by available schema
    coverage.
    """
    seen: set[str] = set()
    for changed_file in files:
        for match in _PROVIDER_PREFIX.finditer(changed_file.head_content):
            seen.add(match.group(1).decode())
    return sorted(seen)


def warn_uncovered_providers(files: list[ChangedFile], cov: Coverage) -> None:
    """Warn about providers without schemas. Schema-independent value checks still run."""
    covered = {provider.name for provider in cov.providers}
    uncovered = [
        provider
        for provider in detect_providers(files)
        if provider not in covered and provider not in SCHEMALESS_PROVIDERS
    ]
    if not uncovered:
        return
    print(
        f"tf-predeploy-firewall: no rule pack for {', '.join(uncovered)} — those "
        "resources were still checked for hardcoded credentials, open CIDRs and your "
        "custom rules, but NOT for unknown arguments, destroy/recreate traps, missing "
        "prevent_destroy, or cost",
        file=sys.stderr,
    )
