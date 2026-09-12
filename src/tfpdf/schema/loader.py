"""Load valid attributes, ForceNew fields, and stateful-resource metadata without Terraform
execution or credentials.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from importlib import resources
from typing import IO, Any

#: The on-disk pack layout this build understands. A pack declaring a newer
#: version is rejected rather than half-read: a pack is security-relevant data,
#: and silently ignoring fields we don't recognise could turn a blocking
#: finding into a missed one.
PACK_FORMAT_VERSION = 1

#: Maps a provider's short name to its Terraform Registry namespace. Unlisted
#: providers fall back to hashicorp/<name>, which is right for the official
#: ones and produces a link that 404s rather than a wrong one for anything else.
REGISTRY_NAMESPACE = {
    "aws": "hashicorp",
    "azurerm": "hashicorp",
}


class PackError(ValueError):
    """An unreadable schema pack."""


@dataclass(slots=True)
class ForceNewSpec:
    """Top-level and nested attributes that trigger resource replacement."""

    top_level: list[str] = field(default_factory=list)
    #: Block path -> ForceNew argument names inside it.
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class ResourceSchema:
    """Valid top-level and nested attributes for a resource type."""

    #: Valid top-level argument names, including nested block names and
    #: Terraform's own meta-arguments.
    top_level: list[str] = field(default_factory=list)
    #: Block path -> valid argument names inside it. Paths absent from this map
    #: are not validated, so an unrecognised block can never produce a finding.
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class _PackResource:
    """A resource entry in the on-disk pack format."""

    top_level: list[str] = field(default_factory=list)
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)
    force_new_top_level: list[str] = field(default_factory=list)
    force_new_nested: dict[str, list[str]] = field(default_factory=dict)
    critical: bool = False


class _LoadedPack:
    """Pack metadata and resource entries awaiting decoding."""

    __slots__ = ("_decoded", "format_version", "id", "provider", "provider_version", "resources")

    def __init__(self, document: dict[str, Any]) -> None:
        self.format_version: int = int(document.get("format_version", 0) or 0)
        self.id: str = str(document.get("id", ""))
        self.provider: str = str(document.get("provider", ""))
        self.provider_version: str = str(document.get("provider_version", ""))
        self.resources: dict[str, Any] = document.get("resources") or {}
        self._decoded: dict[str, _PackResource | None] = {}

    def resource(self, r_type: str) -> _PackResource | None:
        if r_type in self._decoded:
            return self._decoded[r_type]
        raw = self.resources.get(r_type)
        if raw is None:
            return None
        try:
            resource = _decode_resource(raw)
        except (TypeError, ValueError, AttributeError):
            # A malformed entry means this type is simply unknown to us. It
            # must not take down a scan that has nothing to do with it.
            self._decoded[r_type] = None
            return None
        self._decoded[r_type] = resource
        return resource


def _decode_resource(raw: Any) -> _PackResource:
    if not isinstance(raw, dict):
        raise TypeError("resource entry is not an object")
    return _PackResource(
        top_level=list(raw.get("top_level") or []),
        nested_blocks={k: list(v) for k, v in (raw.get("nested_blocks") or {}).items()},
        force_new_top_level=list(raw.get("force_new_top_level") or []),
        force_new_nested={k: list(v) for k, v in (raw.get("force_new_nested") or {}).items()},
        critical=bool(raw.get("critical", False)),
    )


@dataclass(slots=True, frozen=True)
class ProviderCoverage:
    """Coverage information for one provider."""

    name: str
    version: str


@dataclass(slots=True)
class Coverage:
    """Loaded schema coverage displayed in scan summaries and used to explain detection limits."""

    #: The loaded pack IDs, sorted.
    packs: list[str] = field(default_factory=list)
    #: Each covered provider with the release its outermost pack describes,
    #: sorted by name. Per provider, not global: the single provider_version
    #: field this replaces was silently overwritten by whichever pack loaded
    #: last, which was already wrong the moment a second provider's pack sat
    #: next to the first.
    providers: list[ProviderCoverage] = field(default_factory=list)
    #: The number of distinct types across all loaded packs.
    resource_types: int = 0
    #: Whether anything is overlaid on the embedded packs.
    extended: bool = False

    def version_of(self, provider: str) -> str:
        """Return the provider version described by loaded packs, or an empty string if absent."""
        for provider_coverage in self.providers:
            if provider_coverage.name == provider:
                return provider_coverage.version
        return ""


class KnowledgeBase:
    """Loaded schema packs for one or more providers."""

    __slots__ = ("_embedded", "_packs")

    def __init__(self, packs: list[_LoadedPack] | None = None, embedded: int = 0) -> None:
        #: Consulted last-first, so a pack overlaid at scan time takes
        #: precedence over an embedded base pack for any type they share.
        self._packs: list[_LoadedPack] = packs or []
        #: How many of those packs shipped inside the distribution, so
        #: `coverage` can tell "extended" apart from "free tier" without caring
        #: how many base packs the free tier happens to contain.
        self._embedded = embedded

    # --- lookups ----------------------------------------------------------

    def _lookup(self, r_type: str) -> _PackResource | None:
        for pack in reversed(self._packs):
            resource = pack.resource(r_type)
            if resource is not None:
                return resource
        return None

    def resource_schema(self, r_type: str) -> ResourceSchema | None:
        """Return a resource type's valid attribute schema."""
        resource = self._lookup(r_type)
        if resource is None or not resource.top_level:
            return None
        return ResourceSchema(top_level=resource.top_level, nested_blocks=resource.nested_blocks)

    def force_new(self, r_type: str) -> ForceNewSpec | None:
        """Return a resource type's ForceNew attributes."""
        resource = self._lookup(r_type)
        if resource is None or (not resource.force_new_top_level and not resource.force_new_nested):
            return None
        return ForceNewSpec(
            top_level=resource.force_new_top_level, nested_blocks=resource.force_new_nested
        )

    def is_critical(self, r_type: str) -> bool:
        """Check whether the resource type is stateful and should have prevent_destroy protection."""
        resource = self._lookup(r_type)
        return resource is not None and resource.critical

    def coverage(self) -> Coverage:
        seen: set[str] = set()
        versions: dict[str, str] = {}

        c = Coverage(extended=len(self._packs) > self._embedded)
        for pack in self._packs:
            c.packs.append(pack.id)
            # Later packs overlay earlier ones, so the last version recorded
            # per provider is the one lookups actually resolve against.
            versions[pack.provider] = pack.provider_version
            seen.update(pack.resources)

        c.providers = sorted(
            (ProviderCoverage(name=n, version=v) for n, v in versions.items()),
            key=lambda provider: provider.name,
        )
        c.resource_types = len(seen)
        c.packs.sort()
        return c

    # --- documentation links ---------------------------------------------

    def _pack_for(self, r_type: str) -> _LoadedPack | None:
        """Find the pack supplying a resource type so documentation links use its actual provider
        version.
        """
        for pack in reversed(self._packs):
            if pack.resource(r_type) is not None:
                return pack
        return None

    def doc_url(self, r_type: str, data_source: bool = False) -> str:
        """Return the resource type's Terraform Registry page, or an empty string when uncovered."""
        pack = self._pack_for(r_type)
        if pack is None:
            return ""

        namespace = REGISTRY_NAMESPACE.get(pack.provider, "hashicorp")
        version = pack.provider_version or "latest"

        # Registry doc slugs drop the provider prefix: aws_db_instance is
        # documented at .../docs/resources/db_instance.
        prefix = pack.provider + "_"
        slug = r_type[len(prefix) :] if r_type.startswith(prefix) else r_type
        section = "data-sources" if data_source else "resources"

        return (
            f"https://registry.terraform.io/providers/{namespace}/{pack.provider}/"
            f"{version}/docs/{section}/{slug}"
        )


def parse_pack(fp: IO[bytes] | bytes) -> _LoadedPack:
    """Read a gzip-compressed schema pack."""
    raw = fp if isinstance(fp, bytes) else fp.read()
    try:
        decompressed = gzip.decompress(raw)
    except (OSError, EOFError) as exc:
        raise PackError(f"pack is not gzip: {exc}") from exc
    try:
        document = json.loads(decompressed)
    except json.JSONDecodeError as exc:
        raise PackError(f"decoding pack: {exc}") from exc
    if not isinstance(document, dict):
        raise PackError("pack is not an object")

    pack = _LoadedPack(document)
    if pack.format_version != PACK_FORMAT_VERSION:
        raise PackError(
            f"pack {pack.id!r} has format version {pack.format_version}, this build "
            f"understands {PACK_FORMAT_VERSION} — upgrade the scanner"
        )
    return pack


def load() -> KnowledgeBase:
    """Load embedded schema coverage, also used when no extended pack is available."""
    packs: list[_LoadedPack] = []
    data_dir = resources.files(__package__).joinpath("data")
    names = sorted(pack.name for pack in data_dir.iterdir() if pack.name.endswith(".json.gz"))
    for name in names:
        try:
            packs.append(parse_pack(data_dir.joinpath(name).read_bytes()))
        except PackError as exc:
            # A shipped pack that doesn't parse is a broken build, not a
            # degraded one — it was checked in, so fail loudly at load rather
            # than quietly scanning with a provider missing.
            raise PackError(f"loading shipped pack {name}: {exc}") from exc
    if not packs:
        raise PackError("no shipped rule packs — broken build")
    return KnowledgeBase(packs=packs, embedded=len(packs))


def load_with(*extra: IO[bytes] | bytes) -> tuple[KnowledgeBase, list[Exception]]:
    """Overlay packs in order and return available coverage with any loading errors."""
    errs: list[Exception] = []
    knowledge_base = load()
    for resource in extra:
        try:
            knowledge_base._packs.append(parse_pack(resource))
        except PackError as exc:
            errs.append(exc)
    return knowledge_base, errs
