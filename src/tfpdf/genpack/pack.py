"""Le pack de règles généré : ce que le moteur de règles sait des types de
ressources d'un fournisseur.

Port de cmd/genpack/pack.go.

Un pack est auto-descriptif : le scanner charge les packs de base et étendus par
le même chemin de code, la seule différence étant d'où viennent les octets.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..report._json import marshal

#: Bumped when the on-disk pack layout changes in a way older scanners cannot
#: read. The loader refuses a pack whose format version it does not recognise
#: rather than silently mis-reading it.
PACK_FORMAT_VERSION = 1


@dataclass(slots=True)
class PackPricing:
    """Reflète `schema.PricingSpec` sur le fil."""

    base: float = 0.0
    attribute: str = ""
    by_attribute: dict[str, float] = field(default_factory=dict)
    default: float = 0.0

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.base:
            out["base"] = self.base
        if self.attribute:
            out["attribute"] = self.attribute
        if self.by_attribute:
            out["by_attribute"] = _sorted_map(self.by_attribute)
        if self.default:
            out["default"] = self.default
        return out

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> PackPricing:
        return cls(
            base=float(document.get("base", 0) or 0),
            attribute=str(document.get("attribute", "") or ""),
            by_attribute={k: float(v) for k, v in (document.get("by_attribute") or {}).items()},
            default=float(document.get("default", 0) or 0),
        )


@dataclass(slots=True)
class PackResource:
    """L'entrée complète de la base de connaissances pour un type de
    ressource."""

    #: Every argument name valid at the resource's top level, including nested
    #: block names and Terraform meta-arguments.
    top_level: list[str] = field(default_factory=list)

    #: Maps a dotted block path ("root_block_device",
    #: "capacity_reservation_specification.capacity_reservation_target") to the
    #: argument names valid inside it. Paths absent from this map are not
    #: validated at all, so an uncurated block can never produce a finding.
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)

    #: Top-level arguments whose modification forces the resource to be
    #: destroyed and recreated.
    force_new_top_level: list[str] = field(default_factory=list)

    #: The same dotted block paths as `nested_blocks`, to the ForceNew argument
    #: names inside them.
    force_new_nested: dict[str, list[str]] = field(default_factory=dict)

    #: Marks a resource type as stateful enough that destroying it loses data,
    #: so it is expected to carry lifecycle { prevent_destroy }.
    critical: bool = False

    #: The coarse monthly cost estimate used by the plan-JSON cost impact rule.
    #: Absent means "contributes $0", never "guess".
    pricing: PackPricing | None = None

    def to_json(self) -> dict[str, Any]:
        """Ordre des champs et omission des valeurs vides exactement comme les
        étiquettes de structure Go les produisent, pour qu'un pack régénéré
        puisse être comparé à un pack commité."""
        out: dict[str, Any] = {"top_level": sorted(self.top_level)}
        if self.nested_blocks:
            out["nested_blocks"] = _sorted_map(
                {k: sorted(v) for k, v in self.nested_blocks.items()}
            )
        if self.force_new_top_level:
            out["force_new_top_level"] = sorted(self.force_new_top_level)
        if self.force_new_nested:
            out["force_new_nested"] = _sorted_map(
                {k: sorted(v) for k, v in self.force_new_nested.items()}
            )
        if self.critical:
            out["critical"] = True
        if self.pricing is not None:
            out["pricing"] = self.pricing.to_json()
        return out


def _sorted_map(m: dict[str, Any]) -> dict[str, Any]:
    """Go trie les clés d'un map à la sérialisation ; les champs d'une structure
    gardent l'ordre de déclaration. Python préserve l'ordre d'insertion, donc le
    tri doit être explicite."""
    return {k: m[k] for k in sorted(m)}


@dataclass(slots=True)
class Pack:
    """Un pack de règles."""

    #: Identifies the pack ("aws-base", "aws-full"). Reported in scan output so
    #: a finding can always be traced back to the pack that made it.
    id: str = ""
    #: The Terraform provider these resources belong to.
    provider: str = ""
    #: Which provider release the attribute surface was generated from, so "is
    #: this attribute really unknown?" has an auditable answer.
    provider_version: str = ""
    #: resource_type -> everything known about it.
    resources: dict[str, PackResource] = field(default_factory=dict)
    format_version: int = PACK_FORMAT_VERSION

    def to_json(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "id": self.id,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "resources": {k: self.resources[k].to_json() for k in sorted(self.resources)},
        }

    def subset(self, pack_id: str, types: list[str]) -> Pack:
        """Un nouveau pack ne contenant que les types de ressources nommés — sert
        à découper le pack de base gratuit dans le pack complet généré, pour que
        les deux ne puissent jamais diverger ni être en désaccord sur une même
        ressource."""
        return Pack(
            format_version=self.format_version,
            id=pack_id,
            provider=self.provider,
            provider_version=self.provider_version,
            resources={t: self.resources[t] for t in types if t in self.resources},
        )

    def encode(self) -> bytes:
        """Le JSON du pack, exactement comme le `json.Encoder` de Go l'écrit :
        compact, clés de map triées, et le saut de ligne final qu'`Encode`
        ajoute."""
        return marshal(self.to_json()) + b"\n"

    def write_gzip_json(self, path: str | Path) -> None:
        """Écrit le pack en JSON compressé par gzip.

        Les packs sont gzippés sur disque parce que le pack AWS complet fait quelque
        14 Mo de JSON qui se compressent en environ 0,6 Mo — la différence entre un
        fichier livrable et un fichier qui ne l'est pas.

        `mtime=0` parce que l'alternative est un pack dont les octets changent à
        chaque régénération depuis une entrée inchangée, ce que `sortAll` existe
        précisément pour empêcher un niveau plus haut.
        """
        # Best compression: this runs once at generation time, but the result is
        # downloaded by every CI runner on every scan.
        #
        # The file object is opened here rather than passed as a path, because
        # `GzipFile(path)` stamps the filename into the gzip header — the pack
        # would then carry the directory it happened to be generated in.
        with (
            Path(path).open("wb") as fh,
            gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=fh, mtime=0) as gz,
        ):
            gz.write(self.encode())
