"""L'index ForceNew : quels arguments, une fois modifiés, détruisent et
recréent une ressource.

Charge l'index depuis un artefact JSON, le fusionne sur la surface d'attributs
d'un fournisseur, et définit sa forme sérialisée :

```json
{
  "provider": "aws",
  "provider_version": "6.59.0",
  "top_level": {"aws_instance": ["ami", "availability_zone"]},
  "nested": {"aws_instance": {"root_block_device": ["encrypted"]}},
  "stats": {"sdk_resources_seen": 1204, "sdk_resources_resolved": 1150}
}
```

Ne *produit* pas l'index : c'est le seul manque délibéré du port. La seule
source qui fasse autorité est la déclaration de schéma en Go du fournisseur,
que l'extracteur Go lit avec `go/ast`. La reproduire voudrait dire écrire un
analyseur de Go.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .pack import PackResource
from .schemajson import dedupe


@dataclass(slots=True)
class ForceNewStats:
    """Rapportées pour que la couverture d'un pack soit un nombre mesuré plutôt
    qu'une affirmation."""

    sdk_resources_seen: int = 0
    sdk_resources_resolved: int = 0
    framework_seen: int = 0
    framework_resolved: int = 0


@dataclass(slots=True)
class ForceNewIndex:
    """type de ressource -> chemins ForceNew."""

    #: resource type -> ForceNew top-level argument names.
    top_level: dict[str, list[str]] = field(default_factory=dict)
    #: resource type -> dotted block path -> ForceNew names.
    nested: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    provider: str = ""
    provider_version: str = ""
    stats: ForceNewStats = field(default_factory=ForceNewStats)

    def add(self, r_type: str, path: str, attribute: str) -> None:
        if path == "":
            self.top_level.setdefault(r_type, []).append(attribute)
            return
        self.nested.setdefault(r_type, {}).setdefault(path, []).append(attribute)

    def to_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "provider_version": self.provider_version,
            "top_level": {k: sorted(v) for k, v in sorted(self.top_level.items())},
            "nested": {
                k: {p: sorted(a) for p, a in sorted(v.items())}
                for k, v in sorted(self.nested.items())
            },
            "stats": {
                "sdk_resources_seen": self.stats.sdk_resources_seen,
                "sdk_resources_resolved": self.stats.sdk_resources_resolved,
                "framework_seen": self.stats.framework_seen,
                "framework_resolved": self.stats.framework_resolved,
            },
        }


def load_force_new_index(path: str | Path) -> ForceNewIndex:
    """Lit un index ForceNew produit par l'extracteur."""
    try:
        document = json.loads(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"reading ForceNew index: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"parsing ForceNew index {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"parsing ForceNew index {path}: top level is not an object")

    stats_doc = document.get("stats") or {}
    return ForceNewIndex(
        top_level={k: [str(x) for x in v] for k, v in (document.get("top_level") or {}).items()},
        nested={
            k: {p: [str(x) for x in a] for p, a in (v or {}).items()}
            for k, v in (document.get("nested") or {}).items()
        },
        provider=str(document.get("provider", "")),
        provider_version=str(document.get("provider_version", "")),
        stats=ForceNewStats(
            sdk_resources_seen=int(stats_doc.get("sdk_resources_seen", 0)),
            sdk_resources_resolved=int(stats_doc.get("sdk_resources_resolved", 0)),
            framework_seen=int(stats_doc.get("framework_seen", 0)),
            framework_resolved=int(stats_doc.get("framework_resolved", 0)),
        ),
    )


def apply_force_new(resources: dict[str, PackResource], index: ForceNewIndex) -> None:
    """Fusionne les données ForceNew extraites sur la surface d'attributs, en
    écartant tout ce qui ne correspond pas à un argument réel.

    Une entrée ForceNew pour un argument que le schéma du fournisseur ne déclare
    pas signifierait que l'extracteur a mal lu la source, et agir dessus pourrait
    bloquer une PR sur un argument qui n'existe pas.
    """
    for r_type, attrs in index.top_level.items():
        r = resources.get(r_type)
        if r is None:
            continue
        valid = set(r.top_level)
        r.force_new_top_level = dedupe([*r.force_new_top_level, *(a for a in attrs if a in valid)])

    for r_type, by_path in index.nested.items():
        r = resources.get(r_type)
        if r is None:
            continue
        for path, attrs in by_path.items():
            declared = r.nested_blocks.get(path)
            if declared is None:
                continue
            valid = set(declared)
            keep = [a for a in attrs if a in valid]
            if not keep:
                continue
            r.force_new_nested[path] = dedupe([*r.force_new_nested.get(path, []), *keep])


def index_from_pack(document: dict[str, Any]) -> ForceNewIndex:
    """Reconstitue un index depuis un pack déjà généré.

    Les packs générés sont la sortie commitée de l'extracteur, donc la seule
    source ForceNew disponible sans un checkout de fournisseur et une chaîne
    d'outils Go. Cela les rend utilisables à la fois comme entrée de
    régénération et — dans `test_genpack.py` — comme la fixture qui prouve que
    cette chaîne reproduit exactement les packs commités.
    """
    index = ForceNewIndex(
        provider=str(document.get("provider", "")),
        provider_version=str(document.get("provider_version", "")),
    )
    for r_type, r in (document.get("resources") or {}).items():
        if top := r.get("force_new_top_level"):
            index.top_level[r_type] = list(top)
        if nested := r.get("force_new_nested"):
            index.nested[r_type] = {p: list(a) for p, a in nested.items()}
    return index
