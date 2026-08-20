"""Transformation de la sortie de `terraform providers schema -json` en la
moitié « surface d'attributs » d'un pack.

Port de cmd/genpack/schemajson.go.

Pourquoi générer plutôt que curer : le schéma écrit à la main que ceci remplace
listait 29 arguments pour `aws_instance` ; le fournisseur en déclare en réalité
47, plus 16 types de blocs imbriqués. Chaque argument absent d'une liste curée
est une fausse découverte « attribut halluciné » sur du Terraform valide — et
comme cette règle est de sévérité haute, un faux positif y bloque une PR. La
curation ne peut pas suivre un fournisseur qui publie chaque semaine, elle ne
devrait donc pas essayer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .pack import PackResource

#: Valid inside any resource block but Terraform's own, so they never appear in
#: a provider's schema. Without them every `count`, `for_each` or `lifecycle` in
#: a scanned repo would read as a hallucination.
META_ARGUMENTS = (
    "count",
    "depends_on",
    "for_each",
    "lifecycle",
    "provider",
    "provisioner",
    "connection",
    "dynamic",
)


class SchemaError(ValueError):
    """Le document de schéma du fournisseur n'a pas pu être lu, ou ne décrit pas
    le fournisseur demandé."""


def load_provider_schema(path: str | Path, provider_addr: str) -> dict[str, PackResource]:
    """Lit le JSON de schéma généré par terraform et rend la surface
    d'attributs par type de ressource, indexée comme l'est un pack."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise SchemaError(f"reading provider schema: {exc}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"parsing provider schema JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SchemaError("parsing provider schema JSON: top level is not an object")

    schemas = document.get("provider_schemas") or {}
    item = schemas.get(provider_addr)
    if item is None:
        available = ", ".join(sorted(schemas))
        raise SchemaError(f'provider "{provider_addr}" not in schema (found: {available})')

    out: dict[str, PackResource] = {}
    for r_type, r_schema in (item.get("resource_schemas") or {}).items():
        block = (r_schema or {}).get("block")
        if not isinstance(block, dict):
            continue
        res = PackResource()
        _collect_block(block, "", res)

        # Meta-arguments only apply at the resource's top level.
        res.top_level = dedupe([*res.top_level, *META_ARGUMENTS])
        out[r_type] = res
    return out


def _collect_block(b: dict[str, Any], path: str, res: PackResource) -> None:
    """Parcourt récursivement un bloc et ses blocs imbriqués, en enregistrant
    les noms d'arguments valides à chaque chemin pointé.

    Le nom propre d'un bloc imbriqué compte comme un argument valide de son
    parent : HCL autorise à la fois `root_block_device { ... }` (syntaxe de bloc)
    et, pour certains modes d'imbrication, `root_block_device = [...]` (syntaxe
    d'attribut). Traiter le nom comme valide dans les deux positions évite de
    signaler une écriture légale.
    """
    attributes = b.get("attributes") or {}
    block_types = b.get("block_types") or {}
    names = [*attributes.keys(), *block_types.keys()]

    if path == "":
        res.top_level.extend(names)
    else:
        res.nested_blocks[path] = names

    for name, bt in block_types.items():
        child_block = (bt or {}).get("block")
        if not isinstance(child_block, dict):
            continue
        child = name if path == "" else path + "." + name
        _collect_block(child_block, child, res)


def dedupe(items: list[str]) -> list[str]:
    """Déduplication où la première occurrence l'emporte, en préservant
    l'ordre."""
    seen: set[str] = set()
    out: list[str] = []
    for v in items:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
