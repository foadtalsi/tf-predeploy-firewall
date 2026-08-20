"""Construit les packs de règles du scanner depuis les sources du fournisseur,
au lieu de listes curées à la main.

Port de cmd/genpack/main.go.

    # 1. la surface d'attributs complète, depuis le fournisseur
    mkdir -p /tmp/awsschema && cd /tmp/awsschema
    cat > main.tf <<'EOF'
    terraform { required_providers { aws = { source = "hashicorp/aws", version = "~> 6.0" } } }
    EOF
    terraform init && terraform providers schema -json > schema.json

    # 2. les drapeaux ForceNew, absents de ce JSON — voir forcenew.py
    # 3. construire les deux packs
    tfpdf-genpack \
      --provider-schema  /tmp/awsschema/schema.json \
      --force-new-index  /tmp/aws_forcenew.json \
      --provider-version 6.18.0

Le pack de base est livré avec le scanner, le pack complet est servi aux
organisations sous licence. Les deux sont découpés dans les mêmes données, donc
gratuit et payant ne peuvent jamais diverger sur un même type de ressource.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .forcenew import ForceNewIndex, apply_force_new, load_force_new_index
from .pack import PACK_FORMAT_VERSION, Pack, PackPricing, PackResource
from .schemajson import SchemaError, load_provider_schema


class GenpackError(RuntimeError):
    """La génération a échoué. Toujours fatale : un pack à moitié généré est un
    scanner qui cesse silencieusement de reconnaître des arguments."""


def _log(msg: str) -> None:
    print(msg)


def _warn(msg: str) -> None:
    print("genpack: " + msg, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfpdf-genpack", description=__doc__)
    p.add_argument(
        "--provider",
        default="aws",
        help="provider short name (aws, azurerm) — names the pack, and defaults the "
        "address, curated-file and output paths",
    )
    p.add_argument(
        "--provider-schema",
        default="",
        help="path to `terraform providers schema -json` output (required)",
    )
    p.add_argument(
        "--force-new-index",
        default="",
        help="path to a ForceNew index JSON (optional but strongly recommended — "
        "without it the packs carry no destroy/recreate data at all)",
    )
    p.add_argument(
        "--provider-address",
        default="",
        help="provider address inside the schema JSON "
        "(default registry.terraform.io/hashicorp/<provider>)",
    )
    p.add_argument(
        "--provider-version",
        default="",
        help="provider version these packs describe, recorded in the pack (required)",
    )
    p.add_argument(
        "--curated-dir",
        default="",
        help="directory holding the hand-curated overlays "
        "(default <schema>/curated/<provider>; aws keeps its historical flat layout)",
    )
    p.add_argument(
        "--base-out",
        default="",
        help="output path for the free base pack that ships with the scanner",
    )
    p.add_argument(
        "--full-out",
        default="",
        help="output path for the full pack served by the control plane",
    )
    return p


def _default_curated_dir(provider: str) -> Path:
    """Où vivent les surcouches curées, relativement au paquet installé.

    Go les résout depuis la racine du dépôt parce qu'il tourne depuis un
    checkout ; la version Python les livre à l'intérieur de `tfpdf.schema`, donc
    le défaut doit suivre le paquet plutôt que le répertoire courant.
    """
    root = Path(__file__).resolve().parent.parent / "schema" / "curated"
    # aws keeps its historical flat layout.
    return root if provider == "aws" else root / provider


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.provider_schema or not args.provider_version:
        build_parser().print_usage(sys.stderr)
        return 2

    # Everything defaults from the provider name so generating a second
    # provider's packs is one flag, not five paths kept consistent by hand.
    provider_addr = args.provider_address or "registry.terraform.io/hashicorp/" + args.provider
    curated_dir = (
        Path(args.curated_dir) if args.curated_dir else _default_curated_dir(args.provider)
    )
    base_out = args.base_out or f"pack_{args.provider}_base.json.gz"
    full_out = args.full_out or f"dist/pack_{args.provider}_full.json.gz"

    try:
        run(
            provider=args.provider,
            schema_path=args.provider_schema,
            force_new_index_path=args.force_new_index,
            provider_addr=provider_addr,
            provider_ver=args.provider_version,
            curated_dir=curated_dir,
            base_out=base_out,
            full_out=full_out,
        )
    except (GenpackError, SchemaError, ValueError, OSError) as exc:
        _warn(str(exc))
        return 1
    return 0


def build_packs(
    provider: str,
    resources: dict[str, PackResource],
    provider_ver: str,
    curated_dir: Path,
    idx: ForceNewIndex | None = None,
) -> tuple[Pack, Pack]:
    """La génération elle-même, sans aucune écriture de fichier — `(base,
    complet)`.

    Séparée de `run` pour que toute la chaîne puisse être exercée contre une
    fixture dans un test, et pas seulement par une ligne de commande.
    """
    if idx is not None:
        apply_force_new(resources, idx)
        covered = sum(1 for r in resources.values() if r.force_new_top_level or r.force_new_nested)
        _log(
            f"ForceNew: SDKv2 {idx.stats.sdk_resources_resolved}/"
            f"{idx.stats.sdk_resources_seen} resolved, Framework "
            f"{idx.stats.framework_resolved}/{idx.stats.framework_seen} resolved, "
            f"{covered} resource types carry ForceNew data"
        )
    else:
        _log("ForceNew: skipped (--force-new-index not given)")

    # --- curated overlays -------------------------------------------------
    critical = read_string_list(curated_dir / "critical_stateful_resources.json", "resource_types")
    unknown_critical = 0
    for t in critical:
        r = resources.get(t)
        if r is None:
            # A curated type the provider no longer ships: worth knowing about,
            # since the curated list is the one thing still written by hand.
            _warn(f'curated critical type "{t}" is not in the provider schema')
            unknown_critical += 1
            continue
        r.critical = True
    _log(
        f"critical stateful: {len(critical) - unknown_critical} types "
        f"({unknown_critical} unmatched)"
    )

    pricing = read_pricing(curated_dir / f"{provider}_pricing.json")
    for t, p in pricing.items():
        if (r := resources.get(t)) is not None:
            r.pricing = p
    _log(f"pricing: {len(pricing)} types")

    full = Pack(
        format_version=PACK_FORMAT_VERSION,
        id=provider + "-full",
        provider=provider,
        provider_version=provider_ver,
        resources=resources,
    )
    base_types = sorted(read_string_list(curated_dir / "base_pack_types.json", "resource_types"))
    return full.subset(provider + "-base", base_types), full


def run(
    provider: str,
    schema_path: str,
    force_new_index_path: str,
    provider_addr: str,
    provider_ver: str,
    curated_dir: Path,
    base_out: str,
    full_out: str,
) -> None:
    resources = load_provider_schema(schema_path, provider_addr)
    _log(f"attribute surface: {len(resources)} resource types")

    idx = load_force_new_index(force_new_index_path) if force_new_index_path else None
    base, full = build_packs(provider, resources, provider_ver, curated_dir, idx)

    for path in (base_out, full_out):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    base.write_gzip_json(base_out)
    full.write_gzip_json(full_out)

    for label, pack, path in (("base", base, base_out), ("full", full, full_out)):
        size_kb = Path(path).stat().st_size / 1024
        _log(f"wrote {path} ({len(pack.resources)} types, {size_kb:.0f} KB) [{label}]")


def read_string_list(path: str | Path, field_name: str) -> list[str]:
    doc = _read_json_object(path)
    value = doc.get(field_name)
    if not isinstance(value, list):
        raise GenpackError(f'parsing {path} field "{field_name}": not a list')
    return [str(v) for v in value]


def read_pricing(path: str | Path) -> dict[str, PackPricing]:
    doc = _read_json_object(path)
    out: dict[str, PackPricing] = {}
    for k, v in doc.items():
        if k == "_comment":
            continue
        if not isinstance(v, dict):
            raise GenpackError(f"parsing pricing for {k}: not an object")
        out[k] = PackPricing.from_json(v)
    return out


def _read_json_object(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise GenpackError(str(exc)) from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GenpackError(f"parsing {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise GenpackError(f"parsing {path}: top level is not an object")
    return doc


def run_cli() -> None:
    """Point d'entrée du script de console."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run_cli()
