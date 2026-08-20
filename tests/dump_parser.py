"""Sérialise ce que produit tfpdf.parser, dans la forme exacte qu'émet
core/cmd/parserdump depuis l'implémentation Go.

Les deux sorties sont comparées octet pour octet par test_parser_parity.py.
Garder la forme en un seul endroit fait qu'un champ ajouté au modèle est
comparé, plutôt que d'échapper silencieusement à la vérification de parité.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tfpdf.hcl import HCLParseError
from tfpdf.parser import build_scope, parse_file_with_context
from tfpdf.parser.model import Attribute, Resource


def dump_attrs(m: dict[str, Attribute]) -> list[dict[str, object]]:
    out = []
    for name in sorted(m):
        a = m[name]
        out.append(
            {
                "name": a.name,
                "raw_value": a.raw_value,
                "is_literal": a.is_literal,
                "resolved_from": a.resolved_from,
                "start_line": a.range.start.line,
                "start_col": a.range.start.column,
                "start_byte": a.range.start.byte,
                "end_line": a.range.end.line,
                "end_col": a.range.end.column,
                "end_byte": a.range.end.byte,
            }
        )
    return out


def dump_resource(r: Resource) -> dict[str, object]:
    return {
        "kind": r.kind.value,
        "type": r.type,
        "name": r.name,
        "address": r.address(),
        "file": r.file,
        "def_start_line": r.def_range.start.line,
        "def_start_col": r.def_range.start.column,
        "def_start_byte": r.def_range.start.byte,
        "def_end_line": r.def_range.end.line,
        "def_end_byte": r.def_range.end.byte,
        "attributes": dump_attrs(r.attributes),
        "blocks": [
            {
                "type": b.type,
                "labels": b.labels,
                "start_line": b.range.start.line,
                "attributes": dump_attrs(b.attributes),
            }
            for b in r.blocks
        ],
        "has_lifecycle_block": r.has_lifecycle_block,
        "prevent_destroy_value": r.prevent_destroy_value,
        "prevent_destroy_line": r.prevent_destroy_range.start.line,
        "lifecycle_line": r.lifecycle_range.start.line,
    }


def dump_files(paths: list[Path]) -> list[dict[str, object]]:
    # Group by directory so scope resolution matches how the scanner builds it:
    # locals and variable defaults are visible across one directory.
    by_dir: dict[Path, dict[str, bytes]] = {}
    for p in paths:
        by_dir.setdefault(p.parent, {})[str(p)] = p.read_bytes()

    out: list[dict[str, object]] = []
    for p in paths:
        context = build_scope(by_dir[p.parent])
        source = by_dir[p.parent][str(p)]
        entry: dict[str, object] = {"file": p.name, "parse_error": "", "resources": []}
        try:
            resources = parse_file_with_context(p.name, source, context)
        except HCLParseError as exc:
            entry["parse_error"] = str(exc)
            out.append(entry)
            continue
        entry["resources"] = [dump_resource(r) for r in resources]
        out.append(entry)
    return out


if __name__ == "__main__":
    files = [Path(a) for a in sys.argv[1:]]
    json.dump(dump_files(files), sys.stdout, indent=2)
    sys.stdout.write("\n")
