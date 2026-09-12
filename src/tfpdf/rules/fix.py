"""Construit des remplacements exacts de lignes. Retourne None lorsque le code ne permet pas une
édition fiable."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..hcl import Range
from ..parser import Attribute, Resource
from ..report.finding import Fix

_NON_IDENT_CHAR = re.compile(r"[^a-zA-Z0-9_]")


@dataclass(slots=True, frozen=True)
class LineEdit:
    """Un remplacement résolu : quelles lignes, et ce qu'elles deviennent."""

    start: int
    end: int
    lines: list[str]


def line_text(source: bytes, n: int) -> str | None:
    """La ligne `n` (indexée à 1) de `src`, sans sa fin de ligne."""
    if not source or n < 1:
        return None
    lines = source.decode("utf-8", errors="replace").split("\n")
    if n > len(lines):
        return None
    return lines[n - 1].removesuffix("\r")


def indent_of(s: str) -> str:
    """L'espacement de tête de `s`, pour qu'une ligne générée s'aligne sur le
    code qui l'entoure. Les tabulations sont conservées comme tabulations."""
    return s[: len(s) - len(s.lstrip(" \t"))]


def opens_block(line: str) -> bool:
    """Vérifie qu'une ligne ouvre un bloc dont le corps commence sur la ligne suivante."""
    return line.rstrip(" \t").endswith("{")


def declares_attr(line: str, name: str) -> bool:
    """Dit si `line` est la déclaration de l'attribut `name` — `name = …`, éventuellement
    indentée."""
    rest = line.lstrip(" \t")
    if not rest.startswith(name):
        return False
    return rest[len(name) :].lstrip(" \t").startswith("=")


def insert_into_block(source: bytes, header: Range, *add: str) -> LineEdit | None:
    """Conserve l'en-tête exact du bloc et insère les lignes en les indentant d'un niveau."""
    line_no = header.start.line
    text = line_text(source, line_no)
    if text is None or not opens_block(text):
        return None
    inner = indent_of(text) + "  "
    out = [text, *(inner + a for a in add)]
    return LineEdit(start=line_no, end=line_no, lines=out)


def replace_attr_line(source: bytes, r: Range, attr_name: str, new_text: str) -> LineEdit | None:
    """Construit un correctif qui écrase une affectation d'attribut sur une
    ligne par `new_text`, en conservant l'indentation d'origine."""
    if r.start.line != r.end.line:
        return None  # a multi-line value; not ours to rewrite
    text = line_text(source, r.start.line)
    if text is None or not declares_attr(text, attr_name):
        return None
    return LineEdit(start=r.start.line, end=r.start.line, lines=[indent_of(text) + new_text])


# --- naming helpers -------------------------------------------------------


def via_suffix(attribute: Attribute) -> str:
    """Nomme la référence par laquelle une valeur a été atteinte, pour qu'une découverte
    rapportée sur une ligne qui ne lit que `password = var.db_password` dise où se trouve
    réellement le littéral."""
    if not attribute.resolved_from:
        return ""
    return " (via " + attribute.resolved_from + ")"


def credential_var_name(res: Resource, block_type: str, attr_name: str) -> str:
    """Nomme une variable à partir de la ressource, du bloc imbriqué et de l'attribut pour éviter
    les collisions."""
    name = sanitize_ident(res.name)
    if block_type:
        name += "_" + sanitize_ident(block_type)
    return name + "_" + sanitize_ident(attr_name)


def sanitize_ident(s: str) -> str:
    return _NON_IDENT_CHAR.sub("_", s.lower())


def as_fix(edit: LineEdit | None) -> Fix | None:
    """Élève une édition de ligne résolue en Fix, en laissant passer None."""
    if edit is None:
        return None
    return Fix(start_line=edit.start, end_line=edit.end, lines=edit.lines)
