"""Aides pour construire des valeurs `report.Fix` — des remplacements assez
exacts pour que le bouton « Commit suggestion » de GitHub les écrive dans la
branche sans que personne ne les relise.

Port de internal/rules/fix.go et des aides de nommage de
internal/rules/rule_tutorial_pattern.go.

Tout ici est conservateur à dessein. Chaque aide rend `None` dès que la source
ne ressemble pas à ce qu'elle supposait, et l'appelant émet alors la découverte
avec sa seule suggestion en langage humain. Rater un correctif en un clic coûte
un clic ; en produire un faux commet du HCL cassé.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..hcl import Range
from ..parser import Attribute, Resource

_NON_IDENT_CHAR = re.compile(r"[^a-zA-Z0-9_]")


@dataclass(slots=True, frozen=True)
class LineEdit:
    """Un remplacement résolu : quelles lignes, et ce qu'elles deviennent."""

    start: int
    end: int
    lines: list[str]


def line_text(src: bytes, n: int) -> str | None:
    """La ligne `n` (indexée à 1) de `src`, sans sa fin de ligne.

    None si `src` est absente ou si `n` est hors plage — le cas normal pour les
    appelants qui n'ont jamais fourni la source, par exemple des tests
    unitaires qui construisent un FileInput à la main.
    """
    if not src or n < 1:
        return None
    lines = src.decode("utf-8", errors="replace").split("\n")
    if n > len(lines):
        return None
    return lines[n - 1].removesuffix("\r")


def indent_of(s: str) -> str:
    """L'espacement de tête de `s`, pour qu'une ligne générée s'aligne sur le
    code qui l'entoure. Les tabulations sont conservées comme tabulations."""
    return s[: len(s) - len(s.lstrip(" \t"))]


def opens_block(line: str) -> bool:
    """Dit si une ligne est un en-tête de bloc auquel on peut ajouter du contenu
    sans risque, c'est-à-dire qu'elle se termine par `{` et a donc un corps qui
    commence à la ligne suivante.

    Un bloc sur une seule ligne (`lifecycle { prevent_destroy = false }`) échoue
    à ce test, et c'est le but : ajouter une ligne après lui placerait le
    nouveau contenu hors des accolades.
    """
    return line.rstrip(" \t").endswith("{")


def declares_attr(line: str, name: str) -> bool:
    """Dit si `line` est la déclaration de l'attribut `name` — `name = …`,
    éventuellement indentée.

    Sert à confirmer que la ligne visée par une plage est bien l'affectation
    d'une ligne que l'on entend écraser, et non un bloc sur une ligne qui se
    trouve la contenir.
    """
    rest = line.lstrip(" \t")
    if not rest.startswith(name):
        return False
    return rest[len(name) :].lstrip(" \t").startswith("=")


def insert_into_block(src: bytes, header: Range, *add: str) -> LineEdit | None:
    """Construit un correctif qui garde la ligne d'en-tête d'un bloc telle
    quelle et ajoute des lignes juste en dessous, indentées d'un niveau.

    Réécrire l'en-tête à l'identique plutôt que de le régénérer est délibéré :
    il peut porter un commentaire de fin de ligne, un espacement inhabituel ou
    des méta-arguments `for_each` que cet outil n'a pas à normaliser.
    """
    line_no = header.start.line
    text = line_text(src, line_no)
    if text is None or not opens_block(text):
        return None
    inner = indent_of(text) + "  "
    out = [text, *(inner + a for a in add)]
    return LineEdit(start=line_no, end=line_no, lines=out)


def replace_attr_line(src: bytes, r: Range, attr_name: str, new_text: str) -> LineEdit | None:
    """Construit un correctif qui écrase une affectation d'attribut sur une
    ligne par `new_text`, en conservant l'indentation d'origine."""
    if r.start.line != r.end.line:
        return None  # a multi-line value; not ours to rewrite
    text = line_text(src, r.start.line)
    if text is None or not declares_attr(text, attr_name):
        return None
    return LineEdit(start=r.start.line, end=r.start.line, lines=[indent_of(text) + new_text])


# --- naming helpers -------------------------------------------------------


def via_suffix(attr: Attribute) -> str:
    """Nomme la référence par laquelle une valeur a été atteinte, pour qu'une
    découverte rapportée sur une ligne qui ne lit que `password =
    var.db_password` dise où se trouve réellement le littéral.

    Sans cela, le rapport ressemble à un faux positif pour quiconque ouvre le
    fichier.
    """
    if not attr.resolved_from:
        return ""
    return " (via " + attr.resolved_from + ")"


def credential_var_name(res: Resource, block_type: str, attr_name: str) -> str:
    """Un identifiant HCL valide et raisonnablement unique pour la variable
    qu'un correctif propose — nom de la ressource plus nom de l'attribut,
    puisque le même nom d'attribut (`password`) revient d'une ressource à
    l'autre dans un même fichier.

    `block_type` est le bloc imbriqué dans lequel l'attribut se trouve, et
    rejoint le nom quand il y en a un : une ressource peut contenir deux blocs
    déclarant le même attribut, et proposer la même variable pour les deux
    ferait discrètement écraser le sens du premier correctif par le second.
    """
    name = sanitize_ident(res.name)
    if block_type:
        name += "_" + sanitize_ident(block_type)
    return name + "_" + sanitize_ident(attr_name)


def sanitize_ident(s: str) -> str:
    return _NON_IDENT_CHAR.sub("_", s.lower())
