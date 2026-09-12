"""Le mécanisme de suppression à trois niveaux."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from .report.finding import Category, Finding

DIRECTIVE_PREFIX = "tf-firewall-ignore:"

#: La pseudo-catégorie qui supprime toutes les catégories d'une ligne.
_ALL = "all"


def parse_comments(source: bytes) -> dict[int, set[str]]:
    """Parcourt une source .tf brute et rend, par numéro de ligne (indexé à 1), l'ensemble des
    catégories supprimées sur cette ligne."""
    out: dict[int, set[str]] = {}
    text = source.decode("utf-8", errors="replace")
    for line_num, line in enumerate(text.split("\n"), start=1):
        index = line.find("#")
        if index < 0:
            continue
        comment = line[index + 1 :].strip()
        if not comment.startswith(DIRECTIVE_PREFIX):
            continue
        cats = _parse_category_list(comment[len(DIRECTIVE_PREFIX) :])
        # Supprime sur cette ligne et la suivante (directive au-dessus de
        # l'attribut).
        for n in (line_num, line_num + 1):
            out.setdefault(n, set()).update(cats)
    return out


def _parse_category_list(s: str) -> list[str]:
    return [part.strip() for part in s.split(",") if part.strip()]


def apply(
    findings: Iterable[Finding],
    inline_by_file: dict[str, dict[int, set[str]]],
    global_ignore: Sequence[Category | str],
) -> list[Finding]:
    """Retire les découvertes supprimées soit par une directive en ligne dans
    leur fichier source, soit par la liste globale d'exclusion."""
    global_set = {str(c) for c in global_ignore}

    out: list[Finding] = []
    for finding in findings:
        if str(finding.category) in global_set:
            continue
        line_map = inline_by_file.get(finding.file, {}).get(finding.line)
        if line_map is not None and (_ALL in line_map or str(finding.category) in line_map):
            continue
        out.append(finding)
    return out


@dataclass(slots=True)
class PathRule:
    """Supprime les découvertes dans les fichiers correspondant à `pattern` — un motif acceptant
    `**` (n'importe quel nombre de segments de chemin, zéro compris) en plus des `*` et `?`
    habituels sur un seul segment."""

    pattern: str
    #: `Category | str`, parce qu'une catégorie peut être le « custom:<id> »
    #: d'une règle personnalisée, et parce que le fichier de configuration d'où
    #: elle vient est du texte libre.
    categories: list[Category | str] = field(default_factory=list)

    def suppresses(self, category: Category | str) -> bool:
        """Dit si cette règle couvre `category`."""
        if not self.categories:
            return True
        return any(str(c) == str(category) for c in self.categories)


@lru_cache(maxsize=256)
def glob_to_regexp(pattern: str) -> re.Pattern[str]:
    """Compile un motif de chemin (avec `**`) en expression régulière ancrée.

    Mis en cache : les motifs viennent de config.yml et sont retestés contre
    chaque découverte, ce qui éviterait sinon une recompilation par découverte.
    """
    parts = ["^"]
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    parts.append("$")
    return re.compile("".join(parts))


def apply_path_rules(findings: Sequence[Finding], rules: Sequence[PathRule]) -> list[Finding]:
    """Retire les découvertes sous un chemin correspondant à une règle, dans la limite des
    catégories de cette règle."""
    if not rules:
        return list(findings)

    out: list[Finding] = []
    for finding in findings:
        # posixpath et non os.path : les chemins viennent de git, qui parle en
        # barres obliques sur toutes les plateformes, et les motifs de config.yml
        # sont écrits de la même façon. Normaliser avec le séparateur de l'hôte
        # empêcherait `legacy/**` de correspondre sous Windows.
        clean = posixpath.normpath(finding.file)
        if any(
            r.suppresses(finding.category) and glob_to_regexp(r.pattern).search(clean)
            for r in rules
        ):
            continue
        out.append(finding)
    return out
