"""Le mécanisme de suppression à trois niveaux.

Port de internal/ignore/ignore.go et pathrules.go.

 1. Commentaire en ligne, sur la ligne de la découverte ou juste au-dessus :
    `# tf-firewall-ignore: unknown_attribute,tutorial_pattern`
 2. Liste globale dans config.yml (`ignore_rules`), qui supprime une catégorie
    dans tous les fichiers.
 3. Motifs de chemin (`ignore_paths`), qui suppriment un fichier ou une
    arborescence entière, éventuellement restreints à certaines catégories.

**Tout ce qui fait disparaître une découverte mérite une relecture** : le succès
et l'échec s'y ressemblent, un motif trop large étouffant un arbre entier sans
rien signaler.
"""

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
    """Parcourt une source .tf brute et rend, par numéro de ligne (indexé à 1),
    l'ensemble des catégories supprimées sur cette ligne.

    Une directive en ligne N supprime les découvertes de la ligne N *et* de la
    ligne N+1, pour que le commentaire puisse se placer sur la ligne de
    l'attribut elle-même ou juste au-dessus.

    Les catégories restent de simples chaînes plutôt que des valeurs
    `Category` : une directive nommant une catégorie inexistante doit
    simplement ne rien détecter, comme en Go, au lieu de lever une erreur sur un
    membre d'énumération inconnu et de faire tomber tout le scan pour une faute
    de frappe dans le commentaire de quelqu'un.
    """
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
    for f in findings:
        if str(f.category) in global_set:
            continue
        line_map = inline_by_file.get(f.file, {}).get(f.line)
        if line_map is not None and (_ALL in line_map or str(f.category) in line_map):
            continue
        out.append(f)
    return out


@dataclass(slots=True)
class PathRule:
    """Supprime les découvertes dans les fichiers correspondant à `pattern` —
    un motif acceptant `**` (n'importe quel nombre de segments de chemin, zéro
    compris) en plus des `*` et `?` habituels sur un seul segment.

    C'est le pendant à grande échelle des deux mécanismes qui existaient déjà :
    un commentaire en ligne ignore une ligne, la liste globale ignore une
    catégorie partout, mais ni l'un ni l'autre ne pouvait dire « ne scanne pas
    legacy/** du tout » sans parsemer de commentaires chaque fichier de cette
    arborescence.

    `categories`, s'il est non vide, restreint la suppression à ces seules
    catégories sous le chemin correspondant ; vide signifie « ignorer toutes les
    catégories sous ce chemin ».
    """

    pattern: str
    #: `Category | str`, parce qu'une catégorie peut être le « custom:<id> »
    #: d'une règle personnalisée, et parce que le fichier de configuration d'où
    #: elle vient est du texte libre.
    categories: list[Category | str] = field(default_factory=list)

    def suppresses(self, category: Category | str) -> bool:
        """Dit si cette règle couvre `category`.

        Accepte une chaîne nue autant qu'une `Category`, parce que le
        `custom:<id>` d'une règle personnalisée n'est pas un membre de
        l'énumération intégrée — et qu'une règle de chemin qui le nomme doit
        pouvoir le supprimer.
        """
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
    """Retire les découvertes sous un chemin correspondant à une règle, dans la
    limite des catégories de cette règle.

    Appliqué en passe finale sur l'ensemble complet des découvertes — phase 1,
    phase 2 et règles personnalisées réunies : une suppression par chemin ne se
    soucie pas du moteur qui a produit une découverte, seulement de l'endroit
    où elle se trouve.
    """
    if not rules:
        return list(findings)

    out: list[Finding] = []
    for f in findings:
        # posixpath et non os.path : les chemins viennent de git, qui parle en
        # barres obliques sur toutes les plateformes, et les motifs de config.yml
        # sont écrits de la même façon. Normaliser avec le séparateur de l'hôte
        # empêcherait `legacy/**` de correspondre sous Windows.
        clean = posixpath.normpath(f.file)
        if any(r.suppresses(f.category) and glob_to_regexp(r.pattern).search(clean) for r in rules):
            continue
        out.append(f)
    return out
