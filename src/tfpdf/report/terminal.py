"""Le rapport tel qu'on le lit dans un terminal.

Sans équivalent Go. Le scanner n'a longtemps eu qu'un seul rendu, le Markdown
du commentaire de PR, et le CLI l'imprimait tel quel : un tableau Markdown,
des balises `<details>`, un commentaire HTML de marquage et une URL de
registre complète par ligne. Sur une pull request GitHub le rend joliment ;
dans un terminal, trente-trois découvertes font trois cents lignes de syntaxe
qu'aucun humain ne lit.

Ce module ne remplace pas l'autre, il s'ajoute à côté. Le Markdown reste
exactement ce qu'il était — il est comparé octet pour octet au scanner Go, et
c'est lui qui part dans la PR. Ici on choisit l'inverse de ses contraintes :

- **Groupé par règle, pas par fichier.** Un scan de dépôt entier répète deux
  ou trois motifs sur trente lignes. Lire l'explication une fois puis parcourir
  les emplacements est plus court et plus juste que relire la même phrase neuf
  fois. C'est aussi ce qui rend la sortie utile quand elle grandit.
- **Une ligne par emplacement.** Le message varie à l'intérieur d'un groupe
  (l'attribut, le type de ressource), et ce qui varie est en tête de phrase
  dans toutes les règles du pack — le tronquer à la largeur du terminal garde
  donc la partie utile.
- **Rien qu'on ne puisse copier.** Chaque emplacement s'écrit `fichier:ligne`,
  la forme que les éditeurs et les terminaux savent ouvrir.

Les couleurs suivent `NO_COLOR` (https://no-color.org) et disparaissent dès que
la sortie n'est pas un terminal, pour qu'une redirection vers un fichier ne
récolte pas des séquences d'échappement.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

from .finding import Severity
from .ruledocs import category_display

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .finding import Finding


#: Applique une séquence ANSI à un texte, ou la laisse tomber. Nommé parce
#: qu'il circule entre le rendu, l'en-tête et chaque groupe, et qu'un
#: `Callable[[str, str], str]` répété quatre fois se lit moins bien qu'un nom.
Paint = Callable[[str, str], str]

#: Du plus grave au moins grave. L'ordre d'affichage, et l'ordre dans lequel on
#: veut que quelqu'un qui ne lit que le haut de l'écran voie les choses.
_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

#: En deçà, l'alignement en colonnes coûte plus qu'il ne rapporte.
_MIN_WIDTH = 60


def wants_color(stream: object | None = None) -> bool:
    """Dit si l'on doit émettre des séquences ANSI.

    `NO_COLOR` l'emporte sur tout, quelle que soit sa valeur — c'est la
    convention, et discuter de son contenu revient à ne pas la respecter.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def render_terminal(
    findings: list[Finding],
    threshold: Severity | str,
    blocked: bool,
    *,
    color: bool | None = None,
    width: int | None = None,
) -> str:
    """Le rapport, mis en forme pour un terminal.

    `width` sert aux tests et à un appelant qui connaît mieux sa sortie que
    `shutil.get_terminal_size`, laquelle rend 80 quand elle ne sait pas.
    """
    if color is None:
        color = wants_color()
    if width is None:
        width = max(shutil.get_terminal_size((100, 24)).columns, _MIN_WIDTH)

    paint = _painter(color)
    lines: list[str] = []

    live = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]

    lines.append(_headline(live, threshold, blocked, paint))

    for severity in _ORDER:
        for group in _group_by_rule(f for f in live if f.severity is severity):
            lines.append("")
            lines.extend(_render_group(group, severity, width, paint))

    if waived:
        lines.append("")
        lines.append(paint(_DIM, f"{len(waived)} finding(s) waived, not blocking:"))
        for finding in waived:
            lines.append(paint(_DIM, f"  {finding.file}:{finding.line}  {finding.resource}"))

    if live:
        lines.append("")
        lines.append(paint(_DIM, "Full detail, fixes and doc links: --format markdown"))

    return "\n".join(lines)


def _painter(color: bool) -> Paint:
    if not color:
        return lambda _code, text: text
    return lambda code, text: f"{code}{text}{_RESET}"


def _headline(
    live: list[Finding],
    threshold: Severity | str,
    blocked: bool,
    paint: Paint,
) -> str:
    if not live:
        return paint(_BOLD, "No findings.")

    counts = [
        f"{sum(1 for f in live if f.severity is s)} {s}"
        for s in _ORDER
        if any(f.severity is s for f in live)
    ]
    head = f"{len(live)} finding(s) — " + ", ".join(counts)

    if blocked:
        return paint(_COLOR[Severity.CRITICAL], head + f"  ✗ blocked at {threshold}")
    return paint(_BOLD, head) + paint(_DIM, f"  nothing reaches {threshold}")


def _group_by_rule(findings: Iterable[Finding]) -> list[list[Finding]]:
    """Regroupe par règle, en gardant l'ordre de première apparition.

    La clé est `rule_name` quand elle existe et la catégorie sinon : une
    découverte construite hors du pack n'a pas de nom de règle, et la ranger
    sous « inconnu » avec les autres serait pire que de la ranger par
    catégorie.
    """
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.rule_name or str(finding.category), []).append(finding)
    return list(groups.values())


def _render_group(
    group: list[Finding],
    severity: Severity,
    width: int,
    paint: Paint,
) -> list[str]:
    first = group[0]
    count = f" ({len(group)})" if len(group) > 1 else ""
    # Le nom de règle en plus de la catégorie : deux règles partagent souvent
    # une catégorie — `missing_lifecycle` et `s3_force_destroy` toutes deux
    # sous « Missing prevent_destroy » — et deux groupes au même titre se
    # lisent comme une répétition. C'est aussi le nom qu'on écrit dans
    # `ignore_rules` pour en faire taire un.
    title = category_display(first.category)
    if first.rule_name and first.rule_name != str(first.category):
        title += paint(_DIM, f" · {first.rule_name}")
    lines = [paint(_COLOR[severity], f"{severity}") + f"  {title}{count}"]

    # L'explication une seule fois. C'est ce qui fait tenir un scan de dépôt
    # entier sur un écran : la phrase est la même pour les neuf découvertes
    # d'une règle, et la répéter neuf fois n'apprend rien de plus.
    for line in _wrap(_shared_message(group), width - 2):
        lines.append(paint(_DIM, "  " + line))

    places = [f"{f.file}:{f.line}" for f in group]
    place_column = max(len(p) for p in places)
    resource_column = max(len(f.resource) for f in group)
    details = _what_differs(group)

    for finding, place, detail in zip(group, places, details, strict=True):
        left = f"  {place:<{place_column}}  {finding.resource:<{resource_column}}"
        if not detail:
            lines.append(left.rstrip())
            continue
        room = width - len(left) - 2
        lines.append(
            (left + "  " + paint(_DIM, _fit(detail, room))).rstrip() if room > 8 else left.rstrip()
        )
    return lines


def _shared_message(group: list[Finding]) -> str:
    """Le message du groupe, celui de la première découverte.

    Les règles produisent une phrase par découverte, mais c'est la même phrase
    avec un type ou un attribut différent dedans. En prendre une est donc
    fidèle, et `_what_differs` s'occupe de rendre visible ce qui change.
    """
    return " ".join(group[0].message.split())


def _what_differs(group: list[Finding]) -> list[str]:
    """Ce qui distingue chaque message des autres du même groupe.

    Retire le plus long préfixe et le plus long suffixe communs à tout le
    groupe ; ce qui reste est ce que la ligne doit dire de plus que l'en-tête.

    Les deux bornes reculent jusqu'à une frontière de mot — guillemets
    compris, sinon un préfixe commun d'un seul caractère laisse un `name"`
    orphelin dont il faut deviner qu'il s'ouvrait avant la coupe.

    Rendu vide quand ce qui diffère est déjà visible ailleurs sur la ligne :
    répéter `cloudwatch_log_group` à côté de
    `aws_cloudwatch_log_group.api_lambda` occupe une colonne pour rien.
    """
    if len(group) < 2:
        return [""]

    messages = [" ".join(f.message.split()) for f in group]
    shortest = min(len(m) for m in messages)

    prefix = 0
    while prefix < shortest and len({m[prefix] for m in messages}) == 1:
        prefix += 1
    while prefix > 0 and _inside_a_word(messages[0], prefix):
        prefix -= 1

    suffix = 0
    while suffix < shortest - prefix and len({m[-1 - suffix] for m in messages}) == 1:
        suffix += 1
    while suffix > 0 and _inside_a_word(messages[0], len(messages[0]) - suffix):
        suffix -= 1

    differing = []
    for finding, message in zip(group, messages, strict=True):
        text = message[prefix : len(message) - suffix].strip()
        differing.append("" if text and text in finding.resource else text)

    return _quoted_subjects(differing) or differing


def _quoted_subjects(differing: list[str]) -> list[str] | None:
    """Réduit chaque ligne au terme cité qui l'ouvre, quand toutes en ont un.

    Le pack met entre guillemets le sujet d'une découverte — l'attribut, la
    clé. Quand ce qui distingue les lignes commence par un terme cité, ce
    terme *est* la distinction et le reste de la phrase répète l'en-tête :
    vingt-deux lignes de `"name" is a ForceNew attribute on…` deviennent
    vingt-deux fois `"name"` ou `"hash_key"`.

    Exigé de tout le groupe, et non ligne par ligne : une seule ligne sans
    terme cité rendrait la colonne incomparable d'une ligne à l'autre, ce qui
    est pire qu'une colonne un peu longue. Rend None dans ce cas, et
    l'appelant garde le texte entier.
    """
    subjects = []
    for text in differing:
        if not text.startswith('"'):
            return None
        end = text.find('"', 1)
        if end < 1:
            return None
        subjects.append(text[: end + 1])
    return subjects


def _inside_a_word(text: str, index: int) -> bool:
    """Dit si couper `text` à `index` couperait un mot en deux.

    Le guillemet compte comme faisant partie du mot : le pack cite les noms
    d'attributs, et une coupe entre le guillemet et le nom produit exactement
    le fragment qu'on cherche à éviter.
    """
    if index <= 0 or index >= len(text):
        return False
    return _word_char(text[index - 1]) and _word_char(text[index])


def _word_char(character: str) -> bool:
    return character.isalnum() or character in "_\"'"


def _wrap(text: str, width: int) -> list[str]:
    import textwrap

    return textwrap.wrap(text, max(width, 20)) or [""]


def _fit(message: str, room: int) -> str:
    """Coupe à `room` caractères, sur une frontière de mot quand il y en a une.

    Ce qui distingue deux découvertes d'une même règle est en tête de message
    dans tout le pack — l'attribut concerné, le type de ressource — donc
    tronquer par la fin garde ce qui les sépare.
    """
    message = " ".join(message.split())
    if len(message) <= room:
        return message
    cut = message[: room - 1]
    space = cut.rfind(" ")
    if space > room // 2:
        cut = cut[:space]
    return cut + "…"
