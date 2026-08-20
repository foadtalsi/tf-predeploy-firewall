"""Rend les commentaires de revue en ligne, et le marqueur qui empêche une
nouvelle exécution de les poster deux fois.

Port de internal/report/review.go.

**Seul endroit du port qui diverge de Go, et c'est délibéré.** Là-bas,
`ReviewCommentBody` et `GitLabSuggestionBody` déréférencent `f.Fix` sans
vérification et paniquent sur une découverte sans correctif — le cas normal pour
la plupart. En production rien ne les atteint : `postSuggestions` écarte
`f.Fix == nil` d'abord. Mais `Fix.Text()` est explicitement protégé, donc un
correctif absent devait se rendre comme une suggestion vide.

Cette version rend cela. Ajouter la panique reviendrait à faire tomber le code
qui poste les commentaires de PR, emportant le commentaire de synthèse avec lui.
`test_review_nil_fix.py` épingle le choix. À corriger côté Go aussi.
"""

from __future__ import annotations

import hashlib

from .finding import Finding
from .markdown import SEVERITY_EMOJI
from .ruledocs import category_display

#: Ouvre le commentaire HTML caché estampillé sur chaque suggestion en ligne.
#: C'est ainsi qu'une nouvelle exécution reconnaît une suggestion déjà postée :
#: contrairement au commentaire de synthèse, les commentaires de revue ne
#: peuvent pas être mis à jour d'un bloc, donc le seul moyen d'éviter un mur de
#: doublons au troisième push est de regarder ce qui est déjà là et de le
#: sauter.
FIX_MARKER_PREFIX = "<!-- tf-predeploy-firewall:fix:"


def fix_marker(f: Finding) -> str:
    """L'identité d'une suggestion, stable d'un push à l'autre.

    Elle hache ce que la suggestion *dit* — catégorie, ressource, fichier et
    texte de remplacement de la découverte — et délibérément pas la ligne sur
    laquelle elle se pose. Un rebase ou une modification au-dessus décale
    toutes les lignes en dessous ; se baser sur le numéro de ligne reposterait
    la même suggestion après n'importe quelle édition sans rapport, ce qui est
    exactement le bruit qui fait couper le son d'un bot.
    """
    text = f.fix.text() if f.fix is not None else ""
    joined = "\x00".join([str(f.category), f.resource, f.file, text])
    digest = hashlib.sha256(joined.encode()).hexdigest()
    return FIX_MARKER_PREFIX + digest[:16] + " -->"


def has_fix_marker(comment_body: str, f: Finding) -> bool:
    """Dit si le corps d'un commentaire de revue existant a été produit pour la
    même découverte, autrement dit si reposter `f` serait un doublon."""
    return fix_marker(f) in comment_body


def review_comment_body(f: Finding) -> str:
    """Rend une découverte comme corps d'un commentaire de revue en ligne, avec
    son correctif dans un bloc ```suggestion de GitHub, pour que l'auteur
    puisse l'appliquer d'un clic sur « Commit suggestion ».

    La sévérité et la catégorie sont répétées ici plutôt que laissées au
    commentaire de synthèse : un commentaire en ligne est lu là où il tombe,
    dans le diff, par quelqu'un qui ne descendra peut-être jamais jusqu'au
    tableau.
    """
    # Le bloc de GitHub remplace exactement la plage de lignes ancrée par le
    # commentaire, donc l'en-tête simple ne porte pas de plage à lui.
    return _suggestion_body(f, "```suggestion")


def gitlab_suggestion_body(f: Finding) -> str:
    """`review_comment_body` dans la grammaire de bloc de GitLab.

    GitLab ancre un commentaire en ligne sur une seule ligne et exprime la
    plage remplacée dans le bloc lui-même : ```suggestion:-0+2 remplace la ligne
    ancrée plus les deux suivantes. Le commentaire est ancré sur la première
    ligne du correctif, donc le décalage est simplement la hauteur de la plage.
    """
    height = f.fix.end_line - f.fix.start_line if f.fix is not None else 0
    return _suggestion_body(f, f"```suggestion:-0+{height}")


def _suggestion_body(f: Finding, fence_header: str) -> str:
    b: list[str] = []

    b.append(
        f"**{SEVERITY_EMOJI.get(f.severity, '')} {f.severity} — "
        f"{category_display(f.category)}**\n\n"
    )
    b.append(f.message + "\n\n")

    b.append(fence_header + "\n")
    # Les trois lectures de `f.fix` de cette fonction sont protégées, là où Go
    # paniquerait — voir la docstring du module.
    text = f.fix.text() if f.fix is not None else ""
    if text:
        b.append(text + "\n")
    b.append("```\n")

    if f.fix is not None and f.fix.note:
        b.append("\n" + f.fix.note + "\n")
    if f.doc_url:
        b.append(f"\n📖 [Provider documentation for `{f.resource}`]({f.doc_url})\n")

    b.append("\n" + fix_marker(f) + "\n")
    return "".join(b)
