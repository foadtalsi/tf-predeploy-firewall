"""Le vocabulaire de prédicats qu'un fichier de règles peut invoquer.

Port de internal/rules/predicates.go.

C'est ici la frontière entre les données et le code. Une règle déclare *ce
qu'*elle cherche ; quand décider demande plus qu'un motif — mesurer le hasard,
distinguer une sortie base64 d'un chemin de fichier — elle nomme l'un de ces
prédicats, et ces deux tables sont la liste complète de ce qu'un nom peut
atteindre. Il n'y a ni crochet d'enregistrement ni chemin de greffon, donc
l'ensemble des choses qu'une règle peut faire arriver est exactement ce qui est
écrit ici, et auditable sur un écran.
"""

from __future__ import annotations

from collections.abc import Callable

from .entropy import looks_like_secret, shannon_entropy


def looks_like_base64_secret(match: str) -> bool:
    """Dit si une suite base64 de 40 caractères est plausiblement une sortie
    aléatoire plutôt qu'un chemin ou un identifiant.

    Deux conditions, toutes deux peu coûteuses et toutes deux nécessaires. Le
    secret d'exemple canonique d'AWS
    (wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) passe les deux confortablement ;
    la commande de build qui avait été un jour rapportée comme une clé fuitée
    n'en passe aucune.
    """
    has_upper = has_lower = has_digit = False
    for r in match:
        if "A" <= r <= "Z":
            has_upper = True
        elif "a" <= r <= "z":
            has_lower = True
        elif "0" <= r <= "9":
            has_digit = True
    if not (has_upper and has_lower and has_digit):
        return False
    return shannon_entropy(match) >= 4.2


def _hex_entropy(m: str) -> bool:
    return shannon_entropy(m) >= 3.0


#: Run against the substring a rule's `value_matches` found, not the whole
#: value: the point is to judge the candidate the regex picked out. This is
#: what separates a 40-character secret from a 40-character path.
CONFIRM_PREDICATES: dict[str, Callable[[str], bool]] = {
    # Mixed case with digits is what base64 of random bytes looks like and what
    # a lowercase file path never is; the entropy floor then rejects the
    # structured strings that happen to mix case anyway.
    "base64_secret": looks_like_base64_secret,
    # Hex tops out at 4 bits per character, so this floor is low by design — it
    # exists to reject the degenerate runs (forty a's) that satisfy a hex
    # character class while carrying no randomness at all.
    "hex_entropy": _hex_entropy,
}

#: Run against the whole value and return a measurement the message can quote
#: back. A rule that accuses someone on a statistic has to be able to show the
#: statistic.
VALUE_PREDICATES: dict[str, Callable[[str], tuple[float, bool]]] = {
    "looks_like_secret": looks_like_secret,
}


def known_predicates() -> tuple[list[str], list[str]]:
    """Chaque nom qu'un fichier de règles peut employer, pour la passe de
    validation qui tourne au chargement.

    Une règle nommant un prédicat que cette version n'a pas doit échouer
    bruyamment : le sauter en silence désactiverait un détecteur pendant que le
    scan continuerait de rapporter un succès.
    """
    return sorted(CONFIRM_PREDICATES), sorted(VALUE_PREDICATES)
