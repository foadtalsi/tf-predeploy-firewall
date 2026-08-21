"""Positions et plages dans la source.

Chaque nœud que ce paquet produit porte le décalage en octets, la ligne et la
colonne d'où il vient. Ce n'est pas de la comptabilité accessoire : toute la
surface de sortie du scanner est positionnelle. Une découverte sans numéro de
ligne ne peut devenir ni un commentaire de PR sur la bonne ligne, ni une région
SARIF, ni un bloc `suggestion` en ligne, ni une correspondance
`# tf-firewall-ignore:`. C'est la raison pour laquelle l'analyseur est écrit ici
plutôt que délégué à une bibliothèque HCL qui rend des dictionnaires.

Les décalages sont des décalages en **octets** dans la source UTF-8, comme ce
qu'enregistre hashicorp/hcl, pour qu'une plage puisse redécouper les octets
d'origine (voir `rules.iam_wildcard`, qui fait sa recherche sur le texte brut
d'un attribut que l'évaluateur n'a pas su résoudre). Les colonnes sont comptées
en points de code Unicode, là encore comme hcl, pour qu'une colonne se lise
comme une colonne humaine et non comme un indice d'octet dans une ligne
multi-octets.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True, order=True)
class Pos:
    """Un point unique dans un fichier source.

    `line` et `column` sont indexés à 1 et `byte` à 0, comme hcl.Pos.

    Les valeurs par défaut des champs valent toutes **zéro**, ce qui n'est pas
    une position valide, et c'est le but : un Pos construit par défaut signifie
    « aucune position enregistrée », exactement ce que signifie le `hcl.Pos` à
    valeur nulle de Go. `Resource.lifecycle_range` sur une ressource sans bloc
    lifecycle rapporte la ligne 0 dans les deux implémentations, si bien qu'un
    appelant testant `if r.lifecycle_range.start.line:` se comporte à
    l'identique. Choisir la ligne 1 par défaut ferait prétendre à chaque plage
    absente qu'elle pointe sur la première ligne du fichier.
    """

    line: int = 0
    column: int = 0
    byte: int = 0

    def __str__(self) -> str:
        return f"{self.line},{self.column}"


#: The "no position recorded" zero value, matching Go's zero `hcl.Pos`.
ZERO_POS = Pos()

#: The position a file starts at. Mirrors `hcl.InitialPos`, which the Go code
#: passes to every ParseConfig call.
INITIAL_POS = Pos(line=1, column=1, byte=0)


@dataclass(frozen=True, slots=True)
class Range:
    """Une étendue semi-ouverte [début, fin) d'un fichier source."""

    filename: str = ""
    #: A default-constructed Range is the "no position" zero value, matching
    #: Go's zero `hcl.Range`. See the note on Pos.
    start: Pos = field(default=ZERO_POS)
    end: Pos = field(default=ZERO_POS)

    def __str__(self) -> str:
        if self.start.line == self.end.line:
            return f"{self.filename}:{self.start.line},{self.start.column}-{self.end.column}"
        return (
            f"{self.filename}:{self.start.line},{self.start.column}-"
            f"{self.end.line},{self.end.column}"
        )

    def slice(self, source: bytes) -> bytes:
        """Rend les octets que cette plage couvre, ou b"" si elle ne tient pas dans
        `src`.

        Être hors bornes signifie que l'appelant a associé une plage à une
        source dont elle ne vient pas. Rendre du vide en fait une découverte
        manquée plutôt qu'une exception à l'intérieur de la CI de quelqu'un
        d'autre.
        """
        start, end = self.start.byte, self.end.byte
        if start < 0 or end > len(source) or start >= end:
            return b""
        return source[start:end]

    def merge(self, other: Range) -> Range:
        """La plus petite plage couvrant les deux. Sert à étendre une expression de
        son premier jeton à son dernier."""
        return Range(
            filename=self.filename or other.filename,
            start=min(self.start, other.start),
            end=max(self.end, other.end),
        )


def range_between(filename: str, start: Pos, end: Pos) -> Range:
    return Range(filename=filename, start=start, end=end)
