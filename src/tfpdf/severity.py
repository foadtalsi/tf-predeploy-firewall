"""Décide si un ensemble de découvertes doit bloquer une pull request.

Port de internal/severity/gate.go.

**Note sur une divergence héritée de la source Go.** Le `ShouldBlock` de ce
paquet n'ignore pas les découvertes couvertes par une dérogation, alors que le
CLI répond à la même question avec son propre `blockedBy`, qui les ignore. Les
deux sont en désaccord exactement dans le cas pour lequel les dérogations
existent, et c'est la version du CLI que la production utilise ; `ShouldBlock`
n'a aucun appelant hors tests dans l'arbre Go.

Les deux sont portés, parce que les renommer ou les fusionner ferait diverger
les deux scanners d'une façon invisible dans un diff — mais
`should_block_ignoring_waivers` porte le nom de ce qu'il fait réellement, si
bien que choisir le mauvais devient une décision et non un accident. Du code
neuf veut `tfpdf.cli.main.blocked_by`.
"""

from __future__ import annotations

from collections.abc import Iterable

from .report.finding import Finding, Severity


def should_block_ignoring_waivers(findings: Iterable[Finding], threshold: Severity) -> bool:
    """Dit si une découverte atteint ou dépasse `threshold`, dérogation ou non.

    Compte les découvertes couvertes par une dérogation et celles de la
    référence, ce qui n'est presque jamais ce que veut l'appelant — voir la
    docstring du module.
    """
    return any(f.severity.at_least(threshold) for f in findings)
