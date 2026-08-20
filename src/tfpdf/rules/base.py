"""Les types que toutes les règles partagent.

Extraits de `engine.py` pour que les détecteurs puissent importer ce dont ils
ont besoin sans importer le moteur qui les exécute : le moteur importe chaque
détecteur, et l'arête inverse serait un cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..parser import Resource
from ..report.finding import Category, Finding
from ..schema import KnowledgeBase


@dataclass(slots=True)
class FileInput:
    """Ce que chaque règle voit pour un fichier .tf modifié."""

    path: str

    #: The resource blocks as they exist after the change.
    head_resources: list[Resource] = field(default_factory=list)

    #: The raw file content the head resources were parsed from. Rules use it
    #: to build `Fix` values, which have to reproduce existing lines byte for
    #: byte. Optional: with it empty, rules simply emit no one-click fixes,
    #: which is why unit tests that construct a FileInput by hand don't have to
    #: supply it.
    head_source: bytes = b""

    #: Maps "type.name" -> resource as it existed before the change, for files
    #: that existed at the base ref. Empty for new files.
    base_resources: dict[str, Resource] = field(default_factory=dict)


class Rule(Protocol):
    """Un détecteur de risque unique."""

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]: ...


@dataclass(slots=True)
class RunOptions:
    """Comportement optionnel du moteur de scan."""

    #: Categories to suppress across all files.
    global_ignore: list[Category | str] = field(default_factory=list)

    #: The checkout root. When set, each scanned file's whole directory is read
    #: to build a scope for resolving `var.x` and `local.y` — Terraform scopes
    #: those per directory, not per file, so a local declared in locals.tf has
    #: to be visible when scanning rds.tf.
    #:
    #: Leaving it empty disables reference resolution entirely; every rule then
    #: behaves exactly as it did before, skipping non-literal values.
    repo_dir: str = ""


@dataclass(slots=True)
class Options:
    """Les réglages qu'un moteur compilé prend de la configuration plutôt que
    du pack, parce que ce sont des choix propres à un dépôt."""

    #: The estimated monthly increase that makes a cost finding. Zero leaves
    #: the static cost rule out of the set entirely.
    cost_threshold_usd: float = 0.0


class RuleSet(list["Rule"]):
    """Exécute plusieurs règles comme une seule, pour qu'un appelant puisse
    traiter « tout ce que le pack dit des identifiants » comme un détecteur
    unique."""

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for r in self:
            findings.extend(r.check(in_, kb))
        return findings
