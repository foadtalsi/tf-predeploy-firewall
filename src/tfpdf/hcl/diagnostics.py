"""Les diagnostics — le canal d'erreurs de l'analyseur et de l'évaluateur.

Modelés sur hcl.Diagnostics plutôt que sur les exceptions Python, et la raison
est dans l'évaluateur plutôt que dans l'analyseur. `expr.value(ctx)` est appelé
sur chaque attribut de chaque ressource, et *la plupart de ces appels sont
censés échouer* : une valeur qui lit `var.region` sans contexte, un appel de
fonction, tout ce qui se calcule au moment du plan. C'est le chemin normal et
courant, pas un chemin d'erreur.

Rendre `(valeur, diagnostics)` le maintient ainsi. Lever ferait du cas ordinaire
une exception, et tous les sites d'appel seraient un `try/except` autour de ce
qu'ils veulent réellement. Cela correspond aussi ligne pour ligne à la source Go
dont ceci est porté, ce qui rend les deux comparables quand une découverte
diffère.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .pos import Range


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: Severity
    summary: str
    detail: str = ""
    subject: Range | None = None

    def __str__(self) -> str:
        where = f"{self.subject}: " if self.subject is not None else ""
        if self.detail:
            return f"{where}{self.summary}; {self.detail}"
        return f"{where}{self.summary}"


class Diagnostics(list[Diagnostic]):
    """Une liste de diagnostics, avec les deux helpers que hcl lui donne."""

    def has_errors(self) -> bool:
        return any(d.severity is Severity.ERROR for d in self)

    def error(self) -> str:
        """Rend comme le fait hcl.Diagnostics.Error() : le premier diagnostic,
        plus le décompte de ceux qui suivaient."""
        if not self:
            return "no diagnostics"
        if len(self) == 1:
            return str(self[0])
        return f"{self[0]}, and {len(self) - 1} other diagnostic(s)"

    def extended(self, *others: Diagnostics | list[Diagnostic]) -> Diagnostics:
        out = Diagnostics(self)
        for o in others:
            out.extend(o)
        return out


def error(summary: str, detail: str = "", subject: Range | None = None) -> Diagnostics:
    """Raccourci pour le cas à une seule erreur, qui est presque tous les cas."""
    return Diagnostics([Diagnostic(Severity.ERROR, summary, detail, subject)])


class HCLParseError(Exception):
    """Levée uniquement là où le code Go rend une erreur dure à son appelant :
    `ParseFile` sur un fichier malformé. L'évaluation ne lève jamais."""

    def __init__(self, diags: Diagnostics) -> None:
        super().__init__(diags.error())
        self.diags = diags
