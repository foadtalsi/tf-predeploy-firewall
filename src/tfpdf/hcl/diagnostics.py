"""Parser and evaluator diagnostics.

Evaluation returns (value, diagnostics) because unresolved references and
function calls are normal during static analysis. They are not exceptions.
Callers must check diagnostics before trusting a returned value.
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
    """Diagnostics with error detection and summary helpers."""

    def has_errors(self) -> bool:
        return any(diagnostic.severity is Severity.ERROR for diagnostic in self)

    def error(self) -> str:
        """Format the first diagnostic and the count of additional diagnostics, matching HCL."""
        if not self:
            return "no diagnostics"
        if len(self) == 1:
            return str(self[0])
        return f"{self[0]}, and {len(self) - 1} other diagnostic(s)"

    def extended(self, *others: Diagnostics | list[Diagnostic]) -> Diagnostics:
        diagnostics = Diagnostics(self)
        for other_diagnostics in others:
            diagnostics.extend(other_diagnostics)
        return diagnostics


def error(summary: str, detail: str = "", subject: Range | None = None) -> Diagnostics:
    """Create diagnostics containing a single error."""
    return Diagnostics([Diagnostic(Severity.ERROR, summary, detail, subject)])


class HCLParseError(Exception):
    """A malformed file rejected by parse_file. Expression evaluation uses diagnostics instead."""

    def __init__(self, diags: Diagnostics) -> None:
        super().__init__(diags.error())
        self.diags = diags
