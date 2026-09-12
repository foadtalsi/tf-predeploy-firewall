"""Source positions for findings, inline ignores, SARIF, and code suggestions.

Offsets count UTF-8 bytes so ranges can slice the original source. Lines and
columns are one-based; columns count Unicode code points rather than bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True, order=True)
class Pos:
    """A source position: one-based line and column, zero-based byte offset. All-zero defaults mean
    no position was recorded.
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
    """A half-open source range [start, end)."""

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
        """Return the covered source bytes, or b"" if the range is outside this source."""
        start, end = self.start.byte, self.end.byte
        if start < 0 or end > len(source) or start >= end:
            return b""
        return source[start:end]

    def merge(self, other: Range) -> Range:
        """Return the smallest range covering both inputs."""
        return Range(
            filename=self.filename or other.filename,
            start=min(self.start, other.start),
            end=max(self.end, other.end),
        )


def range_between(filename: str, start: Pos, end: Pos) -> Range:
    return Range(filename=filename, start=start, end=end)
