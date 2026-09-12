"""Build exact line replacements, returning None when the source cannot be edited reliably."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..hcl import Range
from ..parser import Attribute, Resource
from ..report.finding import Fix

_NON_IDENT_CHAR = re.compile(r"[^a-zA-Z0-9_]")


@dataclass(slots=True, frozen=True)
class LineEdit:
    """A resolved replacement range and its new contents."""

    start: int
    end: int
    lines: list[str]


def line_text(source: bytes, n: int) -> str | None:
    """Return one-based line n without its line ending."""
    if not source or n < 1:
        return None
    lines = source.decode("utf-8", errors="replace").split("\n")
    if n > len(lines):
        return None
    return lines[n - 1].removesuffix("\r")


def indent_of(s: str) -> str:
    """Return leading whitespace, preserving tabs for generated lines."""
    return s[: len(s) - len(s.lstrip(" \t"))]


def opens_block(line: str) -> bool:
    """Check whether a line opens a block whose body starts on the next line."""
    return line.rstrip(" \t").endswith("{")


def declares_attr(line: str, name: str) -> bool:
    """Check whether a line declares the named attribute, allowing indentation."""
    rest = line.lstrip(" \t")
    if not rest.startswith(name):
        return False
    return rest[len(name) :].lstrip(" \t").startswith("=")


def insert_into_block(source: bytes, header: Range, *add: str) -> LineEdit | None:
    """Preserve the block header and insert lines indented one level into its body."""
    line_no = header.start.line
    text = line_text(source, line_no)
    if text is None or not opens_block(text):
        return None
    inner = indent_of(text) + "  "
    out = [text, *(inner + a for a in add)]
    return LineEdit(start=line_no, end=line_no, lines=out)


def replace_attr_line(source: bytes, r: Range, attr_name: str, new_text: str) -> LineEdit | None:
    """Replace a single-line attribute assignment while retaining its indentation."""
    if r.start.line != r.end.line:
        return None  # a multi-line value; not ours to rewrite
    text = line_text(source, r.start.line)
    if text is None or not declares_attr(text, attr_name):
        return None
    return LineEdit(start=r.start.line, end=r.start.line, lines=[indent_of(text) + new_text])


# --- naming helpers -------------------------------------------------------


def via_suffix(attribute: Attribute) -> str:
    """Name the reference behind a resolved value so the finding explains where the literal lives."""
    if not attribute.resolved_from:
        return ""
    return " (via " + attribute.resolved_from + ")"


def credential_var_name(res: Resource, block_type: str, attr_name: str) -> str:
    """Derive a variable name from resource, nested block, and attribute to avoid collisions."""
    name = sanitize_ident(res.name)
    if block_type:
        name += "_" + sanitize_ident(block_type)
    return name + "_" + sanitize_ident(attr_name)


def sanitize_ident(s: str) -> str:
    return _NON_IDENT_CHAR.sub("_", s.lower())


def as_fix(edit: LineEdit | None) -> Fix | None:
    """Convert a resolved line edit to a Fix, preserving None."""
    if edit is None:
        return None
    return Fix(start_line=edit.start, end_line=edit.end, lines=edit.lines)
