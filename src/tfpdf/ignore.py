"""Inline, category, and path-based finding suppression."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from .report.finding import Category, Finding

DIRECTIVE_PREFIX = "tf-firewall-ignore:"

# Pseudo-category that suppresses all findings on a line.
_ALL = "all"


def parse_comments(source: bytes) -> dict[int, set[str]]:
    """Map one-based source lines to categories suppressed by inline directives."""
    out: dict[int, set[str]] = {}
    text = source.decode("utf-8", errors="replace")
    for line_num, line in enumerate(text.split("\n"), start=1):
        index = line.find("#")
        if index < 0:
            continue
        comment = line[index + 1 :].strip()
        if not comment.startswith(DIRECTIVE_PREFIX):
            continue
        cats = _parse_category_list(comment[len(DIRECTIVE_PREFIX) :])
        # Suppress this line and the next so directives can sit above an attribute.
        for n in (line_num, line_num + 1):
            out.setdefault(n, set()).update(cats)
    return out


def _parse_category_list(s: str) -> list[str]:
    return [part.strip() for part in s.split(",") if part.strip()]


def apply(
    findings: Iterable[Finding],
    inline_by_file: dict[str, dict[int, set[str]]],
    global_ignore: Sequence[Category | str],
) -> list[Finding]:
    """Remove findings covered by inline directives or global category exclusions."""
    global_set = {str(c) for c in global_ignore}

    out: list[Finding] = []
    for finding in findings:
        if str(finding.category) in global_set:
            continue
        line_map = inline_by_file.get(finding.file, {}).get(finding.line)
        if line_map is not None and (_ALL in line_map or str(finding.category) in line_map):
            continue
        out.append(finding)
    return out


@dataclass(slots=True)
class PathRule:
    """A path exclusion supporting ** across zero or more segments, plus * and ? within a segment."""

    pattern: str
    # Accept built-in categories and custom:<id> strings from configuration.
    categories: list[Category | str] = field(default_factory=list)

    def suppresses(self, category: Category | str) -> bool:
        """Return whether this rule covers the category."""
        if not self.categories:
            return True
        return any(str(c) == str(category) for c in self.categories)


@lru_cache(maxsize=256)
def glob_to_regexp(pattern: str) -> re.Pattern[str]:
    """Compile and cache an anchored path expression with ** support for repeated finding checks."""
    parts = ["^"]
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    parts.append("$")
    return re.compile("".join(parts))


def apply_path_rules(findings: Sequence[Finding], rules: Sequence[PathRule]) -> list[Finding]:
    """Remove findings matching a path rule and one of its covered categories."""
    if not rules:
        return list(findings)

    out: list[Finding] = []
    for finding in findings:
        # Git and configuration use forward slashes on every platform; use posixpath for
        # matching.
        clean = posixpath.normpath(finding.file)
        if any(
            r.suppresses(finding.category) and glob_to_regexp(r.pattern).search(clean)
            for r in rules
        ):
            continue
        out.append(finding)
    return out
