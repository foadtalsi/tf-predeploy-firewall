"""Render findings for a terminal."""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

from .finding import Severity
from .ruledocs import category_display

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .finding import Finding


# Shared callable type for optional ANSI styling.
Paint = Callable[[str, str], str]

# Display highest severity first.
_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

# Below this width, use a layout without aligned columns.
_MIN_WIDTH = 60


def wants_color(stream: object | None = None) -> bool:
    """Decide whether to emit ANSI colors. The presence of NO_COLOR overrides all other settings."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def render_terminal(
    findings: list[Finding],
    threshold: Severity | str,
    blocked: bool,
    *,
    color: bool | None = None,
    width: int | None = None,
) -> str:
    """Render the terminal report. An explicit width overrides terminal-size detection for callers
    and tests.
    """
    if color is None:
        color = wants_color()
    if width is None:
        width = max(shutil.get_terminal_size((100, 24)).columns, _MIN_WIDTH)

    paint = _painter(color)
    lines: list[str] = []

    live = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]

    lines.append(_headline(live, threshold, blocked, paint))

    for severity in _ORDER:
        for group in _group_by_rule(f for f in live if f.severity is severity):
            lines.append("")
            lines.extend(_render_group(group, severity, width, paint))

    if waived:
        lines.append("")
        lines.append(paint(_DIM, f"{len(waived)} finding(s) waived, not blocking:"))
        for finding in waived:
            lines.append(paint(_DIM, f"  {finding.file}:{finding.line}  {finding.resource}"))

    if live:
        lines.append("")
        lines.append(paint(_DIM, "Full detail, fixes and doc links: --format markdown"))

    return "\n".join(lines)


def _painter(color: bool) -> Paint:
    if not color:
        return lambda _code, text: text
    return lambda code, text: f"{code}{text}{_RESET}"


def _headline(
    live: list[Finding],
    threshold: Severity | str,
    blocked: bool,
    paint: Paint,
) -> str:
    if not live:
        return paint(_BOLD, "No findings.")

    counts = [
        f"{sum(1 for finding in live if finding.severity is s)} {s}"
        for s in _ORDER
        if any(finding.severity is s for finding in live)
    ]
    head = f"{len(live)} finding(s) — " + ", ".join(counts)

    if blocked:
        return paint(_COLOR[Severity.CRITICAL], head + f"  ✗ blocked at {threshold}")
    return paint(_BOLD, head) + paint(_DIM, f"  nothing reaches {threshold}")


def _group_by_rule(findings: Iterable[Finding]) -> list[list[Finding]]:
    """Group findings by rule in first-appearance order."""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.rule_name or str(finding.category), []).append(finding)
    return list(groups.values())


def _render_group(
    group: list[Finding],
    severity: Severity,
    width: int,
    paint: Paint,
) -> list[str]:
    first = group[0]
    count = f" ({len(group)})" if len(group) > 1 else ""
    # Include rule IDs to distinguish detectors that share a category.
    title = category_display(first.category)
    if first.rule_name and first.rule_name != str(first.category):
        title += paint(_DIM, f" · {first.rule_name}")
    lines = [paint(_COLOR[severity], f"{severity}") + f"  {title}{count}"]

    # Print the shared explanation once per rule, then list individual findings.
    for line in _wrap(_shared_message(group), width - 2):
        lines.append(paint(_DIM, "  " + line))

    places = [f"{f.file}:{f.line}" for f in group]
    place_column = max(len(p) for p in places)
    resource_column = max(len(f.resource) for f in group)
    details = _what_differs(group)

    for finding, place, detail in zip(group, places, details, strict=True):
        left = f"  {place:<{place_column}}  {finding.resource:<{resource_column}}"
        if not detail:
            lines.append(left.rstrip())
            continue
        room = width - len(left) - 2
        lines.append(
            (left + "  " + paint(_DIM, _fit(detail, room))).rstrip() if room > 8 else left.rstrip()
        )
    return lines


def _shared_message(group: list[Finding]) -> str:
    """Use the first finding's message as the group's shared message."""
    return " ".join(group[0].message.split())


def _what_differs(group: list[Finding]) -> list[str]:
    """Extract the parts that differ between messages in a group."""
    if len(group) < 2:
        return [""]

    messages = [" ".join(f.message.split()) for f in group]
    shortest = min(len(match) for match in messages)

    prefix = 0
    while prefix < shortest and len({match[prefix] for match in messages}) == 1:
        prefix += 1
    while prefix > 0 and _inside_a_word(messages[0], prefix):
        prefix -= 1

    suffix = 0
    while suffix < shortest - prefix and len({match[-1 - suffix] for match in messages}) == 1:
        suffix += 1
    while suffix > 0 and _inside_a_word(messages[0], len(messages[0]) - suffix):
        suffix -= 1

    differing = []
    for finding, message in zip(group, messages, strict=True):
        text = message[prefix : len(message) - suffix].strip()
        differing.append("" if text and text in finding.resource else text)

    return _quoted_subjects(differing) or differing


def _quoted_subjects(differing: list[str]) -> list[str] | None:
    """Reduce each message to its leading quoted subject when all messages have one."""
    subjects = []
    for text in differing:
        if not text.startswith('"'):
            return None
        end = text.find('"', 1)
        if end < 1:
            return None
        subjects.append(text[: end + 1])
    return subjects


def _inside_a_word(text: str, index: int) -> bool:
    """Return whether cutting text at index would split a word."""
    if index <= 0 or index >= len(text):
        return False
    return _word_char(text[index - 1]) and _word_char(text[index])


def _word_char(character: str) -> bool:
    return character.isalnum() or character in "_\"'"


def _wrap(text: str, width: int) -> list[str]:
    import textwrap

    return textwrap.wrap(text, max(width, 20)) or [""]


def _fit(message: str, room: int) -> str:
    """Fit text within room characters, preferring a word boundary."""
    message = " ".join(message.split())
    if len(message) <= room:
        return message
    cut = message[: room - 1]
    space = cut.rfind(" ")
    if space > room // 2:
        cut = cut[:space]
    return cut + "…"
