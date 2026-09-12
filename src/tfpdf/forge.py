"""Shared interfaces for publishing scan results to GitHub and other code hosts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class InlineComment:
    """A review comment attached to a line range in a diff."""

    #: File path relative to the repository root.
    path: str

    #: Bound the commented range in the post-change file, inclusive. A
    #: single-line comment sets them equal (or leaves `start_line` zero).
    line: int
    start_line: int = 0

    body: str = ""

    #: Uniquely identifies this comment's content. If a comment already on the
    #: change contains it, this one is skipped — inline comments can't be
    #: upserted as a set the way a summary comment can, so recognizing one's
    #: own past comments is the only defence against stacking duplicates on
    #: every push.
    marker: str = ""


@dataclass(slots=True)
class SuggestionOutcome:
    """Publication results for comments passed to post_suggestions."""

    posted: int = 0
    already_there: int = 0
    outside_diff: int = 0


class Forge(Protocol):
    """A code host that can receive scanner reports."""

    def upsert_comment(self, body: str, marker: str) -> None:
        """Replace the summary comment containing marker, or create one if absent."""
        ...

    def post_suggestions(
        self, summary: str, comments: list[InlineComment], head_sha: str
    ) -> SuggestionOutcome:
        """Post inline review comments, skipping unsupported ranges and existing comments."""
        ...


def patch_line_numbers(patch: str) -> set[int]:
    """Parse a unified patch and return the covered line numbers in the updated file."""
    lines: set[int] = set()
    new_line = 0

    # The trailing newline would otherwise yield one phantom line past the end
    # of the last hunk, and a comment there is rejected by every host.
    for line in patch.removesuffix("\n").split("\n"):
        if line.startswith("@@"):
            n = _hunk_new_start(line)
            if n is not None:
                new_line = n
            continue
        if new_line == 0:
            continue  # text before the first hunk header

        if line.startswith(("+", " ")) or line == "":
            # Added or unchanged: this line exists in the new file. An empty
            # string is an unchanged blank line whose leading space was
            # trimmed somewhere along the way.
            lines.add(new_line)
            new_line += 1
        elif line.startswith("-"):
            # Deleted: present only in the old file; the counter must not
            # advance.
            pass
        else:
            # "\ No newline at end of file" and anything else unrecognized.
            pass
    return lines


def _hunk_new_start(header: str) -> int | None:
    """Extract the updated-file start line from a hunk header, such as 14 from @@ -12,7 +14,9 @@."""
    plus = header.find("+")
    if plus < 0:
        return None
    rest = header[plus + 1 :]
    end = min((i for i in (rest.find(","), rest.find(" ")) if i >= 0), default=-1)
    if end < 0:
        return None
    try:
        n = int(rest[:end])
    except ValueError:
        return None
    return n if n >= 1 else None


def lines_in_diff(diff_lines: dict[str, set[int]], cm: InlineComment) -> bool:
    """Check that every line in a comment's range is commentable in the file's diff."""
    in_file = diff_lines.get(cm.path)
    if in_file is None:
        return False
    start = cm.start_line if cm.start_line > 0 else cm.line
    return all(line in in_file for line in range(start, cm.line + 1))
