"""À quoi ressemble la publication de résultats de scan sur une forge quand elle n'a pas la forme
de GitHub."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class InlineComment:
    """Un commentaire à rattacher à une plage de lignes du diff."""

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
    """Rend compte de chaque commentaire confié à `post_suggestions`."""

    posted: int = 0
    already_there: int = 0
    outside_diff: int = 0


class Forge(Protocol):
    """Une forge à laquelle le scanner peut rapporter."""

    def upsert_comment(self, body: str, marker: str) -> None:
        """Trouve le commentaire de synthèse existant contenant `marker` et remplace
        son corps, ou en crée un."""
        ...

    def post_suggestions(
        self, summary: str, comments: list[InlineComment], head_sha: str
    ) -> SuggestionOutcome:
        """Rattache les commentaires en commentaires de revue en ligne, en écartant
        ce que l'hôte refuserait et ce qui a déjà été posté."""
        ...


def patch_line_numbers(patch: str) -> set[int]:
    """Parcourt un patch au format unifié, hunk par hunk, et rend les numéros de lignes d'après
    changement qu'il couvre."""
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
    """La ligne de départ d'après changement d'un en-tête de hunk : par exemple
    « @@ -12,7 +14,9 @@ resource ... » donne 14."""
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
    """Dit si chaque ligne de la plage du commentaire est commentable, au vu des
    ensembles de lignes de diff par fichier."""
    in_file = diff_lines.get(cm.path)
    if in_file is None:
        return False
    start = cm.start_line if cm.start_line > 0 else cm.line
    return all(line in in_file for line in range(start, cm.line + 1))
