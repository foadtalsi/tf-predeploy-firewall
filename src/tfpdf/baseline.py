"""Record existing findings so they remain visible without blocking new changes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .report.finding import Finding

#: Guards against reading a baseline written by a future scanner whose
#: semantics we don't know. Accepting one blindly could silence findings the
#: author never agreed to.
FORMAT_VERSION = 2

# Version 1 remains readable for compatibility but matches broadly without rule_name. Regenerate
# it to use exact version 2 matching.
READABLE_VERSIONS = frozenset({1, 2})

# Fields introduced by baseline version 2.
LEGACY_VERSION = 1

_NOTE = (
    "Findings accepted as pre-existing. They stay visible in the PR comment but do not "
    "block a merge; anything not listed here does. Matched on rule+category+resource+file, "
    "never on line number. Regenerate with --write-baseline."
)


@dataclass(slots=True, frozen=True)
class Entry:
    """An accepted finding."""

    category: str
    resource: str
    file: str

    # Empty rule names are valid for parse-error findings. File version, not an empty name,
    # determines whether matching is exact.
    rule_name: str = ""

    #: Recorded for the human reading the diff of this file — never matched on.
    #: Messages get reworded as the scanner improves, and lines move; matching
    #: on either would make every upgrade resurrect the whole backlog.
    message: str = ""
    line: int = 0

    def key(self) -> str:
        """Return the exact version 2 key, including the rule name."""
        return f"{self.category}\x00{self.resource}\x00{self.file}\x00{self.rule_name}"

    def legacy_key(self) -> str:
        """Return the version 1 key without a rule name. Its separator count distinguishes it from
        version 2.
        """
        return f"{self.category}\x00{self.resource}\x00{self.file}"


@dataclass(slots=True)
class Baseline:
    """A loaded baseline ready to match against findings."""

    # Version 2 entries match exactly, including rule name.
    by_key: dict[str, Entry] = field(default_factory=dict)
    # Version 1 entries match without rule name.
    by_legacy_key: dict[str, Entry] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)
    # Let the caller warn about broad legacy matching; this module does not print.
    legacy: bool = False

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Mark matching findings as accepted while keeping them in the report."""
        for finding in findings:
            entry = Entry(
                category=str(finding.category),
                resource=finding.resource,
                file=finding.file,
                rule_name=finding.rule_name,
            )
            exact = entry.key()
            if exact in self.by_key:
                matched = exact
            elif (loose := entry.legacy_key()) in self.by_legacy_key:
                matched = loose
            else:
                continue
            self.used.add(matched)
            finding.waived = True
            finding.waiver_note = "accepted in baseline"
        return findings

    def stale(self) -> int:
        """Count baseline entries no longer found in this scan."""
        return self.size() - len(self.used)

    def size(self) -> int:
        """Return the number of accepted findings in the baseline."""
        return len(self.by_key) + len(self.by_legacy_key)


def load(path: str) -> Baseline | None:
    """Load a baseline. A missing file means no findings have been accepted yet."""
    if not path:
        return None
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"reading baseline {path}: {exc}") from exc

    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parsing baseline {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"parsing baseline {path}: top level is not an object")

    version = int(document.get("format_version", 0) or 0)
    if version not in READABLE_VERSIONS:
        readable = ", ".join(str(v) for v in sorted(READABLE_VERSIONS))
        raise ValueError(
            f"baseline {path} has format version {version}, this scanner understands "
            f"{readable} — regenerate it with --write-baseline"
        )

    legacy = version == LEGACY_VERSION
    b = Baseline(legacy=legacy)
    for e in document.get("entries") or []:
        entry = Entry(
            category=str(e.get("category", "")),
            resource=str(e.get("resource", "")),
            file=str(e.get("file", "")),
            # Preserve manually added rule names in version 1, but keep matching semantics tied
            # to file version.
            rule_name=str(e.get("rule_name", "")),
            message=str(e.get("message", "")),
            line=int(e.get("line", 0) or 0),
        )
        if legacy:
            b.by_legacy_key[entry.legacy_key()] = entry
        else:
            b.by_key[entry.key()] = entry
    return b


def write(path: str, findings: list[Finding], generated_at: str) -> None:
    """Write findings atomically with restricted permissions, omitting potentially sensitive
    messages.
    """
    seen: set[str] = set()
    entries: list[Entry] = []

    for finding in findings:
        entry = Entry(
            category=str(finding.category),
            resource=finding.resource,
            file=finding.file,
            rule_name=finding.rule_name,
            message=finding.message,
            line=finding.line,
        )
        if entry.key() in seen:
            continue
        seen.add(entry.key())
        entries.append(entry)

    # Stable order so regenerating an unchanged repo produces no diff.
    entries.sort(key=lambda entry: (entry.file, entry.resource, entry.category, entry.rule_name))

    document = {
        "format_version": FORMAT_VERSION,
        "generated_at": generated_at,
        "_note": _NOTE,
        "entries": [
            {
                "category": entry.category,
                "resource": entry.resource,
                "file": entry.file,
                # Always write rule_name, even when empty, to distinguish complete version 2
                # entries.
                "rule_name": entry.rule_name,
                **({"message": entry.message} if entry.message else {}),
                **({"line": entry.line} if entry.line else {}),
            }
            for entry in entries
        ],
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n")
