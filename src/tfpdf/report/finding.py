"""Findings produced by the rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Severity levels from lowest to highest."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def at_least(self, other: Severity | str) -> bool:
        """Compare severity ranks. Unknown thresholds use the minimum rank and trigger a CLI
        warning.
        """
        return _SEVERITY_RANK[self] >= _SEVERITY_RANK.get(other, 0)  # type: ignore[arg-type]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Category(StrEnum):
    """A finding's detection category."""

    UNKNOWN_ATTRIBUTE = "unknown_attribute"
    UNPINNED_VERSION = "unpinned_version"
    TUTORIAL_PATTERN = "tutorial_pattern"
    FORCE_NEW_CHANGE = "force_new_change"
    MISSING_LIFECYCLE = "missing_lifecycle"

    # Guards that were explicitly switched off. Every rule behind these matches
    # a value someone wrote — never an absent attribute — because a missing
    # setting is the provider default on hundreds of resource types and
    # reporting those is how a scanner earns the mute button.
    #
    # They are four categories rather than one because suppression is
    # per-category: a team that has decided its buckets are public should be
    # able to say so without also silencing unencrypted volumes.
    PUBLIC_EXPOSURE = "public_exposure"
    ENCRYPTION_DISABLED = "encryption_disabled"
    PERMISSIVE_IAM = "permissive_iam"
    AUDIT_DISABLED = "audit_disabled"

    # Phase 2 categories: require a `terraform show -json` plan supplied via
    # --plan-json. Unlike the categories above, these are derived from
    # Terraform's own diff engine, not a heuristic over the .tf source.
    CONFIRMED_REPLACE = "confirmed_replace"
    UNEXPECTED_DRIFT = "unexpected_drift"
    LARGE_BLAST_RADIUS = "large_blast_radius"


@dataclass(slots=True)
class Fix:
    """An exact replacement of inclusive, one-based PR head lines. Uncertain fixes remain
    plain-text advice.
    """

    #: Inclusive, 1-based, referring to the file as it exists at the PR head.
    start_line: int
    end_line: int

    #: The replacement content, one entry per line, already indented to match
    #: the code it replaces. An empty list deletes the range.
    lines: list[str] = field(default_factory=list)

    #: Optional context rendered beneath the suggestion — used when applying
    #: the fix is correct but not sufficient on its own, e.g. swapping a
    #: hardcoded password for `var.x` also requires declaring `variable "x"`
    #: elsewhere in the module. Terraform fails loudly on the undeclared
    #: variable, so the half-applied state is safe; saying so up front is what
    #: stops it being a surprise.
    note: str = ""

    def text(self) -> str:
        """Return replacement lines as they would appear in the file."""
        return "\n".join(self.lines)


@dataclass(slots=True)
class Finding:
    """A single risk detected in Terraform changes."""

    file: str
    line: int
    #: One of the built-in categories, or a bare `"custom:<id>"` string from a
    #: custom rule. Go's `report.Category` is an open string type, so a custom
    #: rule can name anything; the enum here documents the built-in set without
    #: closing the field to it. Everything downstream treats a category as text
    #: — suppression matches on it, the renderers print it — so the two forms
    #: are interchangeable at every use site.
    category: Category | str
    severity: Severity
    #: "type.name" address, for context.
    resource: str
    message: str

    # Rule ID, or custom:<id>, distinct from the shared category. Baseline v2 uses it for exact
    # matching; SARIF retains category-based ruleId. Empty is valid for findings with no rule.
    rule_name: str = ""

    # Actual cloud name, such as prod-backups, distinct from the Terraform address. Empty means
    # unknown; never query AWS with it or infer absence.
    cloud_name: str = ""

    #: An optional, mechanically-generated HCL snippet showing how to fix the
    #: finding — not a computed byte-range patch against the real file (this
    #: tool never has write access to the repo), just a snippet the author can
    #: paste in. Populated only for categories where a safe, generic fix
    #: exists; empty otherwise.
    suggestion: str = ""

    #: When set, links to the provider documentation for the resource type this
    #: finding is about, pinned to the provider version the rule pack
    #: describes.
    #:
    #: It is what turns "attribute X is not a known argument of aws_instance"
    #: from an assertion into something checkable. A scanner that says an
    #: argument does not exist and offers no way to verify it gets argued with;
    #: one that links the argument list gets believed or corrected, and both
    #: outcomes are better.
    doc_url: str = ""

    #: The same fix expressed as an exact line replacement, which is what
    #: GitHub's one-click "Commit suggestion" button needs. See `Fix`.
    fix: Fix | None = None

    #: When true, excludes this finding from the blocking decision and from
    #: SARIF output — an admin accepted this specific finding (matched by
    #: category+resource+file, via the control plane's per-finding waivers,
    #: Starter+) with `waiver_note` as the justification. It still appears in
    #: the PR comment, in its own section, so a waived finding never just
    #: silently vanishes from the record.
    waived: bool = False
    waiver_note: str = ""
