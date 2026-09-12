"""Render inline review comments and stable markers that prevent duplicate posts."""

from __future__ import annotations

import hashlib

from .finding import Finding
from .markdown import SEVERITY_EMOJI
from .ruledocs import category_display

# Hidden marker used to skip inline suggestions already posted on earlier pushes.
FIX_MARKER_PREFIX = "<!-- tf-predeploy-firewall:fix:"


def fix_marker(f: Finding) -> str:
    """Return a suggestion identity stable across pushes."""
    text = f.fix.text() if f.fix is not None else ""
    joined = "\x00".join([str(f.category), f.resource, f.file, text])
    digest = hashlib.sha256(joined.encode()).hexdigest()
    return FIX_MARKER_PREFIX + digest[:16] + " -->"


def has_fix_marker(comment_body: str, f: Finding) -> bool:
    """Check whether an existing comment already represents this finding."""
    return fix_marker(f) in comment_body


def review_comment_body(f: Finding) -> str:
    """Render a finding with a GitHub suggestion block that the author can accept with Commit
    suggestion.
    """
    # GitHub takes the replacement range from the comment anchor, not the suggestion header.
    return _suggestion_body(f, "```suggestion")


def gitlab_suggestion_body(f: Finding) -> str:
    """Render a review suggestion using GitLab's block syntax."""
    height = f.fix.end_line - f.fix.start_line if f.fix is not None else 0
    return _suggestion_body(f, f"```suggestion:-0+{height}")


def _suggestion_body(f: Finding, fence_header: str) -> str:
    b: list[str] = []

    b.append(
        f"**{SEVERITY_EMOJI.get(f.severity, '')} {f.severity} — "
        f"{category_display(f.category)}**\n\n"
    )
    b.append(f.message + "\n\n")

    b.append(fence_header + "\n")
    # Handle findings without fixes instead of dereferencing a missing replacement.
    text = f.fix.text() if f.fix is not None else ""
    if text:
        b.append(text + "\n")
    b.append("```\n")

    if f.fix is not None and f.fix.note:
        b.append("\n" + f.fix.note + "\n")
    if f.doc_url:
        b.append(f"\n📖 [Provider documentation for `{f.resource}`]({f.doc_url})\n")

    b.append("\n" + fix_marker(f) + "\n")
    return "".join(b)
