"""Sortie Code Quality de GitLab."""

from __future__ import annotations

import hashlib
from typing import Any

from ._json import marshal_indent
from .finding import Finding, Severity

#: Maps onto GitLab's accepted set (info/minor/major/critical/blocker).
#: "blocker" is reserved: this tool's notion of blocking lives in its exit code
#: and threshold, and claiming the word in a UI that did not consult the
#: threshold would misstate the tool.
SEVERITY_TO_CODE_QUALITY = {
    Severity.LOW: "info",
    Severity.MEDIUM: "minor",
    Severity.HIGH: "major",
    Severity.CRITICAL: "critical",
}


def render_code_quality(findings: list[Finding]) -> bytes:
    """Produit le rapport GitLab. L'empreinte inclut le message mais exclut la ligne pour rester
    stable après déplacement."""
    issues: list[dict[str, Any]] = []
    for finding in findings:
        if finding.waived:
            continue  # accepted findings are decisions, not open issues
        key = "\x00".join([str(finding.category), finding.resource, finding.file, finding.message])
        issues.append(
            {
                "description": finding.resource + ": " + finding.message,
                "check_name": str(finding.category),
                "fingerprint": hashlib.sha256(key.encode()).hexdigest(),
                "severity": SEVERITY_TO_CODE_QUALITY.get(finding.severity, ""),
                "location": {"path": finding.file, "lines": {"begin": finding.line}},
            }
        )
    return marshal_indent(issues)
