"""Sortie Code Quality de GitLab.

Port de internal/report/codequality.go.

Le JSON dérivé de CodeClimate que le widget de merge request de GitLab rend
nativement. C'est l'équivalent GitLab de l'envoi de SARIF sur GitHub : les
découvertes apparaissent dans l'interface de la MR elle-même, avec des flèches
de dégradation par rapport à la branche cible, sans qu'aucun jeton de
publication de commentaire ne soit requis.

https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format
"""

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
    """Sérialise les découvertes en un rapport Code Quality GitLab.

    L'empreinte exclut délibérément le numéro de ligne : GitLab compare les
    problèmes d'un pipeline à l'autre par empreinte, et une empreinte qui se
    décalerait avec la ligne ferait ressembler chaque rebase à des découvertes
    qui apparaissent et disparaissent. Elle inclut en revanche le message,
    contrairement à la clé plus grossière de la référence : deux découvertes de
    même catégorie sur une même ressource — deux identifiants en dur, par
    exemple — ne doivent pas se fondre en une seule ligne du widget.
    """
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
