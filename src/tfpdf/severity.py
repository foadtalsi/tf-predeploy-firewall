"""Legacy blocking API. The CLI uses blocked_by, which respects accepted findings."""

from __future__ import annotations

from collections.abc import Iterable

from .report.finding import Finding, Severity


def should_block_ignoring_waivers(findings: Iterable[Finding], threshold: Severity) -> bool:
    """Compare all findings against a threshold, including accepted findings."""
    return any(finding.severity.at_least(threshold) for finding in findings)
