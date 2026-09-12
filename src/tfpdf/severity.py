"""Ancienne API de blocage, conservée pour compatibilité. Le CLI utilise blocked_by, qui respecte
les dérogations."""

from __future__ import annotations

from collections.abc import Iterable

from .report.finding import Finding, Severity


def should_block_ignoring_waivers(findings: Iterable[Finding], threshold: Severity) -> bool:
    """Compare les sévérités au seuil, y compris celles des découvertes acceptées."""
    return any(finding.severity.at_least(threshold) for finding in findings)
