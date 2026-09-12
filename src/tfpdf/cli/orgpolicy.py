"""Apply hosted waivers and report scan usage."""

from __future__ import annotations

import os
import sys

from .. import licensing
from ..report.finding import Finding


def _warn(message: str) -> None:
    print("tf-predeploy-firewall: " + message, file=sys.stderr)


def apply_waivers(
    findings: list[Finding], license_key: str, api_base: str, repo_full_name: str = ""
) -> list[Finding]:
    """Accept waiver matches by category, resource, and file, independently of line numbers."""
    if not repo_full_name:
        return findings

    client = licensing.new_client(license_key, api_base)
    try:
        waivers = client.get_waivers(repo_full_name)
    except Exception as exc:
        _warn(f"fetching waivers failed, no findings waived ({exc})")
        return findings
    if not waivers:
        return findings

    by_key = {
        (waiver.category, waiver.resource, waiver.file_path): waiver.justification
        for waiver in waivers
    }
    for finding in findings:
        note = by_key.get((str(finding.category), finding.resource, finding.file))
        if note is not None:
            finding.waived = True
            finding.waiver_note = note
    return findings


def report_usage(
    license_key: str,
    api_base: str,
    findings: list[Finding],
    blocked: bool,
    repo_full_name: str = "",
) -> bool:
    """Report the scan. Return True on quota refusal; warn without blocking on network failure."""
    if not repo_full_name:
        # Warn when no repository identity is available: this scan cannot appear in hosted usage
        # or history.
        _warn(
            "TFPDF_LICENSE_KEY is set but this scan has no repository name — no "
            "GITHUB_REPOSITORY or CI_PROJECT_PATH, and no usable git remote. This scan "
            "will NOT be counted against your plan; pass --repo-name owner/repo (or set "
            "TFPDF_REPO_NAME) to record it."
        )
        return False

    summaries = [
        licensing.FindingSummary(
            category=str(finding.category),
            severity=str(finding.severity),
            resource=finding.resource,
            file_path=finding.file,
            line=finding.line,
            message=finding.message,
        )
        for finding in findings
    ]

    client = licensing.new_client(license_key, api_base)
    try:
        allowed, reason = client.record_scan(
            licensing.ScanResult(
                repo_full_name=repo_full_name,
                finding_count=len(findings),
                blocked=blocked,
                findings=summaries,
                scan_actor=scan_actor(),
            )
        )
    except Exception as exc:
        _warn(f"usage reporting failed (scan still ran): {exc}")
        return False
    if not allowed:
        _warn(reason)
        return True
    return False


def scan_actor() -> str:
    """Identity reported by CI, not a verified dashboard user or commit author."""
    for variable in (
        "TFPDF_SCAN_ACTOR",
        "GITHUB_TRIGGERING_ACTOR",
        "GITHUB_ACTOR",
        "GITLAB_USER_LOGIN",
    ):
        actor = os.environ.get(variable, "").strip()
        if actor:
            return actor[:256]
    return ""
