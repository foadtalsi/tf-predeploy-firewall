"""Hosted-service client used only when a license key is supplied."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import quote

from .._httpjson import request_raw
from .rulepacks import RulePack, fetch_rule_pack
from .waivers import Waiver, waivers_from_json

DEFAULT_API_BASE = "https://api.tfpredeployfirewall.com"

#: Go sets this on the client it builds; the pack fetch narrows it further.
DEFAULT_TIMEOUT = 10.0


class LicensingError(RuntimeError):
    """A hosted-service refusal or failed request."""


@dataclass(slots=True, frozen=True)
class FindingSummary:
    """Finding fields reported to the hosted service for dashboard reports, trends, and audit
    history.
    """

    category: str = ""
    severity: str = ""
    resource: str = ""
    file_path: str = ""
    line: int = 0
    message: str = ""


@dataclass(slots=True)
class ScanResult:
    """Completed scan data used for usage tracking and quota decisions."""

    repo_full_name: str = ""
    finding_count: int = 0
    blocked: bool = False
    findings: list[FindingSummary] = field(default_factory=list)
    scan_actor: str = ""


@dataclass(slots=True)
class Client:
    api_key: str = ""
    api_base: str = DEFAULT_API_BASE
    timeout: float = DEFAULT_TIMEOUT

    def _headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.api_key}

    # --- usage ------------------------------------------------------------

    def record_scan(self, result: ScanResult) -> tuple[bool, str]:
        """Return (allowed, reason). Raise network and server errors for the caller to handle."""
        payload = {
            "repo_full_name": result.repo_full_name,
            "finding_count": result.finding_count,
            "blocked": result.blocked,
        }
        if result.scan_actor:
            payload["scan_actor"] = result.scan_actor
        # `omitempty` on the Go side: an empty findings list is left out
        # entirely rather than sent as [].
        if result.findings:
            payload["findings"] = [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "resource": f.resource,
                    "file": f.file_path,
                    "line": f.line,
                    "message": f.message,
                }
                for f in result.findings
            ]

        response = request_raw(
            "POST",
            self.api_base + "/v1/usage/scan",
            {**self._headers(), "Content-Type": "application/json"},
            body=json.dumps(payload).encode(),
            timeout=self.timeout,
        )

        if response.status == 401:
            raise LicensingError("invalid or revoked API key")
        if response.status != 200:
            raise LicensingError(
                f"licensing service returned {response.status}: {response.body.decode(errors='replace')}"
            )

        try:
            document = json.loads(response.body) if response.body else {}
        except json.JSONDecodeError as exc:
            raise LicensingError(f"parsing licensing response: {exc}") from exc
        if not isinstance(document, dict):
            raise LicensingError("parsing licensing response: not an object")
        return bool(document.get("allowed", False)), str(document.get("reason", ""))

    # --- waivers ----------------------------------------------------------

    def get_waivers(self, repo_full_name: str) -> list[Waiver]:
        """Fetch active, unexpired repository waivers. Return an empty list when none exist."""
        url = self.api_base + "/v1/waivers?repo=" + quote(repo_full_name, safe="")
        response = request_raw("GET", url, self._headers(), timeout=self.timeout)
        if response.status == 401:
            raise LicensingError("invalid or revoked API key")
        if response.status != 200:
            raise LicensingError(f"licensing service returned {response.status}")

        try:
            document = json.loads(response.body) if response.body else []
        except json.JSONDecodeError as exc:
            raise LicensingError(f"parsing waivers response: {exc}") from exc
        return waivers_from_json(document)

    # --- rule packs -------------------------------------------------------

    def fetch_rule_pack(self, provider: str) -> tuple[RulePack | None, Exception | None]:
        """Fetch a provider's extended schema pack; see rulepacks.fetch_rule_pack for advisory
        errors.
        """
        return fetch_rule_pack(self.api_base, self.api_key, provider)


def new_client(api_key: str, api_base: str = "") -> Client:
    """Build a client using the default API base URL when none is supplied."""
    return Client(api_key=api_key, api_base=api_base or DEFAULT_API_BASE)
