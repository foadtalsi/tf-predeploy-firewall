"""Client du service cloud, utilisé uniquement quand une clé de licence est fournie."""

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
    """Le plan de contrôle a refusé, ou n'a pas pu répondre."""


@dataclass(slots=True, frozen=True)
class FindingSummary:
    """Le sous-ensemble d'une découverte envoyé au plan de contrôle, pour que les pages Rapports,
    Tendances et Journal d'audit du tableau de bord puissent montrer ce qui a réellement été
    trouvé, et pas seulement un compteur."""

    category: str = ""
    severity: str = ""
    resource: str = ""
    file_path: str = ""
    line: int = 0
    message: str = ""


@dataclass(slots=True)
class ScanResult:
    """Ce que le CLI rapporte d'un scan terminé, utilisé à la fois pour le
    décompte d'usage et pour les décisions d'application de quota."""

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
        """Retourne (autorisé, raison). Les erreurs réseau ou serveur sont levées ; l'appelant
        décide si elles bloquent."""
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
        """Récupère toutes les dérogations actives — non expirées — configurées
        pour le dépôt.

        Rend une liste vide, et non une erreur, quand il n'y en a aucune.
        """
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
        """Le pack de règles étendu d'un fournisseur.

        Voir `rulepacks.fetch_rule_pack` : l'erreur rendue est consultative.
        """
        return fetch_rule_pack(self.api_base, self.api_key, provider)


def new_client(api_key: str, api_base: str = "") -> Client:
    """Construit un client, en donnant à l'API sa base par défaut."""
    return Client(api_key=api_key, api_base=api_base or DEFAULT_API_BASE)
