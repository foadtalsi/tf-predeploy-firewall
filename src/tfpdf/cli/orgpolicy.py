"""Ce que le plan de contrôle optionnel a le droit de changer à un scan.

Porte la moitié tournée vers la licence de cmd/tf-predeploy-firewall/main.go.

Tout ici échoue **ouvert**. Une panne côté facturation ne doit jamais être la
raison pour laquelle la vérification de PR d'un client payant passe au rouge :
un plan de contrôle injoignable laisse donc le scan tourner exactement sur la
configuration locale qu'il aurait utilisée de toute façon. La seule exception
est un refus explicite de quota, qui est une réponse et non une panne.
"""

from __future__ import annotations

import os
import sys

from .. import licensing
from ..report.finding import Finding
from .config import Config
from .forges import repo_full_name_from_env


def _warn(msg: str) -> None:
    print("tf-predeploy-firewall: " + msg, file=sys.stderr)


def apply_org_policy(cfg: Config, license_key: str, api_base: str) -> None:
    """Récupère la politique Growth gérée centralement pour l'organisation, s'il
    y en a une, et la fusionne sur `cfg` sur place.

    Priorité, du plus faible au plus fort : config.yml du dépôt < politique de
    l'organisation < variable d'environnement. Un opérateur peut donc toujours
    forcer un réglage localement par variable d'environnement, même quand une
    politique d'organisation existe — une échappatoire délibérée, pas un oubli.
    """
    client = licensing.new_client(license_key, api_base)
    try:
        policy = client.get_policy(repo_full_name_from_env())
    except Exception as exc:
        _warn(f"fetching org policy failed, using local config ({exc})")
        return
    if policy is None:
        return

    if policy.block_threshold is not None and not os.environ.get("SCANNER_BLOCK_THRESHOLD"):
        cfg.block_threshold = policy.block_threshold
    if policy.ignore_rules:
        # Centralized policy replaces the repo-local ignore list rather than
        # merging with it — the whole point of a team policy is that a single
        # repo's config.yml can't quietly opt out of it.
        cfg.ignore_rules = list(policy.ignore_rules)
    if policy.plan_blast_radius_threshold is not None and not os.environ.get(
        "SCANNER_PLAN_BLAST_RADIUS_THRESHOLD"
    ):
        cfg.plan_blast_radius_threshold = policy.plan_blast_radius_threshold
    if policy.cost_impact_threshold_usd is not None and not os.environ.get(
        "SCANNER_COST_IMPACT_THRESHOLD_USD"
    ):
        cfg.cost_impact_threshold_usd = policy.cost_impact_threshold_usd
    if policy.custom_rules_yaml is not None:
        cfg.custom_rules_yaml_override = policy.custom_rules_yaml
    if policy.require_second_reviewer_users:
        cfg.require_second_reviewer_users = list(policy.require_second_reviewer_users)
    if policy.require_second_reviewer_teams:
        cfg.require_second_reviewer_teams = list(policy.require_second_reviewer_teams)


def apply_waivers(findings: list[Finding], license_key: str, api_base: str) -> list[Finding]:
    """Marque comme couverte par une dérogation chaque découverte
    correspondante, en y attachant sa justification.

    L'appariement se fait par catégorie + ressource + fichier, pas par ligne —
    voir `licensing.Waiver`. Échoue ouvert : si le plan de contrôle est
    injoignable, les découvertes reviennent inchangées. Un hoquet du plan de
    contrôle ne doit jamais accorder, ni refuser, une dérogation en silence.
    """
    repo_full_name = repo_full_name_from_env()
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

    by_key = {(w.category, w.resource, w.file_path): w.justification for w in waivers}
    for f in findings:
        note = by_key.get((str(f.category), f.resource, f.file))
        if note is not None:
            f.waived = True
            f.waiver_note = note
    return findings


def report_usage(license_key: str, api_base: str, findings: list[Finding], blocked: bool) -> bool:
    """Envoie l'issue de ce scan au service de licence. Rend True quand le quota
    de l'organisation est épuisé, auquel cas l'appelant s'arrête avant de poster
    des commentaires ou d'écrire du SARIF.

    Échoue en ouvert : une panne ou une erreur réseau est journalisée mais ne
    bloque PAS le scan.
    """
    repo_full_name = repo_full_name_from_env()
    if not repo_full_name:
        _warn(
            "TFPDF_LICENSE_KEY is set but neither GITHUB_REPOSITORY nor CI_PROJECT_PATH "
            "is — skipping usage reporting for this run"
        )
        return False

    summaries = [
        licensing.FindingSummary(
            category=str(f.category),
            severity=str(f.severity),
            resource=f.resource,
            file_path=f.file,
            line=f.line,
            message=f.message,
        )
        for f in findings
    ]

    client = licensing.new_client(license_key, api_base)
    try:
        allowed, reason = client.record_scan(
            licensing.ScanResult(
                repo_full_name=repo_full_name,
                finding_count=len(findings),
                blocked=blocked,
                findings=summaries,
            )
        )
    except Exception as exc:
        _warn(f"usage reporting failed (scan still ran): {exc}")
        return False
    if not allowed:
        _warn(reason)
        return True
    return False
