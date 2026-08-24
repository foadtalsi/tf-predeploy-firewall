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


def _warn(message: str) -> None:
    print("tf-predeploy-firewall: " + message, file=sys.stderr)


def apply_org_policy(
    config: Config, license_key: str, api_base: str, repo_full_name: str = ""
) -> None:
    """Récupère la politique Growth gérée centralement pour l'organisation, s'il
    y en a une, et la fusionne sur `cfg` sur place.

    Priorité, du plus faible au plus fort : config.yml du dépôt < politique de
    l'organisation < variable d'environnement. Un opérateur peut donc toujours
    forcer un réglage localement par variable d'environnement, même quand une
    politique d'organisation existe — une échappatoire délibérée, pas un oubli.
    """
    client = licensing.new_client(license_key, api_base)
    try:
        policy = client.get_policy(repo_full_name)
    except Exception as exc:
        _warn(f"fetching org policy failed, using local config ({exc})")
        return
    if policy is None:
        return

    if policy.block_threshold is not None and not os.environ.get("SCANNER_BLOCK_THRESHOLD"):
        config.block_threshold = policy.block_threshold
    if policy.ignore_rules:
        # Centralized policy replaces the repo-local ignore list rather than
        # merging with it — the whole point of a team policy is that a single
        # repo's config.yml can't quietly opt out of it.
        config.ignore_rules = list(policy.ignore_rules)
    if policy.plan_blast_radius_threshold is not None and not os.environ.get(
        "SCANNER_PLAN_BLAST_RADIUS_THRESHOLD"
    ):
        config.plan_blast_radius_threshold = policy.plan_blast_radius_threshold
    if policy.cost_impact_threshold_usd is not None and not os.environ.get(
        "SCANNER_COST_IMPACT_THRESHOLD_USD"
    ):
        config.cost_impact_threshold_usd = policy.cost_impact_threshold_usd
    if policy.custom_rules_yaml is not None:
        config.custom_rules_yaml_override = policy.custom_rules_yaml
    if policy.require_second_reviewer_users:
        config.require_second_reviewer_users = list(policy.require_second_reviewer_users)
    if policy.require_second_reviewer_teams:
        config.require_second_reviewer_teams = list(policy.require_second_reviewer_teams)


def apply_waivers(
    findings: list[Finding], license_key: str, api_base: str, repo_full_name: str = ""
) -> list[Finding]:
    """Marque comme couverte par une dérogation chaque découverte
    correspondante, en y attachant sa justification.

    L'appariement se fait par catégorie + ressource + fichier, pas par ligne —
    voir `licensing.Waiver`. Échoue ouvert : si le plan de contrôle est
    injoignable, les découvertes reviennent inchangées. Un hoquet du plan de
    contrôle ne doit jamais accorder, ni refuser, une dérogation en silence.
    """
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


def report_usage(
    license_key: str,
    api_base: str,
    findings: list[Finding],
    blocked: bool,
    repo_full_name: str = "",
) -> bool:
    """Envoie l'issue de ce scan au service de licence. Rend True quand le quota
    de l'organisation est épuisé, auquel cas l'appelant s'arrête avant de poster
    des commentaires ou d'écrire du SARIF.

    Échoue en ouvert : une panne ou une erreur réseau est journalisée mais ne
    bloque PAS le scan.
    """
    if not repo_full_name:
        # Le seul chemin qui laisse encore un scan non rapporté : ni CI, ni
        # distant git exploitable, ni --repo-name. Il se dit à voix haute,
        # parce qu'un scan silencieusement hors quota est un écart entre ce que
        # l'organisation consomme et ce que son tableau de bord montre.
        _warn(
            "TFPDF_LICENSE_KEY is set but this scan has no repository name — no "
            "GITHUB_REPOSITORY or CI_PROJECT_PATH, and no usable git remote. This scan "
            "will NOT be counted against your plan; pass --repo-name owner/repo (or set "
            "TFPDF_REPO_NAME) to record it."
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
