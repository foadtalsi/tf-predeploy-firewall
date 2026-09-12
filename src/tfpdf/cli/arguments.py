"""Déclaration des options CLI et de leurs valeurs par défaut."""

from __future__ import annotations

import argparse
import os

from .forges import default_base_ref, default_post_comment

_LICENSE_API_BASE_DEFAULT = "https://api.tfpredeployfirewall.com"

CLI_DESCRIPTION = "Le CLI de TF Pre-Deploy Firewall.\n\nPort de cmd/tf-predeploy-firewall/main.go.\n\nScanne les fichiers .tf modifiés entre deux références git, rapporte les\ndécouvertes de risque, et éventuellement poste ou met à jour un commentaire de\nPR et conditionne le code de sortie à un seuil de sévérité.\n\nCodes de sortie, inchangés depuis la version Go parce que des CI en dépendent :\n\n    0  exécuté, rien au niveau du seuil de blocage ni au-dessus\n    1  bloqué — une découverte a atteint le seuil\n    2  le scan n'a pas pu tourner (mauvais drapeaux, config illisible, échec git)\n    3  le quota du plan de l'organisation est épuisé\n"


def _env_or(key: str, fallback: str) -> str:
    return os.environ.get(key) or fallback


def _go_bool(value: str) -> bool:
    """`strconv.ParseBool`, pour une valeur attachée à un drapeau booléen."""
    if value in ("1", "t", "T", "true", "TRUE", "True"):
        return True
    if value in ("0", "f", "F", "false", "FALSE", "False"):
        return False
    raise argparse.ArgumentTypeError(f"must be true or false, got {value!r}")


def build_parser() -> argparse.ArgumentParser:
    """Le jeu de drapeaux, correspondant exactement aux noms et défauts de la
    version Go.

    Les booléens prennent une valeur attachée *optionnelle* au lieu d'être en
    `store_true`, parce qu'`action.yml` passe `--full-repo-scan=false`. Voir
    `goflags`.
    """
    parser = argparse.ArgumentParser(
        prog="tf-predeploy-firewall",
        description=CLI_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    def flag_bool(name: str, default: bool, help_: str) -> None:
        parser.add_argument(name, nargs="?", const=True, default=default, type=_go_bool, help=help_)

    parser.add_argument("--repo-dir", default=".", help="path to the git repository to scan")
    parser.add_argument(
        "--base-ref",
        default=default_base_ref(),
        help="git ref to diff against (PR/MR base)",
    )
    parser.add_argument("--head-ref", default="HEAD", help="git ref containing the changes")
    flag_bool(
        "--full-repo-scan",
        False,
        "scan every .tf file in repo-dir instead of just the PR diff — for a scheduled "
        "drift audit of already-merged code (e.g. cron), not a PR check. ForceNew-change "
        "detection naturally finds nothing (there's no diff), but unknown-attribute, "
        "tutorial-pattern and missing-lifecycle findings run at full strength against "
        "current content.",
    )
    parser.add_argument(
        "--config",
        default=_env_or("SCANNER_CONFIG", "config/default.yml"),
        help="path to YAML config",
    )
    flag_bool(
        "--post-comment",
        default_post_comment(),
        "post/update a PR/MR comment with the results",
    )
    parser.add_argument(
        "--sarif-output",
        default="",
        help="write SARIF 2.1.0 JSON to this file (for GitHub Code Scanning)",
    )
    parser.add_argument(
        "--codequality-output",
        default="",
        help="write a GitLab Code Quality report to this file — declare it under "
        "artifacts:reports:codequality and findings render in the MR widget, no token "
        "needed",
    )
    parser.add_argument(
        "--format",
        default=_env_or("TFPDF_FORMAT", "auto"),
        choices=("auto", "text", "markdown"),
        help='how the report is printed to stdout. "auto" (default) picks the compact '
        "text layout when stdout is a terminal and the PR-comment markdown otherwise, so "
        "redirecting or piping keeps the format every existing script expects. The PR "
        "comment, SARIF and Code Quality outputs are unaffected either way.",
    )
    parser.add_argument(
        "--plan-json",
        default="",
        help="path to `terraform show -json <planfile>` output (phase 2: adds "
        "confirmed-replace, drift and blast-radius findings). Optional — this tool never "
        "runs terraform itself; you run the plan, it only reads the file.",
    )
    flag_bool(
        "--cloud-read-access",
        _env_or("TFPDF_CLOUD_READ_ACCESS", "") == "true",
        "use the workflow's existing cloud credentials to read whether the resources a "
        "finding is about already exist, and how much they hold, so severity reflects "
        "the real account instead of the source alone. Off by default, and the whole "
        "scanner works without it. Only ever reads (sts:GetCallerIdentity, "
        "s3:ListObjectsV2 — see docs/cloud-read-access.md for the IAM policy); missing "
        "or refused credentials leave every severity untouched rather than failing the "
        "scan.",
    )
    parser.add_argument(
        "--license-key",
        default=_env_or("TFPDF_LICENSE_KEY", ""),
        help="paid-plan API key. Entirely optional — leave unset to run the scanner "
        "exactly as the free, open-source tool it has always been.",
    )
    parser.add_argument(
        "--repo-name",
        default=_env_or("TFPDF_REPO_NAME", ""),
        help='the "owner/repo" this scan is reported under, for usage, waivers and org '
        "policy. Only read with a license key. Normally resolved on its own — from "
        "GITHUB_REPOSITORY or CI_PROJECT_PATH on CI, and from the origin remote "
        "otherwise — so pass this only when neither is right.",
    )
    parser.add_argument(
        "--license-api-base",
        default=_env_or("TFPDF_LICENSE_API_BASE", _LICENSE_API_BASE_DEFAULT),
        help="control-plane API base URL, override for self-hosted/staging deployments",
    )
    parser.add_argument(
        "--baseline",
        default=_env_or("TFPDF_BASELINE", ""),
        help="path to a committed baseline file of accepted pre-existing findings. They "
        "stay visible in the PR comment but don't block a merge; anything new does. "
        "Missing file = no baseline.",
    )
    parser.add_argument(
        "--write-baseline",
        default="",
        help="write the current findings to this path as the new baseline and exit "
        "without failing. Run once when adopting the scanner on an existing repo, then "
        "commit the file.",
    )
    parser.add_argument(
        "--providers",
        default=_env_or("TFPDF_PROVIDERS", "auto"),
        help='comma-separated providers to fetch extended rule packs for ("aws,azurerm"), '
        'or "auto" to detect them from the resource types in the scanned files.',
    )
    flag_bool(
        "--staged",
        False,
        "scan the staged changes (git index vs HEAD) instead of a ref diff — what a "
        "pre-commit hook wants: the findings arrive before the secret enters history, "
        "while removing it is still an edit and not a rotation",
    )
    flag_bool(
        "--uncommitted",
        False,
        "scan working-tree changes vs HEAD — staged, unstaged and untracked .tf files "
        'alike. The "what would the firewall say?" mode for local use, no refs needed',
    )
    flag_bool(
        "--rules-dry-run",
        False,
        "test the config's custom_rules against the whole repo without failing anything: "
        "prints what each rule matched (including 'matched nothing', which is what a rule "
        "author most needs to see) and exits 0.",
    )
    parser.add_argument(
        "--rules",
        default=_env_or("TFPDF_RULES", ""),
        help="path to a rule pack (YAML) to use INSTEAD of the built-in one. Start from "
        "--print-rules rather than a blank file.",
    )
    flag_bool(
        "--print-rules",
        False,
        "print the built-in rule pack to stdout and exit — the starting point for a "
        '--rules file, and the honest answer to "what exactly does this thing look for?"',
    )
    flag_bool("--version", False, "print the version and exit")
    return parser
