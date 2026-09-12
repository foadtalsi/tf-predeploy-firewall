"""Quels fichiers un scan regarde, selon le mode demandé."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .. import diff, terragrunt, tfvars
from ..diff import ChangedFile
from ..report.finding import Finding


@dataclass(slots=True, frozen=True)
class Mode:
    """Quel ensemble de fichiers cette exécution scanne. Les trois booléens
    sont mutuellement exclusifs ; le CLI en rejette plus d'un avant de construire
    ceci."""

    staged: bool = False
    uncommitted: bool = False
    full_repo: bool = False
    base_ref: str = "origin/main"
    head_ref: str = "HEAD"


def _select(
    mode: Mode,
    repo_dir: str,
    staged: Callable[[str], list[ChangedFile]],
    uncommitted: Callable[[str], list[ChangedFile]],
    full_repo: Callable[[str], list[ChangedFile]],
    ref_diff: Callable[[str, str, str], list[ChangedFile]],
) -> list[ChangedFile]:
    if mode.staged:
        return staged(repo_dir)
    if mode.uncommitted:
        return uncommitted(repo_dir)
    if mode.full_repo:
        return full_repo(repo_dir)
    return ref_diff(repo_dir, mode.base_ref, mode.head_ref)


def changed_terraform(repo_dir: str, mode: Mode) -> list[ChangedFile]:
    return _select(
        mode,
        repo_dir,
        diff.staged_terraform_files,
        diff.uncommitted_terraform_files,
        diff.all_terraform_files,
        diff.changed_terraform_files,
    )


def changed_terragrunt(repo_dir: str, mode: Mode) -> list[ChangedFile]:
    return _select(
        mode,
        repo_dir,
        diff.staged_terragrunt_files,
        diff.uncommitted_terragrunt_files,
        diff.all_terragrunt_files,
        diff.changed_terragrunt_files,
    )


def changed_tfvars(repo_dir: str, mode: Mode) -> list[ChangedFile]:
    return _select(
        mode,
        repo_dir,
        diff.staged_tfvars_files,
        diff.uncommitted_tfvars_files,
        diff.all_tfvars_files,
        diff.changed_tfvars_files,
    )


def scan_terragrunt(repo_dir: str, mode: Mode, warn: Callable[[str], None]) -> list[Finding]:
    """Scanne les fichiers Terragrunt modifiés ; avertit et poursuit si un fichier échoue."""
    findings: list[Finding] = []
    for changed_file in changed_terragrunt(repo_dir, mode):
        try:
            findings += terragrunt.scan_file(changed_file.path, changed_file.head_content)
        except Exception as exc:
            warn(str(exc))
    return findings


def scan_tfvars(repo_dir: str, mode: Mode, warn: Callable[[str], None]) -> list[Finding]:
    """Scanne les fichiers .tfvars et .tfvars.json modifiés, même contrat que
    `scan_terragrunt`."""
    findings: list[Finding] = []
    for changed_file in changed_tfvars(repo_dir, mode):
        try:
            findings += tfvars.scan_file(changed_file.path, changed_file.head_content)
        except Exception as exc:
            warn(str(exc))
    return findings
