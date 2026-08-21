"""Quels fichiers un scan regarde, selon le mode demandé.

Porte les quatre commutateurs de mode répétés de
cmd/tf-predeploy-firewall/main.go.

Go écrit quatre fois le même `switch` — une fois pour les .tf, une fois pour
terragrunt.hcl, une fois pour les .tfvars, et une de plus dans le dry run —
parce que le paquet `diff` expose une fonction distincte par paire (mode, sorte
de fichier) et que Go n'a aucun moyen de nommer la paire. Il n'y a rien à gagner
à recopier cette répétition : une cinquième sorte de fichier ajoutée à trois des
quatre commutateurs est exactement le bug que cette forme invite.
"""

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
    """Scanne les fichiers terragrunt.hcl modifiés.

    Un fichier qui échoue à l'analyse est signalé et sauté, jamais fatal : un
    seul fichier inanalysable ne doit pas coûter les découvertes de tous les
    autres.
    """
    out: list[Finding] = []
    for f in changed_terragrunt(repo_dir, mode):
        try:
            out += terragrunt.scan_file(f.path, f.head_content)
        except Exception as exc:
            warn(str(exc))
    return out


def scan_tfvars(repo_dir: str, mode: Mode, warn: Callable[[str], None]) -> list[Finding]:
    """Scanne les fichiers .tfvars et .tfvars.json modifiés, même contrat que
    `scan_terragrunt`."""
    out: list[Finding] = []
    for f in changed_tfvars(repo_dir, mode):
        try:
            out += tfvars.scan_file(f.path, f.head_content)
        except Exception as exc:
            warn(str(exc))
    return out
