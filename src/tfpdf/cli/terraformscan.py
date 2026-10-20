"""Select files according to the requested scan mode."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .. import diff, terragrunt, tfvars
from ..diff import ChangedFile
from ..hcl import HCLParseError
from ..report.finding import Finding
from ..rules import incomplete


@dataclass(slots=True, frozen=True)
class Mode:
    """The scan's file selection mode. The CLI rejects mutually exclusive options before
    construction.
    """

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
    """Scan changed Terragrunt files. A file that does not parse becomes a finding; any other
    failure is a warning, and the remaining files are still scanned.
    """
    findings: list[Finding] = []
    for changed_file in changed_terragrunt(repo_dir, mode):
        try:
            findings += terragrunt.scan_file(changed_file.path, changed_file.head_content)
        except HCLParseError as exc:
            findings.append(incomplete.unparsable_file(changed_file.path, exc))
        except Exception as exc:
            warn(str(exc))
    return findings


def scan_tfvars(repo_dir: str, mode: Mode, warn: Callable[[str], None]) -> list[Finding]:
    """Scan changed .tfvars and .tfvars.json files. A file that does not parse becomes a finding;
    any other failure is a warning, and the remaining files are still scanned.
    """
    findings: list[Finding] = []
    for changed_file in changed_tfvars(repo_dir, mode):
        try:
            findings += tfvars.scan_file(changed_file.path, changed_file.head_content)
        except HCLParseError as exc:
            findings.append(incomplete.unparsable_file(changed_file.path, exc))
        except ValueError as exc:
            # The JSON variable-file reader reports a syntax error as ValueError.
            findings.append(incomplete.unparsable_file(changed_file.path, exc, "JSON"))
        except Exception as exc:
            warn(str(exc))
    return findings


def changed_terraform_json(repo_dir: str, mode: Mode) -> list[ChangedFile]:
    return _select(
        mode,
        repo_dir,
        diff.staged_terraform_json_files,
        diff.uncommitted_terraform_json_files,
        diff.all_terraform_json_files,
        diff.changed_terraform_json_files,
    )


def report_terraform_json(repo_dir: str, mode: Mode) -> list[Finding]:
    """Report each changed .tf.json file as unanalysed rather than skipping it without a word."""
    return [
        incomplete.unsupported_file_format(changed_file.path)
        for changed_file in changed_terraform_json(repo_dir, mode)
    ]
