"""Collect Terraform JSON configuration files (.tf.json) for each of the scanner's four scan modes.

The scanner does not analyse this syntax. The files are collected so that each one can be
reported as unanalysed, rather than left out of the report without a word.
"""

from __future__ import annotations

from .git import ChangedFile, _changed_paths_matching, _validate_refs, _walk, show_file
from .local import _staged_files, _uncommitted_files

TERRAFORM_JSON_PATHSPEC = "*.tf.json"


def is_terraform_json(path: str) -> bool:
    """Match Terraform JSON paths when Git is not performing the path filtering."""
    return path.endswith(".tf.json")


def changed_terraform_json_files(repo_dir: str, base_ref: str, head_ref: str) -> list[ChangedFile]:
    """Collect .tf.json files changed between base_ref and head_ref."""
    _validate_refs(repo_dir, base_ref, head_ref)

    files: list[ChangedFile] = []
    for path in _changed_paths_matching(repo_dir, base_ref, head_ref, TERRAFORM_JSON_PATHSPEC):
        head = show_file(repo_dir, head_ref, path)
        if head is None:
            continue  # deleted at head; nothing to scan
        files.append(ChangedFile(path=path, head_content=head))
    return files


def staged_terraform_json_files(repo_dir: str) -> list[ChangedFile]:
    """Collect staged .tf.json changes."""
    return _staged_files(repo_dir, TERRAFORM_JSON_PATHSPEC)


def uncommitted_terraform_json_files(repo_dir: str) -> list[ChangedFile]:
    """Collect .tf.json files differing from HEAD, including untracked files."""
    return _uncommitted_files(repo_dir, TERRAFORM_JSON_PATHSPEC)


def all_terraform_json_files(repo_dir: str) -> list[ChangedFile]:
    """Collect every .tf.json file for a full-repository audit."""
    return [
        ChangedFile(path=relative_path, head_content=content)
        for relative_path, content in _walk(repo_dir, lambda path: is_terraform_json(path.name))
    ]
