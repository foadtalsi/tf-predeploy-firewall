"""Read staged or working-tree changes for local scans before a commit or push."""

from __future__ import annotations

from pathlib import Path

from .git import ChangedFile, GitError, _git_lines, show_file


def staged_terraform_files(repo_dir: str) -> list[ChangedFile]:
    """Collect staged .tf files with index contents as head and HEAD contents as base."""
    return _staged_files(repo_dir, "*.tf")


def staged_terragrunt_files(repo_dir: str) -> list[ChangedFile]:
    """Collect staged terragrunt.hcl files using the same semantics as staged_terraform_files."""
    return _staged_files(repo_dir, "**/terragrunt.hcl")


def _staged_files(repo_dir: str, pathspec: str) -> list[ChangedFile]:
    try:
        paths = _git_lines(repo_dir, "diff", "--cached", "--name-only", "--", pathspec)
    except GitError as exc:
        raise GitError(f"listing staged files: {exc}") from exc

    files: list[ChangedFile] = []
    for p in paths:
        # An empty ref reads the index, not the working tree, preserving selectively staged
        # contents.
        head = show_file(repo_dir, "", p)
        if head is None:
            continue  # Staged deletions have no content to scan. Without HEAD, remaining staged files are new.
        files.append(
            ChangedFile(path=p, head_content=head, base_content=show_file(repo_dir, "HEAD", p))
        )
    return files


def uncommitted_terraform_files(repo_dir: str) -> list[ChangedFile]:
    """Collect .tf files differing from HEAD, including untracked files, using on-disk contents as
    head.
    """
    return _uncommitted_files(repo_dir, "*.tf")


def uncommitted_terragrunt_files(repo_dir: str) -> list[ChangedFile]:
    """Collect working-tree terragrunt.hcl changes using the same semantics as
    uncommitted_terraform_files.
    """
    return _uncommitted_files(repo_dir, "**/terragrunt.hcl")


def _uncommitted_files(repo_dir: str, pathspec: str) -> list[ChangedFile]:
    # Collect tracked changes when HEAD exists; untracked-file collection covers an empty
    # repository.
    try:
        tracked = _git_lines(repo_dir, "diff", "--name-only", "HEAD", "--", pathspec)
    except GitError:
        tracked = []

    # Git diff omits untracked files, so collect them separately while respecting .gitignore.
    try:
        untracked = _git_lines(
            repo_dir, "ls-files", "--others", "--exclude-standard", "--", pathspec
        )
    except GitError as exc:
        raise GitError(f"listing untracked files: {exc}") from exc

    files: list[ChangedFile] = []
    for p in dict.fromkeys(tracked + untracked):
        try:
            head = (Path(repo_dir) / p).read_bytes()
        except OSError:
            continue  # deleted in the worktree; nothing to scan
        files.append(
            ChangedFile(path=p, head_content=head, base_content=show_file(repo_dir, "HEAD", p))
        )
    return files
