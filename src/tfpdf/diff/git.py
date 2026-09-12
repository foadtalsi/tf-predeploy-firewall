"""Collect files changed between two Git references."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# Directories excluded from full-repository traversal.
_SKIP_DIRS = frozenset({".git", ".terraform"})


class GitError(RuntimeError):
    """A failed Git command with an actionable error message."""


@dataclass(slots=True)
class ChangedFile:
    """A changed file with contents from both the base and head revisions."""

    path: str
    head_content: bytes = b""
    # None when the file did not exist in the base revision.
    base_content: bytes | None = None


# Recognize Git ownership errors so they are not misreported as missing refs.
_DUBIOUS_OWNERSHIP = b"dubious ownership"


def _git(repo_dir: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Run read-only Git commands with a nonpersistent safe.directory=* setting for mounted
    checkouts.
    """
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", repo_dir, *args],
        capture_output=True,
        check=False,
    )


def _git_lines(repo_dir: str, *args: str) -> list[str]:
    """Run a Git subcommand and return its nonempty output lines."""
    p = _git(repo_dir, *args)
    if p.returncode != 0:
        raise GitError(
            f"git {' '.join(args)}: exit {p.returncode}\n"
            + p.stderr.decode("utf-8", errors="replace").strip()
        )
    return [ln for ln in p.stdout.decode("utf-8", errors="replace").strip().split("\n") if ln]


def remote_url(repo_dir: str, remote: str = "origin") -> str:
    """Return the named remote's URL, or an empty string if unavailable."""
    process = _git(repo_dir, "remote", "get-url", remote)
    if process.returncode != 0:
        return ""
    return process.stdout.decode("utf-8", errors="replace").strip()


def show_file(repo_dir: str, ref: str, path: str) -> bytes | None:
    """Read a file at a ref, or from the index when ref is empty. Return None on failure."""
    p = _git(repo_dir, "show", f"{ref}:{path}")
    if p.returncode != 0:
        return None
    return p.stdout


def _validate_refs(repo_dir: str, base_ref: str, head_ref: str) -> None:
    """Check that both refs are available and explain shallow-clone or missing-base failures."""
    for ref in (base_ref, head_ref):
        p = _git(repo_dir, "rev-parse", "--verify", ref)
        if p.returncode != 0:
            stderr = p.stderr.decode("utf-8", errors="replace").strip()

            # A repository access failure is not a missing-ref problem; preserve the actionable
            # cause.
            if _DUBIOUS_OWNERSHIP in p.stderr:
                raise GitError(
                    "git refused to open the repository: it belongs to another "
                    "user.\n"
                    f"      Repository: {repo_dir}\n\n"
                    "      This is git's ownership guard, not a problem with your "
                    "Terraform\n"
                    "      or your workflow. It normally means the scanner is "
                    "running as a\n"
                    "      different user than the one that checked the code out.\n\n"
                    f"Original error: {stderr}"
                )

            raise GitError(
                f"git ref {ref!r} not found — cannot compute the PR diff.\n"
                f"{_build_ref_hint(repo_dir, ref)}\n"
                f"Original error: {stderr}"
            )


def _build_ref_hint(repo_dir: str, ref: str) -> str:
    # A shallow clone is a common cause of missing CI refs.
    p = _git(repo_dir, "rev-parse", "--is-shallow-repository")
    if p.returncode == 0 and p.stdout.decode().strip() == "true":
        return (
            "hint: the repository is a shallow clone.\n"
            "      Add `fetch-depth: 0` to your actions/checkout step so the base branch "
            "history is available:\n\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          fetch-depth: 0"
        )
    if ref.startswith("origin/"):
        branch = ref[len("origin/") :]
        return (
            f"hint: the remote ref {ref!r} was not fetched.\n"
            "      Make sure your workflow fetches the base branch:\n\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          fetch-depth: 0\n\n"
            "      Or fetch it explicitly:\n\n"
            f"      - run: git fetch origin {branch}"
        )
    return "hint: verify that both --base-ref and --head-ref are valid git refs in the repository."


def _changed_paths_matching(
    repo_dir: str, base_ref: str, head_ref: str, pathspec: str
) -> list[str]:
    try:
        return _git_lines(
            repo_dir, "diff", "--name-only", f"{base_ref}...{head_ref}", "--", pathspec
        )
    except GitError as exc:
        raise GitError(f"git diff failed: {exc}") from exc


def changed_terraform_files(repo_dir: str, base_ref: str, head_ref: str) -> list[ChangedFile]:
    """Collect .tf files changed between base_ref and head_ref."""
    _validate_refs(repo_dir, base_ref, head_ref)

    files: list[ChangedFile] = []
    for p in _changed_paths_matching(repo_dir, base_ref, head_ref, "*.tf"):
        if not p.endswith(".tf"):
            continue
        head = show_file(repo_dir, head_ref, p)
        if head is None:
            continue  # Deleted in head; nothing to scan.
        files.append(
            ChangedFile(path=p, head_content=head, base_content=show_file(repo_dir, base_ref, p))
        )
    return files


def changed_terragrunt_files(repo_dir: str, base_ref: str, head_ref: str) -> list[ChangedFile]:
    """Collect terragrunt.hcl files changed between the two refs."""
    _validate_refs(repo_dir, base_ref, head_ref)

    files: list[ChangedFile] = []
    for p in _changed_paths_matching(repo_dir, base_ref, head_ref, "**/terragrunt.hcl"):
        head = show_file(repo_dir, head_ref, p)
        if head is None:
            continue  # Deleted in head; nothing to scan.
        files.append(ChangedFile(path=p, head_content=head))
    return files


def _walk(repo_dir: str, matches: Callable[[Path], bool]) -> list[tuple[str, bytes]]:
    """Yield relative paths and contents of matching files under repo_dir."""
    root = Path(repo_dir)
    out: list[tuple[str, bytes]] = []
    for path in sorted(root.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not path.is_file() or not matches(path):
            continue
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise GitError(f"reading {path}: {exc}") from exc
        out.append((str(path.relative_to(root)), content))
    return out


def all_terraform_files(repo_dir: str) -> list[ChangedFile]:
    """Collect every .tf file with identical base and head contents to avoid artificial ForceNew
    changes.
    """
    return [
        ChangedFile(path=rel, head_content=content, base_content=content)
        for rel, content in _walk(repo_dir, lambda p: p.suffix == ".tf")
    ]


def all_terragrunt_files(repo_dir: str) -> list[ChangedFile]:
    """Collect every terragrunt.hcl file for a full-repository audit."""
    return [
        ChangedFile(path=rel, head_content=content)
        for rel, content in _walk(repo_dir, lambda p: p.name == "terragrunt.hcl")
    ]
