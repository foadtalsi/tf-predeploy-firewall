"""Exercise file selection against real temporary Git repositories, including index and
working-tree differences.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tfpdf.diff import (
    ChangedFile,
    all_terraform_files,
    all_terragrunt_files,
    changed_terraform_files,
    changed_terragrunt_files,
    staged_terraform_files,
    uncommitted_terraform_files,
)

BASE_TF = """
resource "aws_instance" "base" {
  ami = "ami-base"
}
"""

HEAD_TF = """
resource "aws_instance" "head" {
  ami = "ami-head"
}
"""


def git(dir_: str, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "t@t.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "t@t.com",
    }
    proc = subprocess.run(["git", "-C", dir_, *args], capture_output=True, env=env, check=False)
    if proc.returncode != 0:
        raise AssertionError(
            f"git {args}: {proc.returncode}\n{proc.stdout.decode()}{proc.stderr.decode()}"
        )


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def git_repo(tmp_path: Path) -> str:
    dir_ = str(tmp_path)
    git(dir_, "init", "-q", "-b", "main")
    git(dir_, "config", "user.email", "t@t.com")
    git(dir_, "config", "user.name", "test")
    return dir_


def make_repo(
    tmp_path: Path, base_path: str, base_tf: str, head_path: str, head_tf: str
) -> tuple[str, str, str]:
    """Commit base_tf at base_path and head_tf at head_path; return (directory, base ref, head
    ref).
    """
    dir_ = git_repo(tmp_path)

    write_file(tmp_path / base_path, base_tf)
    git(dir_, "add", ".")
    git(dir_, "commit", "-m", "base")

    write_file(tmp_path / head_path, head_tf)
    git(dir_, "add", ".")
    git(dir_, "commit", "-m", "head")

    return dir_, "HEAD~1", "HEAD"


def by_path(files: list[ChangedFile]) -> dict[str, ChangedFile]:
    return {f.path: f for f in files}


# Git changes between two refs.


def test_changed_terraform_files_basic_diff(tmp_path: Path) -> None:
    dir_, base, head = make_repo(tmp_path, "main.tf", BASE_TF, "main.tf", HEAD_TF)

    files = changed_terraform_files(dir_, base, head)

    assert len(files) == 1
    assert files[0].path == "main.tf"
    assert b"ami-head" in files[0].head_content
    assert files[0].base_content is not None
    assert b"ami-base" in files[0].base_content


def test_changed_terraform_files_new_file(tmp_path: Path) -> None:
    dir_, base, head = make_repo(tmp_path, "existing.tf", BASE_TF, "new.tf", HEAD_TF)

    files = changed_terraform_files(dir_, base, head)

    assert [f.path for f in files] == ["new.tf"]
    assert files[0].base_content is None, "un fichier tout neuf n'a pas de contenu de base"


def test_changed_terraform_files_non_tf_files_ignored(tmp_path: Path) -> None:
    dir_, base, head = make_repo(tmp_path, "README.md", "# base", "README.md", "# head")

    assert changed_terraform_files(dir_, base, head) == []


def test_changed_terraform_files_subdirectory_tf(tmp_path: Path) -> None:
    dir_, base, head = make_repo(
        tmp_path, "modules/rds/main.tf", BASE_TF, "modules/rds/main.tf", HEAD_TF
    )

    files = changed_terraform_files(dir_, base, head)

    assert [f.path for f in files] == ["modules/rds/main.tf"]


def test_changed_terraform_files_invalid_ref(tmp_path: Path) -> None:
    dir_, _, _ = make_repo(tmp_path, "main.tf", BASE_TF, "main.tf", HEAD_TF)

    with pytest.raises(Exception) as exc:
        changed_terraform_files(dir_, "nonexistent-ref", "HEAD")
    assert "nonexistent-ref" in str(exc.value), "the error must name the missing ref"


# Full-repository traversal.


def test_all_terraform_files_finds_every_tf_file_with_base_equal_to_head(
    tmp_path: Path,
) -> None:
    write_file(tmp_path / "main.tf", 'resource "aws_instance" "x" {}\n')
    write_file(tmp_path / "modules" / "rds" / "db.tf", 'resource "aws_db_instance" "y" {}\n')
    write_file(tmp_path / "README.md", "not terraform")
    # Never traverse Git's internal metadata directory.
    (tmp_path / ".git" / "objects").mkdir(parents=True)

    files = all_terraform_files(str(tmp_path))

    assert len(files) == 2, files
    for f in files:
        assert f.head_content == f.base_content, "a full-repository audit has no previous revision"


def test_all_terragrunt_files_finds_every_terragrunt_hcl(tmp_path: Path) -> None:
    write_file(tmp_path / "live" / "prod" / "terragrunt.hcl", "inputs = {}")
    write_file(tmp_path / "live" / "staging" / "terragrunt.hcl", "inputs = {}")
    write_file(tmp_path / "modules" / "rds" / "main.tf", 'resource "aws_db_instance" "x" {}')

    assert len(all_terragrunt_files(str(tmp_path))) == 2


# --- git.py : terragrunt ---------------------------------------------------


def test_changed_terragrunt_files_picks_up_terragrunt_hcl_not_tf(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)

    write_file(tmp_path / "live" / "prod" / "terragrunt.hcl", 'inputs = { environment = "base" }')
    git(dir_, "add", ".")
    git(dir_, "commit", "-m", "base")

    write_file(tmp_path / "live" / "prod" / "terragrunt.hcl", 'inputs = { environment = "prod" }')
    git(dir_, "add", ".")
    git(dir_, "commit", "-m", "head")

    files = changed_terragrunt_files(dir_, "HEAD~1", "HEAD")

    assert [f.path for f in files] == ["live/prod/terragrunt.hcl"]
    assert b'"prod"' in files[0].head_content


def test_changed_terragrunt_files_ignores_tf_files(tmp_path: Path) -> None:
    dir_, base, head = make_repo(tmp_path, "main.tf", BASE_TF, "main.tf", HEAD_TF)

    assert changed_terragrunt_files(dir_, base, head) == []


# --- local.py : l'index ----------------------------------------------------


def test_staged_scans_the_index_not_the_worktree(tmp_path: Path) -> None:
    """Scan staged contents, which can differ from the working tree after selective staging."""
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")

    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "staged" {}\n')
    git(dir_, "add", "main.tf")
    # Continue editing after staging.
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "worktree_only" {}\n')

    files = staged_terraform_files(dir_)

    assert len(files) == 1
    assert files[0].head_content == b'resource "aws_vpc" "staged" {}\n', (
        "head contents must come from the index"
    )
    assert files[0].base_content == b'resource "aws_vpc" "a" {}\n', (
        "base contents must come from HEAD"
    )


def test_staged_works_on_the_first_commit(tmp_path: Path) -> None:
    """A first commit has no HEAD; all staged files are new."""
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")

    files = staged_terraform_files(dir_)

    assert len(files) == 1
    assert files[0].base_content is None, "without HEAD, base contents must be absent"


def test_staged_nothing_staged_means_nothing_to_scan(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")
    # Unstaged change only.
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "edited" {}\n')

    assert staged_terraform_files(dir_) == [], "unstaged changes do not belong to the commit"


def test_staged_deletion_is_skipped(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")
    git(dir_, "rm", "-q", "main.tf")

    assert staged_terraform_files(dir_) == [], "staged deletions have no contents to scan"


# Working-tree file selection.


def test_uncommitted_includes_untracked_staged_and_unstaged(tmp_path: Path) -> None:
    """Local scans must include untracked files as well as staged and unstaged changes."""
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "committed.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")

    write_file(tmp_path / "committed.tf", 'resource "aws_vpc" "edited" {}\n')  # Unstaged.
    write_file(tmp_path / "staged.tf", 'resource "aws_vpc" "s" {}\n')
    git(dir_, "add", "staged.tf")
    write_file(tmp_path / "untracked.tf", 'resource "aws_vpc" "u" {}\n')

    files = by_path(uncommitted_terraform_files(dir_))

    assert set(files) == {"committed.tf", "staged.tf", "untracked.tf"}
    assert files["committed.tf"].head_content == b'resource "aws_vpc" "edited" {}\n', (
        "head contents must come from the working tree"
    )
    assert files["committed.tf"].base_content is not None, (
        "un fichier suivi doit porter la version de HEAD comme base"
    )
    assert files["untracked.tf"].base_content is None, "un fichier non suivi n'a pas de base"


def test_uncommitted_respects_gitignore(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / ".gitignore", ".terraform/\n")
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")
    # Skip provider caches so vendored Terraform does not drown out the repository's own
    # findings.
    write_file(
        tmp_path / ".terraform" / "modules" / "x" / "main.tf",
        'resource "aws_db_instance" "p" { password = "x" }\n',
    )

    assert uncommitted_terraform_files(dir_) == [], "Git-ignored files must not be scanned"


def test_uncommitted_clean_tree_finds_nothing(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")

    assert uncommitted_terraform_files(dir_) == []


# Per-command Git ownership handling for container-mounted checkouts.


def test_every_git_call_disarms_the_ownership_guard() -> None:
    """Check the per-command ownership override used for container-mounted Git checkouts."""
    import subprocess
    from unittest import mock

    from tfpdf.diff import git as gitmod

    with mock.patch.object(gitmod.subprocess, "run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
        gitmod._git("/un/depot", "rev-parse", "HEAD")

    argv = run.call_args[0][0]
    assert argv[:4] == ["git", "-c", "safe.directory=*", "-C"], (
        "pass the override with -c; build-time global config is lost when "
        "GitHub replaces HOME at runtime"
    )
    assert argv[4] == "/un/depot"
    assert argv[5:] == ["rev-parse", "HEAD"]


def test_an_ownership_refusal_is_reported_as_itself(tmp_path) -> None:
    """Report repository ownership failures directly instead of suggesting a missing-ref fix."""
    import subprocess
    from unittest import mock

    from tfpdf.diff import git as gitmod

    refus = subprocess.CompletedProcess(
        [], 128, b"", b"fatal: detected dubious ownership in repository at '/github/workspace'"
    )
    with (
        mock.patch.object(gitmod, "_git", return_value=refus),
        pytest.raises(gitmod.GitError) as levee,
    ):
        gitmod._validate_refs(str(tmp_path), "origin/main", "HEAD")

    message = str(levee.value)
    assert "belongs to another user" in message
    assert "fetch-depth" not in message, "ne pas conseiller un correctif sans rapport"


def test_a_genuinely_missing_ref_still_says_so(tmp_path) -> None:
    """Preserve useful diagnostics for an actually missing ref."""
    import subprocess
    from unittest import mock

    from tfpdf.diff import git as gitmod

    absente = subprocess.CompletedProcess([], 128, b"", b"fatal: Needed a single revision")
    with (
        mock.patch.object(gitmod, "_git", return_value=absente),
        pytest.raises(gitmod.GitError) as levee,
    ):
        gitmod._validate_refs(str(tmp_path), "origin/main", "HEAD")

    assert "not found" in str(levee.value)
