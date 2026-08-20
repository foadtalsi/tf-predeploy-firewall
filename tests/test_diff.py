"""Port de internal/diff/git_test.go et internal/diff/local_test.go.

Ces seize tests étaient les derniers de l'arbre Go à ne pas avoir de
contrepartie ici. Ils sont les seuls du dépôt à lancer un vrai `git` sur un
vrai dépôt : c'est délibéré et non un raccourci, parce que ce que ce paquet
fait *est* d'invoquer git, et qu'un faux qui rendrait la sortie attendue de
`git diff --name-only` ne testerait que ma lecture de git.
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
    """Un dépôt temporaire : `base_tf` commité en `base_path`, puis `head_tf`
    commité en `head_path` (qui peut être le même fichier). Rend
    `(répertoire, ref de base, ref de tête)`."""
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


# --- git.py : le diff entre deux références ------------------------------


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
    assert "nonexistent-ref" in str(exc.value), "l'erreur doit nommer la mauvaise référence"


# --- git.py : le parcours du dépôt entier --------------------------------


def test_all_terraform_files_finds_every_tf_file_with_base_equal_to_head(
    tmp_path: Path,
) -> None:
    write_file(tmp_path / "main.tf", 'resource "aws_instance" "x" {}\n')
    write_file(tmp_path / "modules" / "rds" / "db.tf", 'resource "aws_db_instance" "y" {}\n')
    write_file(tmp_path / "README.md", "not terraform")
    # Un répertoire .git plein de plomberie non-.tf ne doit jamais être parcouru.
    (tmp_path / ".git" / "objects").mkdir(parents=True)

    files = all_terraform_files(str(tmp_path))

    assert len(files) == 2, files
    for f in files:
        assert f.head_content == f.base_content, (
            "un scan d'audit du dépôt entier n'a pas de « avant »"
        )


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
    """C'est l'index, pas la copie de travail, que le commit contiendra. Un
    utilisateur qui a indexé une version propre puis a continué à éditer doit
    être jugé sur ce qu'il a indexé — scanner la copie de travail bloquerait un
    commit sur des lignes qui n'y sont pas (et, pire, en laisserait passer un
    dont le contenu indexé est sale)."""
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")

    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "staged" {}\n')
    git(dir_, "add", "main.tf")
    # On continue à éditer après l'indexation.
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "worktree_only" {}\n')

    files = staged_terraform_files(dir_)

    assert len(files) == 1
    assert files[0].head_content == b'resource "aws_vpc" "staged" {}\n', (
        "la tête doit être le blob indexé"
    )
    assert files[0].base_content == b'resource "aws_vpc" "a" {}\n', (
        "la base doit être la version de HEAD"
    )


def test_staged_works_on_the_first_commit(tmp_path: Path) -> None:
    """Un hook pre-commit tourne aussi sur le tout premier commit d'un dépôt,
    où HEAD n'existe pas. Tout ce qui est indexé est simplement nouveau."""
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")

    files = staged_terraform_files(dir_)

    assert len(files) == 1
    assert files[0].base_content is None, "sans HEAD, la base doit être absente"


def test_staged_nothing_staged_means_nothing_to_scan(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")
    # Édition non indexée seulement.
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "edited" {}\n')

    assert staged_terraform_files(dir_) == [], (
        "une édition non indexée ne fait pas partie du commit"
    )


def test_staged_deletion_is_skipped(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")
    git(dir_, "rm", "-q", "main.tf")

    assert staged_terraform_files(dir_) == [], (
        "une suppression indexée n'a pas de contenu à scanner"
    )


# --- local.py : la copie de travail ----------------------------------------


def test_uncommitted_includes_untracked_staged_and_unstaged(tmp_path: Path) -> None:
    """Les fichiers non suivis sont toute la raison pour laquelle ce mode
    existe à côté de --staged : le main.tf tout neuf que personne n'a encore
    `git add` est exactement ce que « que dirait le pare-feu ? » demande."""
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "committed.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")

    write_file(tmp_path / "committed.tf", 'resource "aws_vpc" "edited" {}\n')  # non indexé
    write_file(tmp_path / "staged.tf", 'resource "aws_vpc" "s" {}\n')
    git(dir_, "add", "staged.tf")
    write_file(tmp_path / "untracked.tf", 'resource "aws_vpc" "u" {}\n')

    files = by_path(uncommitted_terraform_files(dir_))

    assert set(files) == {"committed.tf", "staged.tf", "untracked.tf"}
    assert files["committed.tf"].head_content == b'resource "aws_vpc" "edited" {}\n', (
        "la tête doit être le contenu de la copie de travail"
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
    # Les caches de fournisseurs contiennent des .tf vendus ; les scanner
    # enterrerait les découvertes de l'utilisateur sous un arbre de modules
    # qui ne lui appartient pas.
    write_file(
        tmp_path / ".terraform" / "modules" / "x" / "main.tf",
        'resource "aws_db_instance" "p" { password = "x" }\n',
    )

    assert uncommitted_terraform_files(dir_) == [], (
        "les fichiers ignorés par git ne doivent pas être scannés"
    )


def test_uncommitted_clean_tree_finds_nothing(tmp_path: Path) -> None:
    dir_ = git_repo(tmp_path)
    write_file(tmp_path / "main.tf", 'resource "aws_vpc" "a" {}\n')
    git(dir_, "add", ".")
    git(dir_, "commit", "-qm", "init")

    assert uncommitted_terraform_files(dir_) == []
