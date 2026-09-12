"""Sources de changement locales, hors pull request : l'index git pour un hook de pre-commit, et
la copie de travail pour un développeur qui demande « que dirait le pare-feu ? » avant tout
commit ou push."""

from __future__ import annotations

from pathlib import Path

from .git import ChangedFile, GitError, _git_lines, show_file


def staged_terraform_files(repo_dir: str) -> list[ChangedFile]:
    """Tout fichier .tf ayant des changements indexés : le contenu indexé comme tête, la version
    de HEAD comme base."""
    return _staged_files(repo_dir, "*.tf")


def staged_terragrunt_files(repo_dir: str) -> list[ChangedFile]:
    """`staged_terraform_files`, pour terragrunt.hcl."""
    return _staged_files(repo_dir, "**/terragrunt.hcl")


def _staged_files(repo_dir: str, pathspec: str) -> list[ChangedFile]:
    try:
        paths = _git_lines(repo_dir, "diff", "--cached", "--name-only", "--", pathspec)
    except GitError as exc:
        raise GitError(f"listing staged files: {exc}") from exc

    files: list[ChangedFile] = []
    for p in paths:
        # Une référence vide lit le blob de l'index, c'est-à-dire le contenu
        # que le commit contiendrait réellement — qui peut différer de la copie
        # de travail si l'utilisateur a indexé sélectivement (git add -p).
        # Scanner la copie de travail à la place reviendrait à juger des lignes
        # qui ne sont pas dans le commit.
        head = show_file(repo_dir, "", p)
        if head is None:
            continue  # suppression indexée ; rien à scanner
        # Au tout premier commit, HEAD n'existe pas : tous les fichiers sont
        # nouveaux.
        files.append(
            ChangedFile(path=p, head_content=head, base_content=show_file(repo_dir, "HEAD", p))
        )
    return files


def uncommitted_terraform_files(repo_dir: str) -> list[ChangedFile]:
    """Tout fichier .tf qui diffère entre la copie de travail et HEAD — indexé,
    non indexé ou non suivi indifféremment — avec le contenu sur disque comme
    tête et la version de HEAD comme base."""
    return _uncommitted_files(repo_dir, "*.tf")


def uncommitted_terragrunt_files(repo_dir: str) -> list[ChangedFile]:
    """`uncommitted_terraform_files`, pour terragrunt.hcl."""
    return _uncommitted_files(repo_dir, "**/terragrunt.hcl")


def _uncommitted_files(repo_dir: str, pathspec: str) -> list[ChangedFile]:
    # Changements suivis, indexés ou non. Sauté en silence quand HEAD n'existe
    # pas (dépôt vide) : le listage des fichiers non suivis ci-dessous est alors
    # la réponse entière.
    try:
        tracked = _git_lines(repo_dir, "diff", "--name-only", "HEAD", "--", pathspec)
    except GitError:
        tracked = []

    # Les fichiers non suivis sont les changements les plus locaux qui soient :
    # un main.tf tout neuf jamais passé par `git add` est précisément le fichier
    # sur lequel on interroge un scan local. `git diff` ne les liste jamais, il
    # leur faut donc leur propre listage — en respectant .gitignore.
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
