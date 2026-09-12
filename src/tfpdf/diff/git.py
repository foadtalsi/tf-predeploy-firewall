"""La vue « pull request » : les fichiers modifiés entre deux références git."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

#: Répertoires qu'il n'est jamais utile de parcourir lors d'un scan complet.
_SKIP_DIRS = frozenset({".git", ".terraform"})


class GitError(RuntimeError):
    """Un appel à git a échoué, avec le message dont l'utilisateur a besoin
    pour agir."""


@dataclass(slots=True)
class ChangedFile:
    """Un fichier modifié entre la base et la tête, avec le contenu des deux
    révisions."""

    path: str
    head_content: bytes = b""
    #: None quand le fichier n'existait pas dans la révision de base.
    base_content: bytes | None = None


#: Ce que git refuse de faire sans qu'on le lui permette, et le message qu'il
#: rend alors. Reconnu pour pouvoir le dire à l'utilisateur en clair plutôt que
#: de le laisser passer pour autre chose.
_DUBIOUS_OWNERSHIP = b"dubious ownership"


def _git(repo_dir: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Exécute Git en lecture avec safe.directory=* pour les dépôts montés dans un conteneur. Le
    réglage ne persiste pas."""
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", repo_dir, *args],
        capture_output=True,
        check=False,
    )


def _git_lines(repo_dir: str, *args: str) -> list[str]:
    """Exécute une sous-commande git et rend ses lignes de sortie non vides."""
    p = _git(repo_dir, *args)
    if p.returncode != 0:
        raise GitError(
            f"git {' '.join(args)}: exit {p.returncode}\n"
            + p.stderr.decode("utf-8", errors="replace").strip()
        )
    return [ln for ln in p.stdout.decode("utf-8", errors="replace").strip().split("\n") if ln]


def remote_url(repo_dir: str, remote: str = "origin") -> str:
    """L'URL du dépôt distant `remote`, ou "" s'il n'y en a pas."""
    process = _git(repo_dir, "remote", "get-url", remote)
    if process.returncode != 0:
        return ""
    return process.stdout.decode("utf-8", errors="replace").strip()


def show_file(repo_dir: str, ref: str, path: str) -> bytes | None:
    """Lit un fichier à une référence, ou l'index si ref est vide. Retourne None si la lecture
    échoue."""
    p = _git(repo_dir, "show", f"{ref}:{path}")
    if p.returncode != 0:
        return None
    return p.stdout


def _validate_refs(repo_dir: str, base_ref: str, head_ref: str) -> None:
    """Vérifie que les deux références sont atteignables, avec un indice
    lisible pour les échecs courants : clone superficiel, ou branche de base non
    récupérée."""
    for ref in (base_ref, head_ref):
        p = _git(repo_dir, "rev-parse", "--verify", ref)
        if p.returncode != 0:
            stderr = p.stderr.decode("utf-8", errors="replace").strip()

            # Quand git n'a pas pu ouvrir le dépôt du tout, la référence n'y
            # est pour rien. Le message d'origine annonçait « cette référence
            # est introuvable, pensez à fetch-depth: 0 » — sur un workflow qui
            # l'avait déjà — et reléguait la vraie cause en dernière ligne
            # sous « Original error ». On envoyait donc l'utilisateur corriger
            # ce qui était correct.
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
    # Clone superficiel : de loin la cause la plus fréquente en CI.
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
    """Tout fichier *.tf qui diffère entre `base_ref` et `head_ref`."""
    _validate_refs(repo_dir, base_ref, head_ref)

    files: list[ChangedFile] = []
    for p in _changed_paths_matching(repo_dir, base_ref, head_ref, "*.tf"):
        if not p.endswith(".tf"):
            continue
        head = show_file(repo_dir, head_ref, p)
        if head is None:
            continue  # supprimé dans la tête ; rien à scanner
        files.append(
            ChangedFile(path=p, head_content=head, base_content=show_file(repo_dir, base_ref, p))
        )
    return files


def changed_terragrunt_files(repo_dir: str, base_ref: str, head_ref: str) -> list[ChangedFile]:
    """Tout fichier terragrunt.hcl qui diffère entre les deux références."""
    _validate_refs(repo_dir, base_ref, head_ref)

    files: list[ChangedFile] = []
    for p in _changed_paths_matching(repo_dir, base_ref, head_ref, "**/terragrunt.hcl"):
        head = show_file(repo_dir, head_ref, p)
        if head is None:
            continue  # supprimé dans la tête ; rien à scanner
        files.append(ChangedFile(path=p, head_content=head))
    return files


def _walk(repo_dir: str, matches: Callable[[Path], bool]) -> list[tuple[str, bytes]]:
    """Parcourt `repo_dir` et rend (chemin relatif, contenu) pour chaque
    fichier correspondant."""
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
    """Scanne tous les .tf avec base identique à head : aucune modification ForceNew
    artificielle."""
    return [
        ChangedFile(path=rel, head_content=content, base_content=content)
        for rel, content in _walk(repo_dir, lambda p: p.suffix == ".tf")
    ]


def all_terragrunt_files(repo_dir: str) -> list[ChangedFile]:
    """Tout terragrunt.hcl du dépôt — l'équivalent terragrunt de
    `all_terraform_files`, pour l'audit de dérive planifié."""
    return [
        ChangedFile(path=rel, head_content=content)
        for rel, content in _walk(repo_dir, lambda p: p.name == "terragrunt.hcl")
    ]
