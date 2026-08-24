"""La vue « pull request » : les fichiers modifiés entre deux références git.

Port de internal/diff/git.go.

**Ce module décide de ce qui est scanné.** Une sous-sélection ne produit aucune
erreur — seulement moins de découvertes — ce qui en fait le mode de défaillance
le plus silencieux du scanner. C'est pourquoi les seize tests de `git_test.go`
et `local_test.go` sont portés un pour un dans `tests/test_diff.py` : ils
couvrent les cas tordus — l'index plutôt que la copie de travail, le premier
commit, les suppressions, `.gitignore`, et `terragrunt.hcl` contre `.tf`.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
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
    base_content: bytes | None = field(default=None)


#: Ce que git refuse de faire sans qu'on le lui permette, et le message qu'il
#: rend alors. Reconnu pour pouvoir le dire à l'utilisateur en clair plutôt que
#: de le laisser passer pour autre chose.
_DUBIOUS_OWNERSHIP = b"dubious ownership"


def _git(repo_dir: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Exécute git sur `repo_dir`, en désarmant la garde de propriété.

    Git refuse d'ouvrir un dépôt qui appartient à un autre utilisateur. Dans le
    conteneur d'une GitHub Action, c'est exactement à quoi ressemble le
    workspace monté : il appartient à l'utilisateur du runner, et le conteneur
    tourne en root. Sans ce réglage, **aucun** diff n'est calculable et l'outil
    ne sert à rien.

    Le `Dockerfile` essayait déjà de le régler, et ne le pouvait pas :
    `git config --global` écrit dans `$HOME/.gitconfig` au moment de la
    construction de l'image, alors que GitHub réécrit `HOME` à l'exécution
    (`/github/home`). Le fichier existait, git ne le lisait jamais, et la
    tentative avait l'air d'une protection. C'est le pire état pour un
    correctif : présent, commenté, inopérant.

    Posé par `-c` plutôt que dans un fichier, donc : ce que reçoit ce processus
    ne dépend plus de son environnement, et rien ne subsiste après lui. Cela
    couvre aussi les usages hors image — un pip install dans un conteneur, un
    hook pre-commit — que le Dockerfile ne pouvait pas atteindre.

    `*` plutôt qu'un chemin : git résout un dépôt en remontant les répertoires,
    donc le dossier qu'on lui désigne n'est pas forcément la racine à déclarer,
    et cette racine n'est connaissable qu'en interrogeant git — ce qu'on
    n'arrive pas à faire, précisément. La portée reste étroite : ces appels ne
    font que lire, et l'utilisateur a lui-même désigné le dépôt.
    """
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


def show_file(repo_dir: str, ref: str, path: str) -> bytes | None:
    """Le contenu de `path` à la référence `ref`, ou None s'il n'y est pas.

    Une `ref` vide lit le blob de l'index (`git show :path`), c'est-à-dire le
    contenu qu'un commit contiendrait réellement — et non celui de la copie de
    travail.
    """
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
    """Tout fichier terragrunt.hcl qui diffère entre les deux références.

    Le format de configuration propre à Terragrunt (`inputs`, `remote_state`, …)
    n'est pas un fichier de ressources .tf : il lui faut donc son propre motif
    de chemin git, au lieu d'être ramassé par le glob *.tf.
    """
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
    """Tout fichier *.tf du dépôt, avec la base égale à la tête — pour un audit
    de dérive planifié sur du code déjà fusionné, et non pour un diff de PR.

    Poser la base égale à la tête fait que les règles fondées sur le diff
    (ForceNew) ne trouvent correctement rien de « changé », puisqu'il n'y a
    aucune PR contre laquelle comparer, tandis que les règles qui ne regardent
    que le contenu courant — attributs inconnus, motifs de tutoriel,
    prevent_destroy manquant — tournent à pleine puissance. C'est ce qui
    rattrape du Terraform qui était propre au moment de la fusion et ne l'est
    plus, parce que la couverture de règles et de schémas du scanner a grandi
    depuis.
    """
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
