"""Collecte des fichiers .tfvars, dans chacun des quatre modes du scanner.

Port de internal/diff/tfvars.go.

Il leur faut leurs propres motifs de chemin parce que le glob « *.tf » ne les
attrape pas, et parce que deux formes sont en usage : terraform.tfvars et
*.auto.tfvars (HCL), plus leurs équivalents .json.
"""

from __future__ import annotations

from collections.abc import Callable

from .git import ChangedFile, _changed_paths_matching, _validate_refs, _walk, show_file
from .local import _staged_files, _uncommitted_files

TFVARS_PATHSPECS = ("*.tfvars", "*.tfvars.json")


def is_tfvars(path: str) -> bool:
    """Reproduit les motifs de chemin ci-dessus pour les modes fondés sur le
    parcours et sur la copie de travail, où git ne fait pas la correspondance à
    notre place."""
    return path.endswith((".tfvars", ".tfvars.json"))


def changed_tfvars_files(repo_dir: str, base_ref: str, head_ref: str) -> list[ChangedFile]:
    """Tout fichier .tfvars qui diffère entre `base_ref` et `head_ref`."""
    _validate_refs(repo_dir, base_ref, head_ref)

    seen: set[str] = set()
    files: list[ChangedFile] = []
    for spec in TFVARS_PATHSPECS:
        for p in _changed_paths_matching(repo_dir, base_ref, head_ref, spec):
            if p in seen:
                continue
            seen.add(p)
            head = show_file(repo_dir, head_ref, p)
            if head is None:
                continue  # deleted at head; nothing to scan
            files.append(ChangedFile(path=p, head_content=head))
    return files


def staged_tfvars_files(repo_dir: str) -> list[ChangedFile]:
    """Tout fichier .tfvars ayant des changements indexés."""
    return _multi_spec(repo_dir, _staged_files)


def uncommitted_tfvars_files(repo_dir: str) -> list[ChangedFile]:
    """Tout fichier .tfvars différant de HEAD dans la copie de travail, les non
    suivis compris.

    Le non-suivi compte ici plus que partout ailleurs : tout l'intérêt d'une
    vérification de pre-commit sur un fichier .tfvars est d'attraper le secret à
    l'instant qui précède le `git add` qui en ferait une part du dépôt.
    """
    return _multi_spec(repo_dir, _uncommitted_files)


def _multi_spec(
    repo_dir: str, collect: Callable[[str, str], list[ChangedFile]]
) -> list[ChangedFile]:
    seen: set[str] = set()
    out: list[ChangedFile] = []
    for spec in TFVARS_PATHSPECS:
        for f in collect(repo_dir, spec):
            if f.path in seen:
                continue
            seen.add(f.path)
            out.append(f)
    return out


def all_tfvars_files(repo_dir: str) -> list[ChangedFile]:
    """Tout fichier .tfvars du dépôt — l'équivalent du scan complet, pour un
    audit planifié de code déjà fusionné."""
    return [
        ChangedFile(path=rel, head_content=content)
        for rel, content in _walk(repo_dir, lambda p: is_tfvars(p.name))
    ]
