"""Test différentiel : cet analyseur contre hashicorp/hcl lui-même.

`tests/data/oracle_*.json` a été produit par `core/cmd/parserdump`, un petit
programme Go qui fait tourner l'*original* internal/parser sur les mêmes
fichiers et sérialise le résultat. Commiter sa sortie fait que la suite Python
est vérifiée contre ce que hcl fait réellement, sans aucune chaîne d'outils Go
au moment du test.

C'est le test qui compte le plus de tout le port. Chaque règle en aval consomme
le modèle Resource — un attribut dont la plage fait deux colonnes de trop, une
valeur qui s'est résolue alors qu'elle n'aurait pas dû, un heredoc désindenté du
mauvais nombre d'espaces — et une divergence ici devient une découverte fausse,
ou une découverte manquante, dans la pull request de quelqu'un. Lire les deux
analyseurs côte à côte n'attrape pas cela ; comparer 800 attributs si.

Pour régénérer après avoir changé le corpus :

    cd core && go run ./cmd/parserdump ../core-py/tests/data/corpus/*.tf \
        > ../core-py/tests/data/oracle_corpus.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from dump_parser import dump_files

DATA = Path(__file__).parent / "data"

CORPORA = [
    ("corpus", "oracle_corpus.json"),
    ("corpus_fixtures", "oracle_fixtures.json"),
]


def _normalise(v: Any) -> Any:
    """Go sérialise une tranche nulle en `null` et une tranche vide en `[]` ;
    les deux veulent dire « pas d'étiquettes ». La différence est l'encodeur JSON
    de Go, pas l'analyse."""
    return [] if v is None else v


def _walk(path: str, go: Any, py: Any, out: list[str]) -> None:
    if isinstance(go, list) or isinstance(py, list):
        go, py = _normalise(go), _normalise(py)
        if len(go) != len(py):
            out.append(f"{path}: length go={len(go)} py={len(py)}")
            return
        for i, (a, b) in enumerate(zip(go, py, strict=True)):
            _walk(f"{path}[{i}]", a, b, out)
        return
    if isinstance(go, dict) and isinstance(py, dict):
        for k in sorted(set(go) | set(py)):
            _walk(f"{path}.{k}", go.get(k), py.get(k), out)
        return
    if go != py:
        out.append(f"{path}: go={go!r} py={py!r}")


@pytest.mark.parametrize(("corpus_dir", "oracle_file"), CORPORA)
def test_matches_hashicorp_hcl(corpus_dir: str, oracle_file: str) -> None:
    oracle = json.loads((DATA / oracle_file).read_text())
    files = sorted((DATA / corpus_dir).glob("*.tf"))
    assert files, f"corpus {corpus_dir} is empty"

    ours = json.loads(json.dumps(dump_files(files)))  # round-trip for type parity

    assert [f["file"] for f in oracle] == [f["file"] for f in ours]

    diffs: list[str] = []
    for go_file, py_file in zip(oracle, ours, strict=True):
        _walk(str(go_file["file"]), go_file, py_file, diffs)

    assert not diffs, "divergence from hashicorp/hcl:\n" + "\n".join(diffs[:40])


@pytest.mark.parametrize(("corpus_dir", "oracle_file"), CORPORA)
def test_corpus_is_substantial(corpus_dir: str, oracle_file: str) -> None:
    """Un test de parité sur un oracle vide passe et ne prouve rien. Ceci
    épingle la taille du corpus, pour que supprimer une fixture soit un test qui
    échoue plutôt qu'une garantie discrètement affaiblie."""
    oracle = json.loads((DATA / oracle_file).read_text())
    resources = sum(len(f["resources"]) for f in oracle)
    attributes = sum(
        len(r["attributes"]) + sum(len(b["attributes"]) for b in r["blocks"])
        for f in oracle
        for r in f["resources"]
    )
    assert resources >= 8, f"{corpus_dir}: only {resources} resources"
    assert attributes >= 24, f"{corpus_dir}: only {attributes} attributes"
