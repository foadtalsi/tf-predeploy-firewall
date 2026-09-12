"""Compare normalized parser output with frozen historical hashicorp/hcl oracles.

Committed fixtures let these tests run without Go. Preserve their provenance:
changes to the corpus or expected values need independent verification, not
regeneration from the Python implementation being tested.
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
    """Normalize null and empty label lists, which represent the same parsed structure."""
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
    """Keep the corpus substantial so deleting fixtures cannot silently weaken parity coverage."""
    oracle = json.loads((DATA / oracle_file).read_text())
    resources = sum(len(f["resources"]) for f in oracle)
    attributes = sum(
        len(r["attributes"]) + sum(len(b["attributes"]) for b in r["blocks"])
        for f in oracle
        for r in f["resources"]
    )
    assert resources >= 8, f"{corpus_dir}: only {resources} resources"
    assert attributes >= 24, f"{corpus_dir}: only {attributes} attributes"
