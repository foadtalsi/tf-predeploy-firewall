"""Port de internal/baseline/baseline_test.go, cas pour cas."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tfpdf import baseline
from tfpdf.report.finding import Category, Finding, Severity


def _finding(
    category: Category = Category.TUTORIAL_PATTERN,
    resource: str = "aws_db_instance.prod",
    file: str = "rds.tf",
    line: int = 10,
    message: str = "hardcoded credential",
) -> Finding:
    return Finding(
        file=file,
        line=line,
        category=category,
        severity=Severity.CRITICAL,
        resource=resource,
        message=message,
    )


def _write_baseline(tmp_path: Path, findings: list[Finding]) -> str:
    path = str(tmp_path / "baseline.json")
    baseline.write(path, findings, "2026-08-16T00:00:00Z")
    return path


def test_apply_accepts_pre_existing_but_not_new_findings(tmp_path: Path) -> None:
    existing = _finding()
    path = _write_baseline(tmp_path, [existing])

    b = baseline.load(path)
    assert b is not None

    brand_new = _finding(resource="aws_db_instance.staging")
    result = b.apply([_finding(), brand_new])

    assert result[0].waived is True
    assert result[0].waiver_note == "accepted in baseline"
    assert result[1].waived is False, "a finding not in the baseline must still block"


def test_apply_matches_regardless_of_line_number(tmp_path: Path) -> None:
    """Une référence qui casserait chaque fois que quelqu'un ajoute une ligne
    au-dessus serait abandonnée en une semaine."""
    path = _write_baseline(tmp_path, [_finding(line=10)])
    b = baseline.load(path)
    assert b is not None

    moved = b.apply([_finding(line=97)])
    assert moved[0].waived is True


def test_apply_does_not_match_across_categories(tmp_path: Path) -> None:
    """Même ressource, même fichier, règle différente — en accepter une ne doit
    pas accepter l'autre."""
    path = _write_baseline(tmp_path, [_finding(category=Category.TUTORIAL_PATTERN)])
    b = baseline.load(path)
    assert b is not None

    other = b.apply([_finding(category=Category.MISSING_LIFECYCLE)])
    assert other[0].waived is False


def test_stale_counts_entries_that_matched_nothing(tmp_path: Path) -> None:
    """Rapportées plutôt qu'élaguées automatiquement : jeter silencieusement
    des entrées laisserait une référence réaccepter en douce une découverte qui
    revient plus tard."""
    path = _write_baseline(
        tmp_path,
        [_finding(resource="aws_db_instance.a"), _finding(resource="aws_db_instance.b")],
    )
    b = baseline.load(path)
    assert b is not None
    assert b.size() == 2
    assert b.stale() == 2, "nothing matched yet"

    b.apply([_finding(resource="aws_db_instance.a")])
    assert b.stale() == 1


def test_load_missing_file_is_not_an_error(tmp_path: Path) -> None:
    """Pas de référence est l'état normal de la plupart des dépôts."""
    assert baseline.load(str(tmp_path / "nope.json")) is None
    assert baseline.load("") is None


def test_load_rejects_unknown_format_version(tmp_path: Path) -> None:
    """Accepter aveuglément un format futur pourrait faire taire des
    découvertes que l'auteur n'a jamais acceptées."""
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"format_version": 99, "entries": []}))
    with pytest.raises(ValueError, match="format version"):
        baseline.load(str(path))


def test_load_corrupt_file_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{not json")
    with pytest.raises(ValueError, match="parsing baseline"):
        baseline.load(str(path))


def test_write_is_deterministic_and_deduplicated(tmp_path: Path) -> None:
    """Un ordre stable, pour que régénérer un dépôt inchangé ne produise aucun
    diff."""
    findings = [
        _finding(resource="aws_db_instance.z", file="z.tf"),
        _finding(resource="aws_db_instance.a", file="a.tf"),
        _finding(resource="aws_db_instance.z", file="z.tf"),  # exact duplicate
    ]
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    baseline.write(str(first), findings, "2026-08-16T00:00:00Z")
    baseline.write(str(second), list(reversed(findings)), "2026-08-16T00:00:00Z")

    assert first.read_text() == second.read_text(), "order of input must not change output"

    doc = json.loads(first.read_text())
    assert len(doc["entries"]) == 2, "the duplicate must be collapsed"
    assert [e["file"] for e in doc["entries"]] == ["a.tf", "z.tf"]
    assert doc["format_version"] == baseline.FORMAT_VERSION
    assert doc["_note"]


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    path = _write_baseline(tmp_path, [_finding()])
    b = baseline.load(path)
    assert b is not None
    assert b.size() == 1
    assert b.apply([_finding()])[0].waived is True
