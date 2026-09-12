"""Baseline persistence and matching regression tests."""

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
    """Moving source lines must not invalidate accepted findings."""
    path = _write_baseline(tmp_path, [_finding(line=10)])
    b = baseline.load(path)
    assert b is not None

    moved = b.apply([_finding(line=97)])
    assert moved[0].waived is True


def test_apply_does_not_match_across_categories(tmp_path: Path) -> None:
    """Accepting one category must not accept another on the same resource."""
    path = _write_baseline(tmp_path, [_finding(category=Category.TUTORIAL_PATTERN)])
    b = baseline.load(path)
    assert b is not None

    other = b.apply([_finding(category=Category.MISSING_LIFECYCLE)])
    assert other[0].waived is False


def test_stale_counts_entries_that_matched_nothing(tmp_path: Path) -> None:
    """Report stale entries without silently deleting acceptance history."""
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
    """A missing baseline is the normal initial state."""
    assert baseline.load(str(tmp_path / "nope.json")) is None
    assert baseline.load("") is None


def test_load_rejects_unknown_format_version(tmp_path: Path) -> None:
    """Unknown formats must not silently accept findings."""
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
    """Regenerating an unchanged baseline must produce no diff."""
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

    document = json.loads(first.read_text())
    assert len(document["entries"]) == 2, "the duplicate must be collapsed"
    assert [e["file"] for e in document["entries"]] == ["a.tf", "z.tf"]
    assert document["format_version"] == baseline.FORMAT_VERSION
    assert document["_note"]


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    path = _write_baseline(tmp_path, [_finding()])
    b = baseline.load(path)
    assert b is not None
    assert b.size() == 1
    assert b.apply([_finding()])[0].waived is True


# Exact rule-name matching in baseline format 2, with legacy version 1 compatibility.


def _finding_named(rule_name: str, category: Category = Category.MISSING_LIFECYCLE) -> Finding:
    """Build findings from different rules in the same category."""
    return Finding(
        file="s3.tf",
        line=22,
        category=category,
        severity=Severity.MEDIUM,
        resource="aws_s3_bucket.site",
        message=f"message de {rule_name}",
        rule_name=rule_name,
    )


def test_accepting_one_rule_does_not_accept_another_of_the_same_category(
    tmp_path: Path,
) -> None:
    """Regression: accepting missing_lifecycle must not also accept s3_force_destroy on the same
    bucket, even though both share a category.
    """
    path = _write_baseline(tmp_path, [_finding_named("missing_lifecycle")])
    base = baseline.load(path)
    assert base is not None

    accepte, autre = _finding_named("missing_lifecycle"), _finding_named("s3_force_destroy")
    base.apply([accepte, autre])

    assert accepte.waived, "the entry must still accept its own rule"
    assert not autre.waived, (
        "another rule in the same category must remain blocking — the purpose of format version 2"
    )


def test_a_version_1_baseline_still_accepts_everything_it_used_to(tmp_path: Path) -> None:
    """Version 1 lacks rule identity, so retain its broad matching for compatibility and warn users
    to regenerate.
    """
    path = tmp_path / "v1.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "entries": [
                    {
                        "category": "missing_lifecycle",
                        "resource": "aws_s3_bucket.site",
                        "file": "s3.tf",
                    }
                ],
            }
        )
    )
    base = baseline.load(str(path))
    assert base is not None
    assert base.legacy, "callers must be able to warn about legacy matching"

    accepte, autre = _finding_named("missing_lifecycle"), _finding_named("s3_force_destroy")
    base.apply([accepte, autre])
    assert accepte.waived and autre.waived, "version 1 retains broad matching"


def test_regenerating_a_version_1_baseline_closes_the_hole(tmp_path: Path) -> None:
    """Regenerating a legacy baseline upgrades it to exact matching."""
    v1 = tmp_path / "v1.json"
    v1.write_text(
        json.dumps(
            {
                "format_version": 1,
                "entries": [
                    {
                        "category": "missing_lifecycle",
                        "resource": "aws_s3_bucket.site",
                        "file": "s3.tf",
                    }
                ],
            }
        )
    )
    ancienne = baseline.load(str(v1))
    assert ancienne is not None and ancienne.legacy

    # Regenerate from current findings as --write-baseline does.
    regenere = _write_baseline(tmp_path, [_finding_named("missing_lifecycle")])
    neuve = baseline.load(regenere)
    assert neuve is not None
    assert not neuve.legacy

    autre = _finding_named("s3_force_destroy")
    neuve.apply([autre])
    assert not autre.waived


def test_a_version_2_entry_without_a_rule_name_is_exact_not_loose(tmp_path: Path) -> None:
    """An empty rule name in version 2 matches only another empty name; file version determines
    legacy behavior.
    """
    anonyme = _finding_named("")
    path = _write_baseline(tmp_path, [anonyme])
    base = baseline.load(path)
    assert base is not None and not base.legacy

    memes, nommee = _finding_named(""), _finding_named("missing_lifecycle")
    base.apply([memes, nommee])
    assert memes.waived
    assert not nommee.waived, "an exact entry without a name is not a wildcard"


def test_the_written_file_records_the_rule_name(tmp_path: Path) -> None:
    path = _write_baseline(tmp_path, [_finding_named("s3_force_destroy")])
    document = json.loads(Path(path).read_text())
    assert document["format_version"] == 2
    assert document["entries"][0]["rule_name"] == "s3_force_destroy"


def test_two_rules_of_one_category_are_two_entries(tmp_path: Path) -> None:
    """Deduplicate by exact rule identity so two rules in one category remain separate entries."""
    path = _write_baseline(
        tmp_path, [_finding_named("missing_lifecycle"), _finding_named("s3_force_destroy")]
    )
    document = json.loads(Path(path).read_text())
    assert len(document["entries"]) == 2
