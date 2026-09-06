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


# --- le nom de la règle dans la clé (format 2) -------------------------------
#
# Le trou que la version 2 bouche, et la fenêtre de compatibilité qui empêche
# de le boucher au prix d'une CI rouge chez tous ceux qui ont adopté l'outil.


def _finding_named(rule_name: str, category: Category = Category.MISSING_LIFECYCLE) -> Finding:
    """Deux règles, une seule catégorie — la forme exacte du bug."""
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
    """Le cas réel, réduit.

    Sur notre propre infrastructure, `force_destroy` était monté de medium à
    critical parce que la lecture cloud avait constaté que le compartiment
    existait et n'était pas vide — et la découverte est arrivée déjà neutralisée
    par une entrée écrite pour le prevent_destroy manquant. Même catégorie, même
    ressource, même fichier : l'ancienne clé ne les séparait pas.
    """
    path = _write_baseline(tmp_path, [_finding_named("missing_lifecycle")])
    base = baseline.load(path)
    assert base is not None

    accepte, autre = _finding_named("missing_lifecycle"), _finding_named("s3_force_destroy")
    base.apply([accepte, autre])

    assert accepte.waived, "l'entrée doit toujours accepter sa propre règle"
    assert not autre.waived, (
        "une règle différente de la même catégorie doit rester bloquante — "
        "c'est tout l'objet du format 2"
    )


def test_a_version_1_baseline_still_accepts_everything_it_used_to(tmp_path: Path) -> None:
    """La compatibilité, et son prix.

    Une référence de version 1 ne dit pas quelle règle son auteur avait
    acceptée ; rien ne permet de le reconstruire. Elle apparie donc comme avant,
    trop largement. Refuser de l'apparier rendrait bloquantes des centaines de
    découvertes déjà acceptées, dans chaque dépôt, à la première exécution après
    la mise à jour — une montée de version qui punit ceux qui ont adopté l'outil
    tôt est une montée de version que personne n'applique.
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
    assert base.legacy, "l'appelant doit pouvoir le dire à l'utilisateur"

    accepte, autre = _finding_named("missing_lifecycle"), _finding_named("s3_force_destroy")
    base.apply([accepte, autre])
    assert accepte.waived and autre.waived, "la version 1 garde son appariement large"


def test_regenerating_a_version_1_baseline_closes_the_hole(tmp_path: Path) -> None:
    """Le chemin de sortie, et la raison pour laquelle l'avertissement existe :
    un `--write-baseline` sur les mêmes découvertes rend l'appariement exact."""
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

    # Ce que ferait --write-baseline : réécrire depuis le scan courant.
    regenere = _write_baseline(tmp_path, [_finding_named("missing_lifecycle")])
    neuve = baseline.load(regenere)
    assert neuve is not None
    assert not neuve.legacy

    autre = _finding_named("s3_force_destroy")
    neuve.apply([autre])
    assert not autre.waived


def test_a_version_2_entry_without_a_rule_name_is_exact_not_loose(tmp_path: Path) -> None:
    """Les deux « vides » ne veulent pas dire la même chose.

    Le scanner produit une découverte sans règle quand il n'arrive pas à
    analyser un fichier. Acceptée dans une référence de version 2, elle doit
    apparier CETTE découverte-là et pas toutes celles qui partagent sa
    catégorie — c'est la version du fichier qui décide, pas le champ vide.
    """
    anonyme = _finding_named("")
    path = _write_baseline(tmp_path, [anonyme])
    base = baseline.load(path)
    assert base is not None and not base.legacy

    memes, nommee = _finding_named(""), _finding_named("missing_lifecycle")
    base.apply([memes, nommee])
    assert memes.waived
    assert not nommee.waived, "une entrée exacte sans nom n'est pas un joker"


def test_the_written_file_records_the_rule_name(tmp_path: Path) -> None:
    path = _write_baseline(tmp_path, [_finding_named("s3_force_destroy")])
    document = json.loads(Path(path).read_text())
    assert document["format_version"] == 2
    assert document["entries"][0]["rule_name"] == "s3_force_destroy"


def test_two_rules_of_one_category_are_two_entries(tmp_path: Path) -> None:
    """La déduplication d'écriture porte sur la clé. Avec l'ancienne, ces deux
    découvertes n'en faisaient qu'une — et la référence produite depuis un scan
    en oubliait une au passage."""
    path = _write_baseline(
        tmp_path, [_finding_named("missing_lifecycle"), _finding_named("s3_force_destroy")]
    )
    document = json.loads(Path(path).read_text())
    assert len(document["entries"]) == 2
