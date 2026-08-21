"""Port de internal/planjson/loader_test.go, cas pour cas, plus la gestion
des valeurs nulles que la version Go n'a pas besoin d'énoncer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf import planjson

PLANS = Path(__file__).parent / "data" / "plans"


def test_load_sample_plan() -> None:
    pf = planjson.load(str(PLANS / "sample_plan.json"))
    assert len(pf.resource_changes) == 4

    by_addr = {rc.address: rc for rc in pf.resource_changes}
    assert by_addr["aws_db_instance.prod"].change.is_replace()
    assert by_addr["aws_s3_bucket.logs"].change.is_destroy_only()
    assert by_addr["aws_security_group.web"].change.is_pure_update()
    assert by_addr["aws_iam_role.app"].change.is_no_op()


def test_load_missing_file() -> None:
    with pytest.raises(ValueError, match="reading plan JSON"):
        planjson.load(str(PLANS / "does_not_exist.json"))


def test_load_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    with pytest.raises(ValueError, match="parsing plan JSON"):
        planjson.load(str(path))


# --- beyond the Go suite ----------------------------------------------------


def test_a_null_state_is_absence_not_an_empty_object() -> None:
    """Go modélise before et after par des maps nullables, si bien que
    `"before": null` sur une création se distingue de `"before": {}`. Décoder
    les deux en `{}` — le Python évident — fait facturer par la règle de coût
    une ressource à tarif fixe des deux côtés d'une création, et rapporter un
    écart nul. Rien dans la suite Go ne dit cela, parce qu'en Go la distinction
    vient gratuitement avec le type."""
    pf = planjson.parse(
        """
        {"resource_changes": [
          {"address": "a.b", "mode": "managed", "type": "a", "name": "b",
           "change": {"actions": ["create"], "before": null, "after": {"x": 1}}},
          {"address": "c.d", "mode": "managed", "type": "c", "name": "d",
           "change": {"actions": ["update"], "before": {}, "after": {}}}
        ]}
        """
    )
    create, update = pf.resource_changes
    assert create.change.before is None
    assert create.change.after == {"x": 1}
    assert update.change.before == {}, "an empty object is not absence"


def test_a_missing_change_object_does_not_crash() -> None:
    """Une entrée de plan sans aucune clé `change`. La structure à valeur zéro
    de Go absorbe cela ; il faut le dire à Python."""
    pf = planjson.parse('{"resource_changes": [{"address": "a.b", "mode": "managed"}]}')
    rc = pf.resource_changes[0]
    assert rc.change.actions == []
    assert not rc.change.is_replace()
    assert not rc.change.is_no_op()


def test_sensitive_marks_are_read_from_either_side() -> None:
    """before et after portent toujours le vrai texte clair même quand le
    masque dit que l'attribut est sensible : tout code qui affiche une valeur
    doit donc consulter le masque d'abord — la règle de dérive le fait."""
    pf = planjson.parse(
        """
        {"resource_changes": [
          {"address": "a.b", "mode": "managed", "type": "a", "name": "b",
           "change": {"actions": ["update"],
                      "before": {"pw": "old"}, "after": {"pw": "new"},
                      "after_sensitive": {"pw": true}}}
        ]}
        """
    )
    change = pf.resource_changes[0].change
    assert change.is_sensitive_attr("pw")
    assert not change.is_sensitive_attr("other")


def test_a_top_level_non_object_is_rejected() -> None:
    with pytest.raises(ValueError, match="top level is not an object"):
        planjson.parse("[1, 2, 3]")
