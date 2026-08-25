"""La configuration que ce dépôt s'applique à lui-même.

`config/default.yml` existe pour une raison précise et étroite : les seuls .tf
d'ici sont des fixtures de test, mauvaises exprès, et l'audit programmé
hebdomadaire échouait dessus depuis des semaines. Un rouge qui revient tous les
lundis cesse d'être lu, ce qui revient à n'avoir aucun audit.

Un fichier d'exclusions est exactement le genre de fichier qui s'élargit : on y
ajoute un chemin pour faire passer une CI, puis un autre, et un jour le scanner
ne se scanne plus. D'où ces tests — ils tiennent la portée du fichier, pas son
existence.
"""

from __future__ import annotations

from pathlib import Path

from tfpdf.cli.config import load_config

CONFIG = Path(__file__).parent.parent / "config" / "default.yml"


def test_the_repo_scans_itself_clean() -> None:
    """Ce que l'audit du lundi doit trouver : rien. Cela n'a de valeur que
    couplé au test suivant, qui interdit d'y arriver en élargissant les
    exclusions."""
    config = load_config(str(CONFIG))
    assert [p.path for p in config.ignore_paths] == ["tests/data/**"]


def test_nothing_but_the_fixtures_is_excluded() -> None:
    """Aucune exclusion ne doit couvrir du code réel. Les seuls .tf du dépôt
    sont sous tests/data ; le jour où du Terraform de production entre ici, il
    doit être scanné."""
    tf_files = sorted(
        str(p.relative_to(CONFIG.parent.parent))
        for p in (CONFIG.parent.parent).rglob("*.tf")
        if ".venv" not in p.parts and ".git" not in p.parts
    )
    assert tf_files, "aucun .tf trouvé — ce test ne vérifierait plus rien"
    assert all(f.startswith("tests/data/") for f in tf_files), (
        "un .tf hors des fixtures est apparu : vérifiez qu'il est bien scanné "
        f"avant d'élargir config/default.yml — {[f for f in tf_files if not f.startswith('tests/data/')]}"
    )


def test_the_exclusion_carries_no_category_filter() -> None:
    """Vide veut dire « toutes catégories sous ce chemin ». Y ajouter une liste
    de catégories laisserait passer les autres sur des fichiers volontairement
    cassés, et rendrait l'audit bruyant à nouveau."""
    config = load_config(str(CONFIG))
    assert config.ignore_paths[0].categories == []


def test_the_config_changes_nothing_else() -> None:
    """Le seuil de blocage et les règles ignorées restent ceux par défaut : ce
    fichier exclut un chemin, il ne desserre pas la détection."""
    config = load_config(str(CONFIG))
    assert config.ignore_rules == []
    assert str(config.block_threshold) == "high"
