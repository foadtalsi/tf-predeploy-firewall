"""Keep this repository's self-scan exclusions limited to intentionally insecure test fixtures."""

from __future__ import annotations

from pathlib import Path

from tfpdf.cli.config import load_config

CONFIG = Path(__file__).parent.parent / "config" / "default.yml"

#: The only trees holding Terraform that is insecure on purpose: test fixtures and the labelled
#: benchmark cases.
FIXTURE_ROOTS = ("tests/data/", "benchmarks/cases/")


def test_the_repo_scans_itself_clean() -> None:
    """The self-scan should be clean only because intentionally insecure fixtures are excluded."""
    config = load_config(str(CONFIG))
    assert [p.path for p in config.ignore_paths] == [root + "**" for root in FIXTURE_ROOTS]


def test_nothing_but_the_fixtures_is_excluded() -> None:
    """Exclusions must not cover production Terraform added later."""
    tf_files = sorted(
        str(p.relative_to(CONFIG.parent.parent))
        for p in (CONFIG.parent.parent).rglob("*.tf")
        if ".venv" not in p.parts and ".git" not in p.parts
    )
    assert tf_files, "no Terraform files found; this test would no longer check anything"
    outside = [f for f in tf_files if not f.startswith(FIXTURE_ROOTS)]
    assert not outside, (
        "Terraform exists outside fixtures; verify it is scanned "
        f"before expanding config/default.yml — {outside}"
    )


def test_the_exclusion_carries_no_category_filter() -> None:
    """Exclude all finding categories within the fixture directories."""
    config = load_config(str(CONFIG))
    assert all(entry.categories == [] for entry in config.ignore_paths)


def test_the_config_changes_nothing_else() -> None:
    """The self-scan configuration must not weaken thresholds or global detection."""
    config = load_config(str(CONFIG))
    assert config.ignore_rules == []
    assert str(config.block_threshold) == "high"
