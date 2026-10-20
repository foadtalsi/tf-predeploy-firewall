"""The labelled benchmark backs every rule allowed to block, and its published results are current.

A rule promoted to validated or stable must meet the acceptance criteria in benchmarks/score.py.
A change that moves any score shows up as a diff of benchmarks/RESULTS.md in review, because the
committed file must match what the cases produce.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from tfpdf import ruledef

BENCHMARKS = Path(__file__).parent.parent / "benchmarks"


def _load_score_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("benchmark_score", BENCHMARKS / "score.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: dataclasses resolve their annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


score_module = _load_score_module()


@pytest.fixture(scope="module")
def scored() -> tuple[dict[str, object], list[object]]:
    return score_module.score()  # type: ignore[no-any-return]


def test_the_published_results_are_current(scored: tuple[dict[str, object], list[object]]) -> None:
    rendered = score_module.render_results(*scored)
    committed = (BENCHMARKS / "RESULTS.md").read_text(encoding="utf-8")
    assert rendered == committed, (
        "benchmarks/RESULTS.md is out of date; run `python benchmarks/score.py --write` and "
        "review the diff"
    )


def test_every_rule_allowed_to_block_meets_its_acceptance_criteria(
    scored: tuple[dict[str, object], list[object]],
) -> None:
    scores, _ = scored
    failures = {}
    for rule in ruledef.builtin().rules:
        if rule.maturity == "experimental":
            continue
        rule_score = scores.get(rule.id, score_module.RuleScore(rule.id))
        missed = rule_score.acceptance_failures()  # type: ignore[attr-defined]
        if missed:
            failures[rule.id] = missed
    assert not failures, f"rules below their acceptance criteria: {failures}"


def test_every_label_names_a_built_in_rule() -> None:
    known = {rule.id for rule in ruledef.builtin().rules}
    for case_file in sorted((BENCHMARKS / "cases").glob("*/case.yml")):
        labels = yaml.safe_load(case_file.read_text(encoding="utf-8"))
        for entry in (labels.get("expect") or []) + (labels.get("must_not_report") or []):
            assert entry["rule"] in known, f"{case_file}: unknown rule {entry['rule']!r}"
