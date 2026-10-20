"""Score the built-in rules against the labelled cases in benchmarks/cases.

Each case is a directory:

    case.yml    what the case is about, and its labels
    base/       optional: the files before the change
    head/       the files after the change
    plan.json   optional: a `terraform show -json` plan for the change

The case is committed into a temporary Git repository (base, then head) and scanned by the same
code path as the command line, so the scores describe what a user gets. Labels in case.yml:

    expect:            findings the scan must report
      - rule: public_data_store
        target: aws_db_instance.public      # a resource address, or file:<path>
        count: 1                            # optional, for several findings on one target
    must_not_report:   near misses: targets that look risky but are not
      - rule: public_data_store
        target: aws_db_instance.private

A case is labelled only for the rules it names. A finding from such a rule that is not expected
is a false positive; findings from other rules are not scored in that case.

Run `python benchmarks/score.py` to print the results, `--write` to update RESULTS.md.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tfpdf import ruledef
from tfpdf.cli.arguments import build_parser
from tfpdf.cli.config import Config
from tfpdf.cli.goflags import normalize_argv
from tfpdf.cli.pipeline import collect_findings
from tfpdf.report.finding import Finding

BENCHMARK_DIR = Path(__file__).resolve().parent
CASES_DIR = BENCHMARK_DIR / "cases"
RESULTS_PATH = BENCHMARK_DIR / "RESULTS.md"

#: The acceptance criteria a rule must meet on this corpus to be validated or stable. They are
#: engineering targets for a small, maintainer-labelled corpus, not a claim about real-world
#: precision; docs/benchmark.md explains the difference.
MINIMUM_POSITIVES = 5
MINIMUM_NEAR_MISSES = 3
MINIMUM_PRECISION = 0.95
MINIMUM_RECALL = 0.90


@dataclass(slots=True)
class RuleScore:
    """Counts for one rule across every case labelled for it."""

    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    #: Labelled near misses, and how many of them the rule reported anyway.
    near_misses: int = 0
    near_misses_reported: int = 0
    cases: set[str] = field(default_factory=set)

    @property
    def positives(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def precision(self) -> float | None:
        reported = self.true_positives + self.false_positives
        return self.true_positives / reported if reported else None

    @property
    def recall(self) -> float | None:
        return self.true_positives / self.positives if self.positives else None

    def acceptance_failures(self) -> list[str]:
        """Return the acceptance criteria this rule misses; empty when it meets them all."""
        failures: list[str] = []
        if self.positives < MINIMUM_POSITIVES:
            failures.append(f"{self.positives} positives, needs {MINIMUM_POSITIVES}")
        if self.near_misses < MINIMUM_NEAR_MISSES:
            failures.append(f"{self.near_misses} near misses, needs {MINIMUM_NEAR_MISSES}")
        if self.precision is not None and self.precision < MINIMUM_PRECISION:
            failures.append(f"precision {self.precision:.2f} < {MINIMUM_PRECISION}")
        if self.recall is not None and self.recall < MINIMUM_RECALL:
            failures.append(f"recall {self.recall:.2f} < {MINIMUM_RECALL}")
        return failures


@dataclass(slots=True)
class Mismatch:
    """A finding the labels did not predict, or a label the scan did not satisfy."""

    case: str
    rule_id: str
    target: str
    kind: str  # "false positive" or "false negative"


def _git(directory: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=directory, capture_output=True, check=True)


def _copy_tree(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file():
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def _clear_worktree(repository: Path) -> None:
    for path in repository.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def scan_case(case_dir: Path) -> list[Finding]:
    """Commit the case's base and head into a temporary repository and scan the change."""
    with tempfile.TemporaryDirectory(prefix="tfpdf-benchmark-") as temporary:
        repository = Path(temporary)
        _git(repository, "init", "-q", "-b", "main")
        _git(repository, "config", "user.email", "benchmark@example.com")
        _git(repository, "config", "user.name", "benchmark")
        if (case_dir / "base").is_dir():
            _copy_tree(case_dir / "base", repository)
        _git(repository, "commit", "-q", "--allow-empty", "-m", "base")
        _git(repository, "add", "-A")
        _git(repository, "commit", "-q", "--allow-empty", "-m", "base files")
        _clear_worktree(repository)
        _copy_tree(case_dir / "head", repository)
        _git(repository, "add", "-A")
        _git(repository, "commit", "-q", "--allow-empty", "-m", "head")

        argv = [
            "--repo-dir",
            str(repository),
            "--base-ref",
            "HEAD~1",
            "--head-ref",
            "HEAD",
            "--license-key",
            "",
            "--rules",
            "",
            "--baseline",
            "",
            "--cloud-read-access=false",
        ]
        plan = case_dir / "plan.json"
        if plan.is_file():
            argv += ["--plan-json", str(plan)]
        arguments = build_parser().parse_args(normalize_argv(argv))
        # The scan narrates its coverage on stderr; the benchmark reports scores instead.
        with contextlib.redirect_stderr(io.StringIO()):
            return collect_findings(arguments, Config())


def target_of(finding: Finding) -> str:
    """Name what a finding is about: its resource, or its file for file-level findings."""
    if finding.resource and finding.resource != "-":
        return finding.resource
    return f"file:{finding.file}"


def _labels(entries: list[dict[str, object]] | None) -> Counter[tuple[str, str]]:
    labels: Counter[tuple[str, str]] = Counter()
    for entry in entries or []:
        labels[(str(entry["rule"]), str(entry["target"]))] += int(str(entry.get("count", 1)))
    return labels


def score(cases_dir: Path = CASES_DIR) -> tuple[dict[str, RuleScore], list[Mismatch]]:
    """Scan every case and count true positives, false positives and false negatives per rule."""
    scores: dict[str, RuleScore] = {}
    mismatches: list[Mismatch] = []

    for case_dir in sorted(path for path in cases_dir.iterdir() if path.is_dir()):
        labels = yaml.safe_load((case_dir / "case.yml").read_text(encoding="utf-8"))
        expected = _labels(labels.get("expect"))
        near_misses = _labels(labels.get("must_not_report"))
        labelled_rules = {rule for rule, _ in expected} | {rule for rule, _ in near_misses}

        reported: Counter[tuple[str, str]] = Counter(
            (finding.rule_name, target_of(finding))
            for finding in scan_case(case_dir)
            if finding.rule_name in labelled_rules
        )

        for rule_id in labelled_rules:
            scores.setdefault(rule_id, RuleScore(rule_id)).cases.add(case_dir.name)
        for key in expected | reported:
            rule_id, target = key
            rule_score = scores[rule_id]
            matched = min(expected[key], reported[key])
            rule_score.true_positives += matched
            if expected[key] > matched:
                rule_score.false_negatives += expected[key] - matched
                mismatches.append(Mismatch(case_dir.name, rule_id, target, "false negative"))
            if reported[key] > matched:
                rule_score.false_positives += reported[key] - matched
                mismatches.append(Mismatch(case_dir.name, rule_id, target, "false positive"))
        for key, count in near_misses.items():
            rule_score = scores[key[0]]
            rule_score.near_misses += count
            rule_score.near_misses_reported += min(count, reported[key])

    return scores, mismatches


def _percentage(value: float | None) -> str:
    return "—" if value is None else f"{value:.0%}"


def render_results(scores: dict[str, RuleScore], mismatches: list[Mismatch]) -> str:
    """Render the results table, in built-in pack order, with every rule listed."""
    pack = ruledef.builtin()
    lines = [
        "<!-- Generated by benchmarks/score.py. Do not edit by hand: run",
        '     "python benchmarks/score.py --write". -->',
        "",
        "# Benchmark results",
        "",
        "Scores of the built-in rules on the labelled cases in `benchmarks/cases`. The corpus is",
        "small, synthetic and labelled by the maintainers: it shows what each rule catches and",
        "misses on known cases and guards against regressions. It is not an estimate of",
        "precision on real repositories. See [docs/benchmark.md](../docs/benchmark.md).",
        "",
        f"Acceptance criteria for `validated` and `stable` rules: at least {MINIMUM_POSITIVES} "
        f"positives and {MINIMUM_NEAR_MISSES} near misses,",
        f"precision ≥ {MINIMUM_PRECISION:.0%} and recall ≥ {MINIMUM_RECALL:.0%}.",
        "",
        "| Rule | Maturity | Cases | Positives | Near misses | TP | FP | FN | Precision | Recall |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for rule in pack.rules:
        rule_score = scores.get(rule.id, RuleScore(rule.id))
        lines.append(
            f"| `{rule.id}` | {rule.maturity} | {len(rule_score.cases)} | {rule_score.positives} "
            f"| {rule_score.near_misses} | {rule_score.true_positives} "
            f"| {rule_score.false_positives} | {rule_score.false_negatives} "
            f"| {_percentage(rule_score.precision)} | {_percentage(rule_score.recall)} |"
        )
    totals = RuleScore("all")
    for rule_score in scores.values():
        totals.true_positives += rule_score.true_positives
        totals.false_positives += rule_score.false_positives
        totals.false_negatives += rule_score.false_negatives
        totals.near_misses += rule_score.near_misses
    lines += [
        "",
        f"All rules: {totals.positives} positives, {totals.near_misses} near misses, "
        f"{totals.true_positives} true positives, {totals.false_positives} false positives, "
        f"{totals.false_negatives} false negatives.",
        "",
        "## Known misses",
        "",
    ]
    if mismatches:
        lines += ["| Case | Rule | Target | Outcome |", "|---|---|---|---|"]
        lines += [
            f"| `{m.case}` | `{m.rule_id}` | `{m.target}` | {m.kind} |"
            for m in sorted(mismatches, key=lambda m: (m.rule_id, m.case, m.target))
        ]
    else:
        lines.append("None: every labelled case is scored as labelled.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help=f"update {RESULTS_PATH.name}")
    arguments = parser.parse_args(argv)

    # The scan must not post comments or reach the hosted service from a developer's shell.
    for name in list(os.environ):
        if name.startswith(("GITHUB_", "GITLAB_", "CI_", "TFPDF_", "SCANNER_")):
            del os.environ[name]

    results = render_results(*score())
    if arguments.write:
        RESULTS_PATH.write_text(results, encoding="utf-8")
    else:
        sys.stdout.write(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
