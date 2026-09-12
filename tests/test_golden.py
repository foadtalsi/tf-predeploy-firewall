"""Compare complete findings with frozen historical Go golden files, including locations, severity,
messages, and exact fixes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf.parser import build_scope, parse_file_with_context
from tfpdf.report.finding import Finding
from tfpdf.rules import FileInput, builtin_pack, default_rules, rules_for_category
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema

DATA = Path(__file__).parent / "data"
FIXTURES = DATA / "corpus_fixtures"
GOLDEN = DATA / "golden"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def one_line(s: str) -> str:
    return s.replace("\n", "\\n").replace("\r", "")


def render_findings(findings: list[Finding]) -> list[str]:
    """Render every significant finding field, including exact replacement text and notes."""
    out: list[str] = []
    for f in findings:
        line = f"{f.file}:{f.line} | {f.category} | {f.severity} | {f.resource} | {f.message}"
        if f.suggestion:
            line += " | suggestion=" + one_line(f.suggestion)
        if f.fix is not None:
            line += f" | fix={f.fix.start_line}-{f.fix.end_line}:{one_line(f.fix.text())}"
            if f.fix.note:
                line += " | note=" + one_line(f.fix.note)
        out.append(line)
    return out


def _file_input(name: str) -> FileInput:
    source = (FIXTURES / name).read_bytes()
    # Parsed with a scope built from the fixture itself, so a value reached
    # through a variable default resolves and sets resolved_from. Without it
    # the corpus would never exercise the branch where a finding names the
    # reference and deliberately withholds the one-click fix — the line under
    # that finding is already correct.
    scope = build_scope({name: source})
    resources = parse_file_with_context(name, source, scope)
    return FileInput(path=name, head_resources=resources, head_source=source)


def _compare(got: list[str], golden_name: str) -> None:
    # Sorting is not hiding a problem: nothing downstream depends on the order
    # rules emit in, and the report sorts before rendering.
    actual = "\n".join(sorted(got)) + "\n"
    want = (GOLDEN / golden_name).read_text()

    if want == actual:
        return

    want_lines = want.rstrip("\n").split("\n")
    got_lines = actual.rstrip("\n").split("\n")
    in_want, in_got = set(want_lines), set(got_lines)
    report = [f"want {len(want_lines)} findings, got {len(got_lines)}"]
    report.extend(f"  -{line}" for line in want_lines if line not in in_got)
    report.extend(f"  +{line}" for line in got_lines if line not in in_want)
    pytest.fail("\n".join(report), pytrace=False)


def test_golden_tutorial_pattern(kb: KnowledgeBase) -> None:
    """Pin credential detection output so changes to patterns, severity, or suggestions remain
    explicit.
    """
    rule = rules_for_category(builtin_pack(), "tutorial_pattern")

    got: list[str] = []
    for name in (
        "tutorial_golden.tf",
        "tutorial_pattern.tf",
        "credential_values.tf",
        "nested_block_cidr.tf",
    ):
        got.extend(render_findings(rule.check(_file_input(name), kb)))

    _compare(got, "tutorial_pattern.txt")


def test_golden_insecure_config(kb: KnowledgeBase) -> None:
    """Run all rules against insecure and clean fixtures to catch duplicate findings and false
    positives as well as missed detections.
    """
    ruleset = default_rules()

    got: list[str] = []
    for name in ("insecure_config.tf", "insecure_config_clean.tf"):
        in_ = _file_input(name)
        for r in ruleset:
            got.extend(render_findings(r.check(in_, kb)))

    _compare(got, "insecure_config.txt")
