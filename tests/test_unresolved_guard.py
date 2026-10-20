"""Guard settings the scanner cannot evaluate are reported as unverified, not passed as safe."""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.rules import RunOptions, builtin_pack, default_rules, run
from tfpdf.rules.unresolved import guard_rules
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _unresolved(kb: KnowledgeBase, source: str, repo_dir: Path) -> list[Finding]:
    """Scan one file the way the CLI does, with its directory available to resolve references."""
    (repo_dir / "main.tf").write_text(source)
    result = run(
        [ChangedFile(path="main.tf", head_content=source.encode())],
        kb,
        default_rules(),
        RunOptions(repo_dir=str(repo_dir)),
    )
    return [f for f in result.findings if f.rule_name == "unresolved_guard_value"]


def test_a_variable_without_default_is_reported(kb: KnowledgeBase, tmp_path: Path) -> None:
    findings = _unresolved(
        kb,
        'variable "skip" {}\n'
        'resource "aws_db_instance" "db" {\n'
        "  skip_final_snapshot = var.skip\n"
        "  lifecycle {\n    prevent_destroy = true\n  }\n"
        "}\n",
        tmp_path,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is Category.UNRESOLVED_VALUE
    assert finding.severity is Severity.LOW
    assert finding.line == 3
    assert finding.resource == "aws_db_instance.db"
    assert finding.message.startswith("skip_final_snapshot = var.skip could not be evaluated")
    assert "skip_final_snapshot did not check it" in finding.message


def test_a_variable_with_a_default_is_evaluated_not_reported(
    kb: KnowledgeBase, tmp_path: Path
) -> None:
    findings = _unresolved(
        kb,
        'variable "skip" {\n  default = false\n}\n'
        'resource "aws_db_instance" "db" {\n'
        "  skip_final_snapshot = var.skip\n"
        "}\n",
        tmp_path,
    )
    assert findings == []


def test_a_credential_reference_is_not_an_unresolved_guard(
    kb: KnowledgeBase, tmp_path: Path
) -> None:
    """`password = var.x` is the correct way to pass a secret, not an unchecked setting."""
    findings = _unresolved(
        kb,
        'resource "aws_db_instance" "db" {\n  password = var.db_password\n}\n',
        tmp_path,
    )
    assert findings == []


def test_a_nested_guard_is_reported_once(kb: KnowledgeBase, tmp_path: Path) -> None:
    findings = _unresolved(
        kb,
        'resource "aws_instance" "web" {\n'
        "  metadata_options {\n"
        "    http_tokens = var.tokens\n"
        "  }\n"
        "}\n",
        tmp_path,
    )
    assert [(f.line, f.message.split(" could")[0]) for f in findings] == [
        (3, "http_tokens = var.tokens")
    ]


def test_a_long_expression_is_shortened(kb: KnowledgeBase, tmp_path: Path) -> None:
    long_condition = " && ".join(f"var.flag_{index}" for index in range(12))
    findings = _unresolved(
        kb,
        f'resource "aws_s3_bucket" "logs" {{\n  force_destroy = {long_condition}\n}}\n',
        tmp_path,
    )
    assert len(findings) == 1
    assert "…" in findings[0].message


def test_only_rules_that_judge_a_written_setting_are_guards() -> None:
    guard_ids = {rule.id for rule in guard_rules(builtin_pack())}

    assert {"public_data_store", "skip_final_snapshot", "s3_force_destroy"} <= guard_ids
    assert not guard_ids & {"hardcoded_credential", "placeholder_attribute_value", "open_cidr"}


def test_the_rule_is_experimental() -> None:
    rule = builtin_pack().by_id("unresolved_guard_value")
    assert rule is not None
    assert rule.maturity == "experimental"
