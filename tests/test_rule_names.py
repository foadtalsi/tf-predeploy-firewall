"""Verify that finding construction names the rule and that IDs agree with the built-in registry.
Static checks complement scans over the fixture corpus.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from tfpdf import ruledef
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Finding
from tfpdf.rules import default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema

SRC = pathlib.Path(__file__).parent.parent / "src" / "tfpdf"

# Explicit rule IDs for non-Terraform files, where no resource-type pack entry applies.
NAMES_OUTSIDE_THE_PACK = frozenset(
    {
        "terragrunt_credential_name",
        "terragrunt_credential_value",
        "terragrunt_open_cidr",
        "tfvars_credential_name",
        "tfvars_credential_value",
        "tfvars_open_cidr",
        "tfvars_high_entropy",
    }
)


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _pack_rule_ids() -> set[str]:
    return {rule.id for rule in ruledef.builtin().rules}


def _finding_sites() -> list[tuple[str, int, ast.Call]]:
    """Yield Finding constructor calls with source locations."""
    sites = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Finding"
            ):
                sites.append((str(path.relative_to(SRC.parent.parent)), node.lineno, node))
    return sites


def test_every_place_that_builds_a_finding_names_its_rule() -> None:
    """Require rule names at construction sites, with an explicit exception for parser-error
    findings.
    """
    allowed_to_be_anonymous = {("src/tfpdf/rules/engine.py", "could not parse file")}

    anonymous = []
    for path, lineno, call in _finding_sites():
        if any(keyword.arg == "rule_name" for keyword in call.keywords):
            continue
        message = next((k for k in call.keywords if k.arg == "message"), None)
        text = ast.unparse(message.value) if message else ""
        if any(path.endswith(p) and marker in text for p, marker in allowed_to_be_anonymous):
            continue
        anonymous.append(f"{path}:{lineno}")

    assert not anonymous, "findings without rule names: " + ", ".join(anonymous)


def test_every_literal_rule_name_is_one_the_registry_knows() -> None:
    """Reject misspelled literal rule names that would break registry-based filtering."""
    known = _pack_rule_ids() | NAMES_OUTSIDE_THE_PACK
    unknown = []
    for path, lineno, call in _finding_sites():
        keyword = next((k for k in call.keywords if k.arg == "rule_name"), None)
        if keyword is None or not isinstance(keyword.value, ast.Constant):
            continue  # spec.id and custom:<id> are checked by the following tests.
        if keyword.value.value not in known:
            unknown.append(f"{path}:{lineno} -> {keyword.value.value!r}")

    assert not unknown, "rule names missing from the registry: " + ", ".join(unknown)


def test_the_names_outside_the_pack_do_not_shadow_a_pack_rule() -> None:
    """Extra rule names must not shadow built-in IDs."""
    assert not (NAMES_OUTSIDE_THE_PACK & _pack_rule_ids())


def test_a_declarative_rule_carries_its_pack_id() -> None:
    """Distinguish rules sharing the same category and resource through rule_name."""
    source = b"""resource "aws_s3_bucket" "backups" {
  bucket        = "prod-backups"
  force_destroy = true
}
"""
    findings = _scan(source)
    names = {f.rule_name for f in findings}

    assert "s3_force_destroy" in names
    assert "missing_lifecycle" in names
    # The findings otherwise share the same identity fields.
    assert len({f.category for f in findings}) == 1
    assert len({f.resource for f in findings}) == 1


def test_no_finding_from_a_real_scan_comes_out_anonymous(kb: KnowledgeBase) -> None:
    """Exercise dynamic finding factories that static constructor inspection cannot fully cover."""
    corpus = pathlib.Path(__file__).parent / "data" / "corpus_fixtures"
    changed = [
        ChangedFile(path=f.name, head_content=f.read_bytes()) for f in sorted(corpus.glob("*.tf"))
    ]
    assert changed, "le corpus doit contenir des fichiers"

    findings = run(changed, kb, default_rules()).findings
    assert findings, "the corpus must produce findings"

    anonymous = [f"{f.file}:{f.line} {f.category}" for f in findings if not f.rule_name]
    assert not anonymous, "anonymous findings: " + ", ".join(anonymous)


def _scan(source: bytes) -> list[Finding]:
    return run(
        [ChangedFile(path="s3.tf", head_content=source)],
        load_schema(),
        default_rules(),
    ).findings
