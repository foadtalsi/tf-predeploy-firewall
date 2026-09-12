"""Exercise rules.run across parsing, scope resolution, detection, suppression, and documentation
links.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf import ignore
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.rules import RunOptions, default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema

FIXTURES = Path(__file__).parent / "data" / "corpus_fixtures"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _categories(findings: list[Finding]) -> set[Category]:
    return {f.category for f in findings}


def test_run_detects_force_new_across_revisions(kb: KnowledgeBase) -> None:
    """ForceNew detection must receive both base and head contents."""
    base = (FIXTURES / "forcenew_base.tf").read_bytes()
    head = (FIXTURES / "forcenew_head.tf").read_bytes()

    result = run(
        [ChangedFile(path="rds.tf", head_content=head, base_content=base)],
        kb,
        default_rules(),
    )

    force_new = [f for f in result.findings if f.category is Category.FORCE_NEW_CHANGE]
    assert force_new, "a changed ForceNew attribute must be reported"
    # aws_db_instance is a critical stateful type, so the severity is raised.
    assert any(f.severity is Severity.CRITICAL for f in force_new)


def test_run_reports_no_force_new_for_a_new_file(kb: KnowledgeBase) -> None:
    """New resources have no previous values to replace."""
    head = (FIXTURES / "forcenew_head.tf").read_bytes()

    result = run(
        [ChangedFile(path="rds.tf", head_content=head, base_content=None)],
        kb,
        default_rules(),
    )
    assert Category.FORCE_NEW_CHANGE not in _categories(result.findings)


def test_run_records_changed_attrs(kb: KnowledgeBase) -> None:
    """Record changed attributes so plan checks can distinguish edits from drift."""
    base = (FIXTURES / "forcenew_base.tf").read_bytes()
    head = (FIXTURES / "forcenew_head.tf").read_bytes()

    result = run(
        [ChangedFile(path="rds.tf", head_content=head, base_content=base)],
        kb,
        default_rules(),
    )
    assert result.changed_attrs, "a modified resource must record its changed attributes"
    for keys in result.changed_attrs.values():
        assert keys


def test_run_reports_a_parse_error_as_a_finding(kb: KnowledgeBase) -> None:
    """Report unreadable HCL visibly while allowing other files to scan."""
    result = run(
        [ChangedFile(path="broken.tf", head_content=b'resource "aws_instance" "x" {')],
        kb,
        default_rules(),
    )
    assert len(result.findings) == 1
    assert result.findings[0].resource == "-"
    assert "could not parse file as HCL" in result.findings[0].message


def test_run_attaches_doc_urls(kb: KnowledgeBase) -> None:
    """Link schema claims to provider documentation."""
    head = (FIXTURES / "unknown_attribute.tf").read_bytes()
    result = run([ChangedFile(path="main.tf", head_content=head)], kb, default_rules())

    unknown = [f for f in result.findings if f.category is Category.UNKNOWN_ATTRIBUTE]
    assert unknown
    for f in unknown:
        assert f.doc_url.startswith("https://registry.terraform.io/providers/")
        assert "/latest/" not in f.doc_url, "a doc link must pin the release the pack describes"


def test_run_applies_global_ignore(kb: KnowledgeBase) -> None:
    head = (FIXTURES / "unknown_attribute.tf").read_bytes()
    files = [ChangedFile(path="main.tf", head_content=head)]

    with_all = run(files, kb, default_rules())
    assert Category.UNKNOWN_ATTRIBUTE in _categories(with_all.findings)

    suppressed = run(
        files,
        kb,
        default_rules(),
        RunOptions(global_ignore=[Category.UNKNOWN_ATTRIBUTE]),
    )
    assert Category.UNKNOWN_ATTRIBUTE not in _categories(suppressed.findings)


def test_run_applies_inline_ignore(kb: KnowledgeBase) -> None:
    """An inline ignore on line N covers N and N+1."""
    source = b"""
resource "aws_db_instance" "prod" {
  identifier = "x"
  # tf-firewall-ignore: tutorial_pattern
  password = "hunter2"
}
"""
    findings = run([ChangedFile(path="main.tf", head_content=source)], kb, default_rules()).findings
    assert Category.TUTORIAL_PATTERN not in _categories(findings)

    # Without the directive, the same file reports the credential.
    without = source.replace(b"  # tf-firewall-ignore: tutorial_pattern\n", b"")
    findings = run(
        [ChangedFile(path="main.tf", head_content=without)], kb, default_rules()
    ).findings
    assert Category.TUTORIAL_PATTERN in _categories(findings)


def test_run_scope_resolution_is_off_without_a_repo_dir(kb: KnowledgeBase) -> None:
    """Without repo_dir, scope resolution must not read unrelated directories."""
    source = b"""
variable "db_password" { default = "changeme" }
resource "aws_db_instance" "prod" {
  identifier = "x"
  password   = var.db_password
}
"""
    findings = run([ChangedFile(path="main.tf", head_content=source)], kb, default_rules()).findings
    resolved = [f for f in findings if "via var.db_password" in f.message]
    assert not resolved


def test_run_scope_resolution_with_a_repo_dir(tmp_path: Path, kb: KnowledgeBase) -> None:
    """Resolve literal defaults and explain the reference behind the finding."""
    source = b"""
variable "db_password" { default = "changeme" }
resource "aws_db_instance" "prod" {
  identifier = "x"
  password   = var.db_password
}
"""
    (tmp_path / "main.tf").write_bytes(source)

    findings = run(
        [ChangedFile(path="main.tf", head_content=source)],
        kb,
        default_rules(),
        RunOptions(repo_dir=str(tmp_path)),
    ).findings
    assert any("via var.db_password" in f.message for f in findings)


def test_scope_cache_refuses_to_read_outside_the_repo(tmp_path: Path, kb: KnowledgeBase) -> None:
    """Scope resolution must not read paths outside the repository."""
    from tfpdf.rules.engine import ScopeCache

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "secrets"
    outside.mkdir()
    (outside / "leak.tf").write_bytes(b'locals { stolen = "s3cret" }')

    cache = ScopeCache(str(repo))
    scope = cache.for_file("../secrets/leak.tf", None)
    assert scope is None, "the scope must not be built from files outside the repository"


# --- path rules -----------------------------------------------------------


def _finding(path: str, category: Category = Category.TUTORIAL_PATTERN) -> Finding:
    return Finding(
        file=path, line=1, category=category, severity=Severity.HIGH, resource="x.y", message="m"
    )


@pytest.mark.parametrize(
    ("pattern", "path", "suppressed"),
    [
        ("legacy/**", "legacy/main.tf", True),
        ("legacy/**", "legacy/deep/nested/main.tf", True),
        # "**" matches zero segments too.
        ("legacy/**", "legacy", False),
        ("legacy/**", "modern/main.tf", False),
        # A single "*" does not cross a "/".
        ("sandbox/*.tf", "sandbox/main.tf", True),
        ("sandbox/*.tf", "sandbox/deep/main.tf", False),
        ("?.tf", "a.tf", True),
        ("?.tf", "ab.tf", False),
    ],
)
def test_apply_path_rules(pattern: str, path: str, suppressed: bool) -> None:
    kept = ignore.apply_path_rules([_finding(path)], [ignore.PathRule(pattern=pattern)])
    assert (kept == []) is suppressed


def test_path_rules_can_be_scoped_to_categories() -> None:
    """Excluding lifecycle findings under a path must not hide credentials there."""
    rules = [
        ignore.PathRule(pattern="legacy/**", categories=[Category.MISSING_LIFECYCLE]),
    ]
    findings = [
        _finding("legacy/a.tf", Category.MISSING_LIFECYCLE),
        _finding("legacy/a.tf", Category.TUTORIAL_PATTERN),
    ]
    kept = ignore.apply_path_rules(findings, rules)
    assert [f.category for f in kept] == [Category.TUTORIAL_PATTERN]


# Keep s3_force_destroy fixtures separate from the historical Go corpus, whose scanner predates
# this rule.

_BUCKET_FORCE_DESTROY = b"""
resource "aws_s3_bucket" "backups" {
  bucket        = "acme-backups"
  force_destroy = true
}
"""

_BUCKET_KEEPS_OBJECTS = b"""
resource "aws_s3_bucket" "backups" {
  bucket        = "acme-backups"
  force_destroy = false
}
"""


def _force_destroy_findings(kb: KnowledgeBase, source: bytes) -> list[Finding]:
    result = run(
        [ChangedFile(path="s3.tf", head_content=source, base_content=None)],
        kb,
        default_rules(),
    )
    return [f for f in result.findings if "force_destroy" in f.message]


def test_s3_force_destroy_true_is_reported(kb: KnowledgeBase) -> None:
    """force_destroy removes S3's protection against deleting a nonempty bucket."""
    findings = _force_destroy_findings(kb, _BUCKET_FORCE_DESTROY)

    assert len(findings) == 1, "one bucket should produce one finding"
    finding = findings[0]
    assert finding.category is Category.MISSING_LIFECYCLE
    assert finding.severity is Severity.MEDIUM
    assert finding.resource == "aws_s3_bucket.backups"
    assert finding.line == 4, "the finding must point to the attribute line"


def test_s3_force_destroy_false_is_not_reported(kb: KnowledgeBase) -> None:
    """Explicit force_destroy = false must remain clean."""
    assert _force_destroy_findings(kb, _BUCKET_KEEPS_OBJECTS) == []


def test_s3_force_destroy_fix_is_applied_verbatim(kb: KnowledgeBase) -> None:
    """Exact suggestions must preserve the source indentation."""
    finding = _force_destroy_findings(kb, _BUCKET_FORCE_DESTROY)[0]

    assert finding.fix is not None
    assert finding.fix.lines == ["  force_destroy = false"]
