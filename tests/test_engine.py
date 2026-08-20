"""Tests du moteur de bout en bout : `rules.run` sur un diff base→tête.

Porte les cas au niveau moteur de internal/rules/rules_test.go et
internal/ignore/ignore_test.go. Tout ce qui suit passe par le même `run()` que
le CLI appelle : cela exerce donc ensemble l'analyse, la résolution de portée,
chaque règle, la suppression en ligne et l'attachement des URL de documentation,
plutôt qu'une chose à la fois.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf import ignore
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Category, Finding, Severity
from tfpdf.rules import Options, RunOptions, default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema

FIXTURES = Path(__file__).parent / "data" / "corpus_fixtures"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _categories(findings: list[Finding]) -> set[Category]:
    return {f.category for f in findings}


def test_run_detects_force_new_across_revisions(kb: KnowledgeBase) -> None:
    """La règle ForceNew est la seule qui ait besoin des deux révisions : c'est
    donc elle qui prouve que le moteur fait bien circuler le contenu de
    base."""
    base = (FIXTURES / "forcenew_base.tf").read_bytes()
    head = (FIXTURES / "forcenew_head.tf").read_bytes()

    result = run(
        [ChangedFile(path="rds.tf", head_content=head, base_content=base)],
        kb,
        default_rules(Options()),
    )

    force_new = [f for f in result.findings if f.category is Category.FORCE_NEW_CHANGE]
    assert force_new, "a changed ForceNew attribute must be reported"
    # aws_db_instance is a critical stateful type, so the severity is raised.
    assert any(f.severity is Severity.CRITICAL for f in force_new)


def test_run_reports_no_force_new_for_a_new_file(kb: KnowledgeBase) -> None:
    """Une ressource qui n'existait pas avant ne peut pas avoir été changée. En
    rapporter une voudrait dire que chaque nouvelle base de données ressemble à
    un remplacement imminent."""
    head = (FIXTURES / "forcenew_head.tf").read_bytes()

    result = run(
        [ChangedFile(path="rds.tf", head_content=head, base_content=None)],
        kb,
        default_rules(Options()),
    )
    assert Category.FORCE_NEW_CHANGE not in _categories(result.findings)


def test_run_records_changed_attrs(kb: KnowledgeBase) -> None:
    """Les règles basées sur le plan utilisent cet ensemble pour distinguer une
    édition délibérée d'une dérive."""
    base = (FIXTURES / "forcenew_base.tf").read_bytes()
    head = (FIXTURES / "forcenew_head.tf").read_bytes()

    result = run(
        [ChangedFile(path="rds.tf", head_content=head, base_content=base)],
        kb,
        default_rules(Options()),
    )
    assert result.changed_attrs, "a modified resource must record its changed attributes"
    for keys in result.changed_attrs.values():
        assert keys


def test_run_reports_a_parse_error_as_a_finding(kb: KnowledgeBase) -> None:
    """Un fichier que le scanner ne peut pas lire est un trou dont l'appelant
    doit entendre parler — ni un plantage, ni un silence."""
    result = run(
        [ChangedFile(path="broken.tf", head_content=b'resource "aws_instance" "x" {')],
        kb,
        default_rules(Options()),
    )
    assert len(result.findings) == 1
    assert result.findings[0].resource == "-"
    assert "could not parse file as HCL" in result.findings[0].message


def test_run_attaches_doc_urls(kb: KnowledgeBase) -> None:
    """Une découverte qui dit qu'un argument n'existe pas doit lier la liste
    des arguments, sinon l'affirmation ne peut pas être vérifiée."""
    head = (FIXTURES / "unknown_attribute.tf").read_bytes()
    result = run([ChangedFile(path="main.tf", head_content=head)], kb, default_rules(Options()))

    unknown = [f for f in result.findings if f.category is Category.UNKNOWN_ATTRIBUTE]
    assert unknown
    for f in unknown:
        assert f.doc_url.startswith("https://registry.terraform.io/providers/")
        assert "/latest/" not in f.doc_url, "a doc link must pin the release the pack describes"


def test_run_applies_global_ignore(kb: KnowledgeBase) -> None:
    head = (FIXTURES / "unknown_attribute.tf").read_bytes()
    files = [ChangedFile(path="main.tf", head_content=head)]

    with_all = run(files, kb, default_rules(Options()))
    assert Category.UNKNOWN_ATTRIBUTE in _categories(with_all.findings)

    suppressed = run(
        files,
        kb,
        default_rules(Options()),
        RunOptions(global_ignore=[Category.UNKNOWN_ATTRIBUTE]),
    )
    assert Category.UNKNOWN_ATTRIBUTE not in _categories(suppressed.findings)


def test_run_applies_inline_ignore(kb: KnowledgeBase) -> None:
    """Une directive en ligne N supprime les découvertes des lignes N et N+1,
    pour que le commentaire puisse se poser sur la ligne de l'attribut ou sur
    celle du dessus."""
    src = b"""
resource "aws_db_instance" "prod" {
  identifier = "x"
  # tf-firewall-ignore: tutorial_pattern
  password = "hunter2"
}
"""
    findings = run(
        [ChangedFile(path="main.tf", head_content=src)], kb, default_rules(Options())
    ).findings
    assert Category.TUTORIAL_PATTERN not in _categories(findings)

    # Without the directive, the same file reports the credential.
    without = src.replace(b"  # tf-firewall-ignore: tutorial_pattern\n", b"")
    findings = run(
        [ChangedFile(path="main.tf", head_content=without)], kb, default_rules(Options())
    ).findings
    assert Category.TUTORIAL_PATTERN in _categories(findings)


def test_run_scope_resolution_is_off_without_a_repo_dir(kb: KnowledgeBase) -> None:
    """Sans repo_dir il n'y a aucun répertoire à lire, donc `var.x` reste non
    résolu et chaque règle basée sur les valeurs le saute — le comportement
    d'avant l'existence des portées."""
    src = b"""
variable "db_password" { default = "changeme" }
resource "aws_db_instance" "prod" {
  identifier = "x"
  password   = var.db_password
}
"""
    findings = run(
        [ChangedFile(path="main.tf", head_content=src)], kb, default_rules(Options())
    ).findings
    resolved = [f for f in findings if "via var.db_password" in f.message]
    assert not resolved


def test_run_scope_resolution_with_a_repo_dir(tmp_path: Path, kb: KnowledgeBase) -> None:
    """Avec un repo_dir, un mot de passe à une indirection de distance dans la
    valeur par défaut d'une variable est attrapé — et la découverte nomme la
    référence pour qu'elle ne se lise pas comme un faux positif."""
    src = b"""
variable "db_password" { default = "changeme" }
resource "aws_db_instance" "prod" {
  identifier = "x"
  password   = var.db_password
}
"""
    (tmp_path / "main.tf").write_bytes(src)

    findings = run(
        [ChangedFile(path="main.tf", head_content=src)],
        kb,
        default_rules(Options()),
        RunOptions(repo_dir=str(tmp_path)),
    ).findings
    assert any("via var.db_password" in f.message for f in findings)


def test_scope_cache_refuses_to_read_outside_the_repo(tmp_path: Path, kb: KnowledgeBase) -> None:
    """Un chemin fabriqué dans la PR de quelqu'un ne doit pas transformer le
    scanner en lecteur de fichiers pour l'exécuteur d'intégration continue."""
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
    """Une équipe qui a cessé d'appliquer les garde-fous de cycle de vie sur un
    arbre historique ne doit pas pour autant cesser d'entendre parler des
    identifiants qui s'y trouvent."""
    rules = [
        ignore.PathRule(pattern="legacy/**", categories=[Category.MISSING_LIFECYCLE]),
    ]
    findings = [
        _finding("legacy/a.tf", Category.MISSING_LIFECYCLE),
        _finding("legacy/a.tf", Category.TUTORIAL_PATTERN),
    ]
    kept = ignore.apply_path_rules(findings, rules)
    assert [f.category for f in kept] == [Category.TUTORIAL_PATTERN]
