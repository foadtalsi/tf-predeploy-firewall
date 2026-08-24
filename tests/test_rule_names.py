"""Chaque découverte dit de quelle règle elle vient.

`Finding.rule_name` est renseigné à la main sur une vingtaine de sites de
construction, ce qui est la façon lisible de le faire et aussi celle qu'on peut
oublier. Ce fichier est la contrepartie : il balaye le paquet source à la
recherche d'un site qui n'aurait pas de nom, puis vérifie que les noms
correspondent bien au registre qui fait foi — le pack de règles.

Sans lui, une règle ajoutée demain produirait des découvertes anonymes, et le
code qui trie sur `rule_name` les ignorerait en silence.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from tfpdf import ruledef
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Finding
from tfpdf.rules import Options, default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema

SRC = pathlib.Path(__file__).parent.parent / "src" / "tfpdf"

#: Les règles qui vivent hors du pack : elles scannent des fichiers qui ne sont
#: pas du .tf (terragrunt.hcl, .tfvars) et n'ont donc pas de type de ressource
#: auquel une entrée de pack pourrait s'accrocher. Énumérées ici plutôt que
#: devinées, pour qu'un nom inventé au hasard ressorte comme un échec.
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
    """Tout appel `Finding(...)` du paquet, avec l'endroit où il se trouve."""
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
    """Le balayage.

    Une exception : le moteur construit une découverte pour un fichier qu'il
    n'a pas su analyser, qui ne vient d'aucune règle. Elle est nommée
    explicitement dans la liste ci-dessous plutôt que tolérée par une
    condition, pour qu'un second site anonyme ne se glisse pas dessous.
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

    assert not anonymous, "des découvertes sans nom de règle : " + ", ".join(anonymous)


def test_every_literal_rule_name_is_one_the_registry_knows() -> None:
    """Une faute de frappe dans un nom écrit à la main est indétectable à
    l'exécution : la découverte sort avec un nom que rien ne rapproche du pack,
    et le code qui filtre dessus ne trouve simplement jamais rien."""
    known = _pack_rule_ids() | NAMES_OUTSIDE_THE_PACK
    unknown = []
    for path, lineno, call in _finding_sites():
        keyword = next((k for k in call.keywords if k.arg == "rule_name"), None)
        if keyword is None or not isinstance(keyword.value, ast.Constant):
            continue  # spec.id / "custom:" + id, vérifiés par les tests suivants
        if keyword.value.value not in known:
            unknown.append(f"{path}:{lineno} -> {keyword.value.value!r}")

    assert not unknown, "noms de règle inconnus du registre : " + ", ".join(unknown)


def test_the_names_outside_the_pack_do_not_shadow_a_pack_rule() -> None:
    """La liste d'exceptions ne doit pas devenir une porte dérobée pour
    redéfinir un identifiant du pack sous un autre code."""
    assert not (NAMES_OUTSIDE_THE_PACK & _pack_rule_ids())


def test_a_declarative_rule_carries_its_pack_id() -> None:
    """Le cas qui motive tout : deux règles différentes, même catégorie, même
    ressource. `category` ne les sépare pas ; `rule_name` oui."""
    source = b"""resource "aws_s3_bucket" "backups" {
  bucket        = "prod-backups"
  force_destroy = true
}
"""
    findings = _scan(source)
    names = {f.rule_name for f in findings}

    assert "s3_force_destroy" in names
    assert "missing_lifecycle" in names
    # Elles se ressemblaient sur tout le reste.
    assert len({f.category for f in findings}) == 1
    assert len({f.resource for f in findings}) == 1


def test_no_finding_from_a_real_scan_comes_out_anonymous(kb: KnowledgeBase) -> None:
    """Le balayage statique ne voit pas les découvertes construites par une
    fabrique partagée. Celui-ci les voit toutes, mais seulement pour le code
    que le corpus atteint réellement — les deux sont nécessaires."""
    corpus = pathlib.Path(__file__).parent / "data" / "corpus_fixtures"
    changed = [
        ChangedFile(path=f.name, head_content=f.read_bytes()) for f in sorted(corpus.glob("*.tf"))
    ]
    assert changed, "le corpus doit contenir des fichiers"

    findings = run(changed, kb, default_rules(Options())).findings
    assert findings, "le corpus doit produire des découvertes"

    anonymous = [f"{f.file}:{f.line} {f.category}" for f in findings if not f.rule_name]
    assert not anonymous, "découvertes anonymes : " + ", ".join(anonymous)


def _scan(source: bytes) -> list[Finding]:
    return run(
        [ChangedFile(path="s3.tf", head_content=source)],
        load_schema(),
        default_rules(Options()),
    ).findings
