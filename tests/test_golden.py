"""Port de internal/rules/golden_test.go et golden_insecure_test.go.

Ceux-ci comparent contre **les mêmes fichiers témoins sur lesquels le scanner Go
est épinglé**, copiés tels quels dans tests/data/golden/. Cela en fait la
vérification de bout en bout la plus forte du port : chaque découverte que
produit le corpus, en entier — fichier, ligne, catégorie, sévérité, ressource,
message, suggestion, et le correctif en un clic avec sa note. Une règle dont la
formulation a dérivé d'un caractère, une sévérité qui a bougé, un correctif qui
a silencieusement cessé d'être produit : tout cela échoue ici.

Le rendu ci-dessous reproduit `renderFindings` octet pour octet, parce que c'est
le format dans lequel les fichiers témoins sont écrits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tfpdf.parser import build_scope, parse_file_with_context
from tfpdf.report.finding import Finding
from tfpdf.rules import FileInput, Options, builtin_pack, default_rules, rules_for_category
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
    """Aplatit une découverte en une ligne par champ qui compte, correctif en un
    clic inclus. Un correctif qui cesse silencieusement d'être produit est une
    régression qu'une comparaison sur le seul message manquerait."""
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
    src = (FIXTURES / name).read_bytes()
    # Parsed with a scope built from the fixture itself, so a value reached
    # through a variable default resolves and sets resolved_from. Without it
    # the corpus would never exercise the branch where a finding names the
    # reference and deliberately withholds the one-click fix — the line under
    # that finding is already correct.
    scope = build_scope({name: src})
    resources = parse_file_with_context(name, src, scope)
    return FileInput(path=name, head_resources=resources, head_source=src)


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
    """Les détecteurs de motif de tutoriel sont ceux qui ont un vrai contenu de
    détection — tables d'expressions régulières, planchers d'entropie,
    vocabulaire de valeurs de remplissage — et ce sont aussi ceux qui ont déjà
    livré un faux positif.

    Ce fichier témoin est le garde-fou : chaque découverte que produit le
    corpus, en entier, épinglée. Une migration qui change une sévérité, retire
    une branche ou remanie un message doit le dire à voix haute en réécrivant ce
    fichier.
    """
    rule = rules_for_category(builtin_pack(), "tutorial_pattern", Options())

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
    """Le groupe insecure_config est épinglé contre le jeu de règles par défaut
    COMPLET plutôt que contre les détecteurs d'une seule catégorie, et contre
    deux fixtures plutôt qu'une.

    Les deux choix répondent à la même faiblesse. Un témoin par catégorie prouve
    qu'une règle se déclenche encore ; il ne peut pas montrer qu'élargir le
    motif d'une règle s'est mis à rapporter en double une ligne qu'une autre
    règle couvrait déjà, parce que l'autre règle ne tourne pas. Et un corpus de
    cas positifs seulement prouve la détection et ne dit rien du bruit — qui est
    le mode de défaillance qui compte vraiment ici, puisqu'un scanner que les
    gens mettent en sourdine ne trouve plus rien du tout.

    insecure_config_clean.tf est donc dans le même témoin. Ses découvertes sont
    censées être exactement celles que produisent les autres catégories
    (missing_lifecycle sur les types porteurs d'état) et rien de ce groupe-ci.
    """
    ruleset = default_rules(Options())

    got: list[str] = []
    for name in ("insecure_config.tf", "insecure_config_clean.tf"):
        in_ = _file_input(name)
        for r in ruleset:
            got.extend(render_findings(r.check(in_, kb)))

    _compare(got, "insecure_config.txt")
