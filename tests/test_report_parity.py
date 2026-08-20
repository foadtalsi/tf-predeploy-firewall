"""Test différentiel : chaque sortie rendue comparée octet pour octet à celle
de l'implémentation Go.

`internal/report` n'a aucun test couvrant SARIF ou Code Quality, et ceux qu'il a
vérifient des sous-chaînes — `strings.Contains(out, "Merge blocked")`. C'est
assez pour attraper un moteur de rendu qui a cessé de fonctionner et pas assez
pour en attraper un qui a dérivé. Ces sorties sont consommées par des machines
configurées contre la version Go : GitHub Code Scanning ingère le SARIF, le
widget de MR de GitLab analyse le rapport Code Quality, et une nouvelle
exécution reconnaît ses propres commentaires passés par une empreinte du
correctif rendu.

Les oracles de `data/oracles/` ont été produits par le paquet Go lui-même sur un
jeu de découvertes délibérément retors — les caractères que l'encodeur JSON de
Go échappe et que celui de Python n'échappe pas (`<`, `>`, `&`), du non-ASCII
que Python échappe et que Go n'échappe pas, une découverte sous dérogation, une
URL de documentation, un correctif multiligne avec une note, et une catégorie de
règle personnalisée sans entrée dans le pack.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tfpdf.report import (
    Category,
    Finding,
    Fix,
    Severity,
    gitlab_suggestion_body,
    render_code_quality,
    render_markdown,
    render_rule_docs,
    render_sarif,
    review_comment_body,
    sarif,
)

ORACLES = Path(__file__).parent / "data" / "oracles"
DATA = Path(__file__).parent / "data"


def _oracle_findings() -> list[Finding]:
    """Le même jeu que `zz_tmp_oracle_test.go` rend du côté Go."""
    return [
        Finding(
            file="rds.tf",
            line=12,
            category=Category.TUTORIAL_PATTERN,
            severity=Severity.CRITICAL,
            resource="aws_db_instance.prod",
            message='password = "hunter2" — hardcoded credential (a & b < c > d)',
            doc_url=(
                "https://registry.terraform.io/providers/hashicorp/aws/5.31.0"
                "/docs/resources/db_instance"
            ),
            fix=Fix(
                start_line=12,
                end_line=12,
                lines=["  password = var.db_password"],
                note='You also need to declare `variable "db_password"`.',
            ),
        ),
        Finding(
            file="s3.tf",
            line=3,
            category=Category.PUBLIC_EXPOSURE,
            severity=Severity.HIGH,
            resource="aws_s3_bucket_public_access_block.logs",
            message="block_public_acls = false — bucket ACLs may grant public read",
            suggestion="block_public_acls = true\nblock_public_policy = true",
        ),
        Finding(
            file="iam.tf",
            line=40,
            category=Category.MISSING_LIFECYCLE,
            severity=Severity.MEDIUM,
            resource="aws_db_instance.legacy",
            message="no prevent_destroy guard",
            waived=True,
            waiver_note="legacy repo, ticketed as INFRA-42",
        ),
        Finding(
            file="main.tf",
            line=1,
            category="custom:no-iam-users",
            severity=Severity.LOW,
            resource="aws_iam_user.bob",
            message="Use aws_iam_role instead",
            fix=Fix(
                start_line=1,
                end_line=4,
                lines=['resource "aws_iam_role" "bob" {', '  name = "bob"', "}"],
            ),
        ),
    ]


@pytest.fixture
def stamped_version() -> Iterator[None]:
    """L'oracle a été rendu avec la version de pilote que l'exécution Go a
    estampillée."""
    before = sarif.TOOL_VERSION
    sarif.set_tool_version("1.4.2")
    yield
    sarif.set_tool_version(before)


@pytest.mark.usefixtures("stamped_version")
def test_sarif_matches_the_go_implementation() -> None:
    """34 Ko de JSON, y compris la documentation Markdown complète de chaque
    règle.

    Un seul caractère de différence dans l'échappement, l'ordre des clés ou
    l'indentation fait échouer ceci — ce qui est le propos, puisque rien d'autre
    ne vérifie le SARIF.
    """
    want = (ORACLES / "oracle_sarif.json").read_bytes()
    assert render_sarif(_oracle_findings()) == want


def test_code_quality_matches_the_go_implementation() -> None:
    want = (ORACLES / "oracle_codequality.json").read_bytes()
    assert render_code_quality(_oracle_findings()) == want


def test_code_quality_escapes_html_the_way_go_does() -> None:
    """Épinglé séparément parce que c'est la seule différence qui survivrait à
    un test d'aller-retour JSON : `json.loads` sur l'une ou l'autre sortie donne
    le même objet, donc seule une comparaison d'octets l'attrape. GitLab indexe
    l'historique de ses problèmes sur l'empreinte, pas sur les octets, mais un
    scanner dont la sortie change de forme le jour où il change de langage est un
    scanner que personne ne peut comparer."""
    out = render_code_quality(_oracle_findings()).decode()
    assert "\\u0026" in out and "\\u003c" in out and "\\u003e" in out
    assert "—" in out, "non-ASCII stays raw UTF-8, as Go emits it"


def test_markdown_matches_the_go_implementation() -> None:
    want = (ORACLES / "oracle_markdown.md").read_text(encoding="utf-8")
    assert render_markdown(_oracle_findings(), Severity.HIGH, True) == want


def test_review_bodies_match_the_go_implementation() -> None:
    """Les deux grammaires de bloc, et le marqueur de correctif que chacune
    porte.

    Le marqueur est un SHA-256 du correctif rendu : ceci épingle donc aussi
    l'entrée du hachage — un marqueur qui différerait ferait reposter à la
    version Python chaque suggestion que la version Go avait déjà laissée sur une
    PR ouverte.
    """
    parts: list[str] = []
    for f in _oracle_findings():
        if f.fix is None:
            continue  # the guard the CLI applies; see the note in test_go_defect
        parts.append(f"=== {f.resource}\n")
        parts.append(review_comment_body(f))
        parts.append("--- gitlab\n")
        parts.append(gitlab_suggestion_body(f))

    want = (ORACLES / "oracle_review.txt").read_text(encoding="utf-8")
    assert "".join(parts) == want


def test_rule_docs_match_the_committed_go_generated_file(
    pytestconfig: pytest.Config,
) -> None:
    """docs/rules.md est généré, et chaque `helpUri` SARIF pointe dedans.

    Une catégorie sans section là-bas est un lien mort dans le tableau de bord de
    sécurité de qui a ingéré le SARIF : l'arbre Go régénère donc et compare le
    fichier dans `TestRuleDocs_FileMatchesThePack`. `data/rules.md` est ce
    fichier, tel quel : ceci vérifie que le moteur de rendu Python produit les
    mêmes 604 lignes depuis le même pack.

    `--update-docs` réécrit la copie propre à ce paquet, ce qui est le port du
    drapeau `-update` de Go. Il ne touche pas à `data/rules.md` — c'est l'oracle,
    et un test qui pourrait réécrire ce contre quoi il compare ne vérifierait
    rien.
    """
    got = render_rule_docs()

    if pytestconfig.getoption("--update-docs"):
        out = Path(__file__).parent.parent / "docs" / "rules.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(got, encoding="utf-8")
        pytest.skip(f"wrote {out}")

    want = (DATA / "rules.md").read_text(encoding="utf-8")
    assert got == want
