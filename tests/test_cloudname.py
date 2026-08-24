"""Le nom réel d'une ressource chez le fournisseur.

Ce que ce fichier protège n'est pas la table — c'est le sens du vide. Une
chaîne vide veut dire « je ne sais pas », et l'appelant qui la prendrait pour
un nom interrogerait le cloud avec, recevrait « cet objet n'existe pas », et
en conclurait qu'il n'y a rien à perdre. L'erreur va donc dans le sens
dangereux, et c'est pour ça que chaque façon de ne pas savoir a son cas ici.
"""

from __future__ import annotations

import pytest

from tfpdf import cloudname
from tfpdf.diff import ChangedFile
from tfpdf.parser import parse_file
from tfpdf.report.finding import Severity
from tfpdf.rules import Options, RunOptions, default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema


def _resource(source: bytes, name: str = "a"):  # type: ignore[no-untyped-def]
    return next(r for r in parse_file("t.tf", source) if r.name == name)


def test_the_naming_attribute_is_not_called_name_on_every_type() -> None:
    """Le cœur de la table : trois types, trois attributs différents. C'est ce
    qui interdit un simple `attributes["name"]`."""
    cases = [
        (b'resource "aws_s3_bucket" "a" { bucket = "prod-backups" }', "prod-backups"),
        (b'resource "aws_db_instance" "a" { identifier = "prod-db" }', "prod-db"),
        (b'resource "aws_lambda_function" "a" { function_name = "resize" }', "resize"),
    ]
    for source, expected in cases:
        assert cloudname.of(_resource(source)) == expected


def test_the_name_attribute_of_a_database_is_not_its_identifier() -> None:
    """Le cas qui interdit un repli sur `name`.

    Sur `aws_db_instance`, `name` désigne la base créée *dans* l'instance, pas
    l'instance. Un repli rendrait « appdb » là où l'API attend « prod-db » —
    et « cette instance n'existe pas » est exactement la réponse qui fait
    baisser une sévérité à tort.
    """
    resource = _resource(b'resource "aws_db_instance" "a" { name = "appdb" }')
    assert cloudname.of(resource) == ""


def test_a_type_the_table_does_not_cover_says_so() -> None:
    resource = _resource(b'resource "aws_quantum_widget" "a" { name = "w" }')
    assert cloudname.of(resource) == ""


def test_a_name_built_at_apply_time_is_not_a_name() -> None:
    """`var.x` sans portée pour le résoudre : on ne sait pas, et on le dit."""
    resource = _resource(b'resource "aws_s3_bucket" "a" { bucket = var.bucket_name }')
    assert cloudname.of(resource) == ""


def test_an_interpolated_name_is_not_a_name() -> None:
    resource = _resource(b'resource "aws_s3_bucket" "a" { bucket = "pre-${var.env}" }')
    assert cloudname.of(resource) == ""


def test_a_missing_attribute_is_not_a_name() -> None:
    """`bucket` est facultatif — sans lui le fournisseur en génère un, qui
    n'est donc dans aucun fichier."""
    resource = _resource(b'resource "aws_s3_bucket" "a" { force_destroy = true }')
    assert cloudname.of(resource) == ""


def test_a_data_source_has_no_name_to_give() -> None:
    """Un `data` lit une ressource existante ; ce n'est pas cette PR qui la
    crée, et les règles de cycle de vie ne s'y appliquent pas."""
    resource = _resource(b'data "aws_s3_bucket" "a" { bucket = "prod-backups" }')
    assert cloudname.of(resource) == ""


def test_every_entry_in_the_table_names_a_plausible_attribute() -> None:
    """Garde-fou contre une entrée ajoutée à la va-vite : une clé vide ou un
    type sans préfixe de fournisseur est une faute de frappe, pas une
    affirmation sur un schéma."""
    for resource_type, attribute in cloudname.NAME_ATTRIBUTE_BY_TYPE.items():
        assert "_" in resource_type, resource_type
        assert attribute and attribute.islower(), (resource_type, attribute)


# --- de bout en bout --------------------------------------------------------


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def test_a_finding_carries_both_the_address_and_the_real_name(kb: KnowledgeBase) -> None:
    """Les deux, parce qu'ils servent à deux choses : l'adresse situe la
    découverte dans la PR, le nom réel est ce qu'une API comprend."""
    source = b"""resource "aws_s3_bucket" "backups" {
  bucket        = "prod-backups"
  force_destroy = true
}
"""
    findings = run(
        [ChangedFile(path="s3.tf", head_content=source)], kb, default_rules(Options())
    ).findings
    force_destroy = next(f for f in findings if f.rule_name == "s3_force_destroy")

    assert force_destroy.resource == "aws_s3_bucket.backups"
    assert force_destroy.cloud_name == "prod-backups"


def test_the_severity_check_is_not_called_without_the_opt_in(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La garde qui rend vraie la phrase de la page d'accueil : sans
    `--cloud-read-access`, le scanner ne demande rien à personne."""
    import botocore.client

    calls: list[str] = []
    monkeypatch.setattr(
        botocore.client.BaseClient,
        "_make_api_call",
        lambda self, name, params: calls.append(name),
    )
    source = b"""resource "aws_s3_bucket" "backups" {
  bucket        = "prod-backups"
  force_destroy = true
}
"""
    result = run([ChangedFile(path="s3.tf", head_content=source)], kb, default_rules(Options()))

    assert calls == []
    assert (
        next(f for f in result.findings if f.rule_name == "s3_force_destroy").severity
        is Severity.MEDIUM
    )


def test_with_the_opt_in_the_check_receives_the_real_bucket_name(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le défaut que ce champ existe pour éviter : passer `finding.resource`
    enverrait « aws_s3_bucket.backups » à S3."""
    received: list[str] = []

    def check(severity: Severity, bucket: str) -> str:
        received.append(bucket)
        return "critical"

    # La sonde est simulée, sinon ce test dépend des identifiants AWS de la
    # machine : il passait en local (où il en existe) et échouait en CI, pour
    # une raison qui n'a rien à voir avec ce qu'il vérifie. Et une suite de
    # tests ne doit appeler personne.
    monkeypatch.setattr("tfpdf.ruledef.severitycheck.available_context", lambda: True)
    monkeypatch.setattr("tfpdf.ruledef.severitycheck.s3_force_destroy_severity_check", check)
    source = b"""resource "aws_s3_bucket" "backups" {
  bucket        = "prod-backups"
  force_destroy = true
}
"""
    result = run(
        [ChangedFile(path="s3.tf", head_content=source)],
        kb,
        default_rules(Options()),
        RunOptions(cloud_reader=object()),
    )

    assert received == ["prod-backups"]
    finding = next(f for f in result.findings if f.rule_name == "s3_force_destroy")
    # La conversion : la vérification rend une chaîne nue, le champ doit rester
    # une Severity ou le seuil de blocage comparerait deux types.
    assert finding.severity is Severity.CRITICAL


def test_a_bucket_whose_name_is_a_variable_is_never_looked_up(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sans nom réel, pas de question — et surtout pas une question dont la
    réponse ferait baisser la sévérité."""
    called: list[str] = []
    # Simulée elle aussi : sans cela le test serait vert parce que la sonde a
    # échoué, et non parce que le nom n'a pas pu être établi.
    monkeypatch.setattr("tfpdf.ruledef.severitycheck.available_context", lambda: True)
    monkeypatch.setattr(
        "tfpdf.ruledef.severitycheck.s3_force_destroy_severity_check",
        lambda severity, bucket: called.append(bucket) or "low",
    )
    source = b"""resource "aws_s3_bucket" "backups" {
  bucket        = var.bucket_name
  force_destroy = true
}
"""
    result = run(
        [ChangedFile(path="s3.tf", head_content=source)],
        kb,
        default_rules(Options()),
        RunOptions(cloud_reader=object()),
    )

    assert called == []
    assert (
        next(f for f in result.findings if f.rule_name == "s3_force_destroy").severity
        is Severity.MEDIUM
    )


# --- une seule sonde par scan -----------------------------------------------


THREE_BUCKETS = b"""resource "aws_s3_bucket" "one" {
  bucket        = "bucket-one"
  force_destroy = true
}

resource "aws_s3_bucket" "two" {
  bucket        = "bucket-two"
  force_destroy = true
}

resource "aws_s3_bucket" "three" {
  bucket        = "bucket-three"
  force_destroy = true
}
"""


def test_the_account_is_probed_once_however_many_buckets_there_are(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`available_context()` ouvre une session STS et construit un client.

    Appelée depuis la vérification, elle l'était une fois par découverte : sur
    un dépôt à trente compartiments, trente allers-retours vers AWS pour
    apprendre trente fois la même chose. Elle est appelée par le moteur, avant
    la boucle.
    """
    probes: list[int] = []
    checked: list[str] = []
    monkeypatch.setattr(
        "tfpdf.ruledef.severitycheck.available_context",
        lambda: probes.append(1) or True,
    )
    monkeypatch.setattr(
        "tfpdf.ruledef.severitycheck.s3_force_destroy_severity_check",
        lambda severity, bucket: checked.append(bucket) or "critical",
    )

    run(
        [ChangedFile(path="s3.tf", head_content=THREE_BUCKETS)],
        kb,
        default_rules(Options()),
        RunOptions(cloud_reader=object()),
    )

    assert checked == ["bucket-one", "bucket-two", "bucket-three"]
    assert len(probes) == 1


def test_nothing_to_corroborate_means_no_probe_at_all(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le cas courant : une PR qui ne touche aucun `force_destroy`. Activer
    l'option ne doit pas coûter une requête AWS sur chacune de ces PR."""
    probes: list[int] = []
    monkeypatch.setattr(
        "tfpdf.ruledef.severitycheck.available_context",
        lambda: probes.append(1) or True,
    )
    source = b"""resource "aws_s3_bucket" "quiet" {
  bucket = "nothing-to-see"
}
"""
    run(
        [ChangedFile(path="s3.tf", head_content=source)],
        kb,
        default_rules(Options()),
        RunOptions(cloud_reader=object()),
    )

    assert probes == []


def test_a_context_that_cannot_be_opened_stops_before_the_checks(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sonde en échec : aucune vérification n'est tentée, et les sévérités
    restent celles du scan statique."""
    checked: list[str] = []
    monkeypatch.setattr("tfpdf.ruledef.severitycheck.available_context", lambda: False)
    monkeypatch.setattr(
        "tfpdf.ruledef.severitycheck.s3_force_destroy_severity_check",
        lambda severity, bucket: checked.append(bucket) or "low",
    )

    result = run(
        [ChangedFile(path="s3.tf", head_content=THREE_BUCKETS)],
        kb,
        default_rules(Options()),
        RunOptions(cloud_reader=object()),
    )

    assert checked == []
    assert all(
        f.severity is Severity.MEDIUM for f in result.findings if f.rule_name == "s3_force_destroy"
    )


def test_the_check_itself_never_probes(kb: KnowledgeBase) -> None:
    """La contrepartie côté `severitycheck` : la vérification lit `AWS_OK`,
    elle ne le recalcule pas. Sans quoi la sonde unique du moteur ne servirait
    à rien — la vérification en referait une par découverte."""
    import ast
    import inspect
    import textwrap

    from tfpdf.ruledef import severitycheck

    # L'arbre syntaxique et non le texte : chercher la chaîne attraperait un
    # commentaire qui nomme la fonction, et faire échouer un test parce qu'on a
    # documenté le code est la meilleure façon d'apprendre à le désactiver.
    tree = ast.parse(
        textwrap.dedent(inspect.getsource(severitycheck.s3_force_destroy_severity_check))
    )
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "available_context" not in called
