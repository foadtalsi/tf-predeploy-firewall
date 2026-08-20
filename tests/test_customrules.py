"""Port de internal/customrules/customrules_test.go, cas pour cas."""

from __future__ import annotations

import pytest

from tfpdf import customrules
from tfpdf.parser import parse_file
from tfpdf.report.finding import Finding, Severity
from tfpdf.rules import FileInput


def _check(yaml_src: str, tf_src: str) -> list[Finding]:
    cfg = customrules.load(yaml_src)
    resources = parse_file("test.tf", tf_src.encode())
    return cfg.as_engine_rule().check(FileInput(path="test.tf", head_resources=resources), None)


@pytest.mark.parametrize(
    ("name", "yaml_src"),
    [
        (
            "missing id",
            'custom_rules: [{resource_type: aws_s3_bucket, severity: high, message: x, pattern: "y"}]',
        ),
        (
            "missing resource_type",
            'custom_rules: [{id: r1, severity: high, message: x, pattern: "y"}]',
        ),
        (
            "bad severity",
            'custom_rules: [{id: r1, resource_type: "*", severity: extreme, message: x, pattern: "y"}]',
        ),
        (
            "missing message",
            'custom_rules: [{id: r1, resource_type: "*", severity: high, pattern: "y"}]',
        ),
        (
            "bad regex",
            'custom_rules: [{id: r1, resource_type: "*", severity: high, message: x, pattern: "("}]',
        ),
        (
            "attribute without pattern",
            'custom_rules: [{id: r1, resource_type: "*", severity: high, message: x, attribute: acl}]',
        ),
    ],
)
def test_load_validates_required_fields(name: str, yaml_src: str) -> None:
    with pytest.raises(customrules.CustomRuleError):
        customrules.load(yaml_src)


def test_existence_rule() -> None:
    findings = _check(
        """
custom_rules:
  - id: no-iam-users
    resource_type: aws_iam_user
    severity: medium
    message: "Use aws_iam_role instead of aws_iam_user"
""",
        """
resource "aws_iam_user" "bob" {
  name = "bob"
}
resource "aws_iam_role" "app" {
  name = "app"
}
""",
    )
    assert len(findings) == 1, findings
    assert findings[0].resource == "aws_iam_user.bob"
    assert str(findings[0].category) == "custom:no-iam-users"
    assert findings[0].severity is Severity.MEDIUM


def test_pattern_rule_on_attribute() -> None:
    findings = _check(
        """
custom_rules:
  - id: no-public-acl
    resource_type: aws_s3_bucket
    attribute: acl
    pattern: "public"
    severity: high
    message: "S3 bucket ACL must not be public"
""",
        """
resource "aws_s3_bucket" "logs" {
  acl = "public-read"
}
resource "aws_s3_bucket" "private" {
  acl = "private"
}
""",
    )
    assert len(findings) == 1, findings
    assert findings[0].resource == "aws_s3_bucket.logs"


def test_negated_rule_flags_missing_required_attribute() -> None:
    """`negate: true` est la façon d'exprimer « ceci doit être présent et
    ressembler à X » — la règle se déclenche quand le motif ne correspond pas,
    ou quand l'attribut est entièrement absent."""
    findings = _check(
        """
custom_rules:
  - id: require-env-tag
    resource_type: aws_instance
    attribute: environment_tag
    pattern: ".+"
    negate: true
    severity: low
    message: "aws_instance must set environment_tag"
""",
        """
resource "aws_instance" "tagged" {
  environment_tag = "prod"
}
resource "aws_instance" "untagged" {
  ami = "ami-123"
}
""",
    )
    assert len(findings) == 1, findings
    assert findings[0].resource == "aws_instance.untagged"


def test_block_scoped_rule() -> None:
    findings = _check(
        """
custom_rules:
  - id: no-wide-open-ingress
    resource_type: "*"
    block: ingress
    attribute: cidr_blocks
    pattern: "0\\\\.0\\\\.0\\\\.0/0"
    severity: critical
    message: "ingress block allows 0.0.0.0/0"
""",
        """
resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}
""",
    )
    assert len(findings) == 1, findings
    assert findings[0].severity is Severity.CRITICAL


def test_non_literal_attribute_is_not_guessed() -> None:
    """Un attribut qui référence une variable ne peut pas être apparié à un
    motif. Ne pas deviner est la même règle que suit le reste de l'outil."""
    findings = _check(
        """
custom_rules:
  - id: no-public-acl
    resource_type: aws_s3_bucket
    attribute: acl
    pattern: "public"
    severity: high
    message: "S3 bucket ACL must not be public"
""",
        """
resource "aws_s3_bucket" "computed" {
  acl = var.bucket_acl
}
""",
    )
    assert findings == [], findings


def test_wildcard_resource_type() -> None:
    findings = _check(
        """
custom_rules:
  - id: banned-name
    resource_type: "*"
    attribute: name
    pattern: "^test"
    severity: low
    message: "no test- prefixed names"
""",
        """
resource "aws_s3_bucket" "x" {
  name = "test-bucket"
}
resource "aws_iam_role" "y" {
  name = "prod-role"
}
""",
    )
    assert len(findings) == 1, findings
    assert "aws_s3_bucket.x" in findings[0].resource


def test_negated_rule_misfires_on_an_object_valued_attribute() -> None:
    """Épingle un défaut partagé avec le scanner Go plutôt que de le cacher.

    `cty_value_to_string` rend un objet ou un map en "" — il ne traite que les
    chaînes, nombres, booléens et séquences. Une règle « doit avoir des tags »
    écrite `attribute: tags, pattern: ".+", negate: true` voit donc "" pour
    `tags = { env = "prod" }`, conclut que le motif n'a pas correspondu, et se
    déclenche sur une ressource qui définit *bien* des tags.

    Vérifié contre l'implémentation Go, qui produit les deux mêmes découvertes
    sur les deux mêmes lignes. Épinglé ici pour que le port reste fidèle et pour
    qu'une correction en amont apparaisse comme un changement délibéré des deux
    côtés plutôt que comme une divergence silencieuse.
    """
    findings = _check(
        """
custom_rules:
  - id: require-tags
    resource_type: "*"
    attribute: tags
    pattern: ".+"
    negate: true
    severity: low
    message: "every resource must set tags"
""",
        """
resource "aws_s3_bucket" "a" {
  tags = { env = "prod" }
}
resource "aws_instance" "b" {
  ami = "ami-123"
}
""",
    )
    assert [f.resource for f in findings] == ["aws_s3_bucket.a", "aws_instance.b"]


def test_empty_config_is_not_an_error() -> None:
    """La plupart des dépôts ne définissent aucune règle personnalisée ; leur
    absence ne doit jamais être une erreur."""
    assert customrules.load("").rules == []
    assert customrules.load("custom_rules: []").rules == []
