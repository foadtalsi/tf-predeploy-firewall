"""Port de internal/terragrunt/terragrunt_test.go, cas pour cas."""

from __future__ import annotations

import pytest

from tfpdf.hcl import HCLParseError
from tfpdf.report.finding import Category, Severity
from tfpdf.terragrunt import scan_file


def test_flags_hardcoded_credential_in_inputs() -> None:
    """« password » (exact) correspond au motif de nom d'identifiant de la même
    façon qu'un attribut de ressource .tf littéralement nommé `password` — un
    nom préfixé comme db_password NE correspond PAS, par conception (le même
    motif que celui de la règle .tf) ; seule la vérification du motif de valeur
    l'attraperait."""
    findings = scan_file(
        "live/prod/terragrunt.hcl",
        b"""
inputs = {
  environment = "prod"
  password    = "SuperSecretPlaintext1"
}
""",
    )
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.category is Category.TUTORIAL_PATTERN
    assert f.severity is Severity.CRITICAL
    assert f.resource == "inputs"


def test_flags_credential_value_pattern_regardless_of_key_name() -> None:
    findings = scan_file(
        "terragrunt.hcl",
        b"""
inputs = {
  some_setting = "AKIAABCDEFGHIJKLMNOP"
}
""",
    )
    assert len(findings) == 1, findings


def test_flags_open_cidr_in_remote_state_config() -> None:
    findings = scan_file(
        "terragrunt.hcl",
        b"""
remote_state {
  backend = "s3"
  config = {
    allowed_cidr = "0.0.0.0/0"
  }
}
""",
    )
    assert len(findings) == 1, findings
    assert findings[0].severity is Severity.HIGH
    assert findings[0].resource == "remote_state.config"


def test_recurses_into_nested_maps() -> None:
    findings = scan_file(
        "terragrunt.hcl",
        b"""
inputs = {
  database = {
    host     = "db.internal"
    password = "AnotherSecretValueHere"
  }
}
""",
    )
    assert len(findings) == 1, findings
    assert findings[0].resource == "inputs.database"


def test_clean_inputs_produce_no_findings() -> None:
    findings = scan_file(
        "terragrunt.hcl",
        b"""
inputs = {
  environment = "prod"
  instance_count = 3
}
""",
    )
    assert findings == []


def test_skips_variable_references_gracefully() -> None:
    """Des entrées qui référencent des locals ou des sorties de dépendance ne
    peuvent pas être évaluées sans portée — elles doivent être sautées, pas
    traitées comme une erreur."""
    findings = scan_file(
        "terragrunt.hcl",
        b"""
locals {
  env = "prod"
}
inputs = {
  environment = local.env
  db_password = dependency.rds.outputs.password
}
""",
    )
    assert findings == [], findings


def test_invalid_hcl_raises() -> None:
    with pytest.raises(HCLParseError):
        scan_file("terragrunt.hcl", b"inputs = { this is not valid HCL")
