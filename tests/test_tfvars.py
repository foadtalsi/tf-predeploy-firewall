"""Port de internal/tfvars/tfvars_test.go, cas pour cas."""

from __future__ import annotations

import pytest

from tfpdf.hcl import HCLParseError
from tfpdf.report.finding import Finding, Severity
from tfpdf.tfvars import is_tfvars_path, scan_file


def messages(findings: list[Finding]) -> str:
    return "".join(f"{f.resource}: {f.message}\n" for f in findings)


def test_catches_a_credential_by_name() -> None:
    """Le cas pour lequel ce module existe. Quand on leur dit de sortir un
    secret de main.tf, les gens le déplacent dans terraform.tfvars — et
    commitent ça."""
    findings = scan_file(
        "terraform.tfvars",
        b"""
region      = "eu-west-1"
db_password = "hunter2"
instance_ct = 3
""",
    )
    assert len(findings) == 1, messages(findings)
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.resource == "db_password"
    assert f.line == 3

    # A secret in a committed file is already disclosed; deleting the line is
    # not the fix, and the message has to say so.
    assert "rotate" in f.message
    # …but the same scan runs pre-commit, where nothing is disclosed yet and
    # "already committed" would be a false alarm. The rotation advice must be
    # stated as a condition, not as a fact.
    assert "committed in a" not in f.message
    assert "If this file is already committed" in f.message


def test_recurses_into_objects_and_lists() -> None:
    """Une valeur .tfvars peut être un objet de réglages ; un identifiant niché
    dedans n'en est pas moins commité."""
    got = messages(
        scan_file(
            "prod.auto.tfvars",
            b"""
database = {
  host     = "db.internal"
  password = "hunter2"
}
allowed_cidrs = ["10.0.0.0/8", "0.0.0.0/0"]
""",
        )
    )
    assert "database.password" in got
    assert "0.0.0.0/0" in got


def test_catches_credential_shapes_and_entropy() -> None:
    got = messages(
        scan_file(
            "terraform.tfvars",
            b"""
some_opaque_setting = "AKIAIOSFODNN7EXAMPLE"
another_setting     = "Vt5wYq2Jn8RkLp3zXcB7dHm4gFa9eSu6TbNr"
""",
        )
    )
    assert "AWS access key" in got
    assert "high-entropy" in got


def test_stays_quiet_on_ordinary_values() -> None:
    """Les faux positifs sont ce qui fait désactiver un scanner. Un fichier
    .tfvars est surtout de la configuration ordinaire et doit rester
    silencieux."""
    findings = scan_file(
        "terraform.tfvars",
        b"""
region          = "eu-west-1"
instance_type   = "t3.medium"
instance_count  = 3
enable_backups  = true
vpc_cidr        = "10.0.0.0/16"
bucket_arn      = "arn:aws:s3:::prod-logs-eu-west-1-longish-name"
tags            = { owner = "platform", env = "production" }
public_key      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ1x2y3z4"
subnet_ids      = ["subnet-0a1b2c3d4e5f6a7b8", "subnet-1b2c3d4e5f6a7b8c9"]
""",
    )
    assert findings == [], messages(findings)


def test_skips_unresolvable_values() -> None:
    """Une valeur que le scanner ne peut pas résoudre ne doit jamais être
    devinée."""
    findings = scan_file("terraform.tfvars", b'password = file("secret.txt")')
    assert findings == [], messages(findings)


def test_handles_the_json_form() -> None:
    got = messages(
        scan_file(
            "terraform.tfvars.json",
            b"""{
  "region": "eu-west-1",
  "db_password": "hunter2",
  "database": {"admin_password": "s3cret"}
}""",
        )
    )
    assert "db_password" in got
    assert "database.admin_password" in got


def test_reports_parse_errors() -> None:
    """Un fichier que le scanner ne peut pas lire est un trou que l'appelant
    doit rapporter, pas un trou qu'il doit sauter en silence."""
    with pytest.raises(HCLParseError):
        scan_file("bad.tfvars", b"this is = not ( valid")
    with pytest.raises(ValueError):
        scan_file("bad.tfvars.json", b"{not json")


@pytest.mark.parametrize(
    "path", ["terraform.tfvars", "prod.auto.tfvars", "a/b/x.tfvars", "terraform.tfvars.json"]
)
def test_is_tfvars_path_recognises(path: str) -> None:
    assert is_tfvars_path(path)


@pytest.mark.parametrize("path", ["main.tf", "terragrunt.hcl", "vars.tf", "notes.txt"])
def test_is_tfvars_path_rejects(path: str) -> None:
    assert not is_tfvars_path(path)
