"""Regression cases from public repositories, covering false positives as well as detections.
Repository names retain the origin of each example.
"""

from __future__ import annotations

import pytest

from tfpdf import providerversion
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Finding
from tfpdf.rules import default_rules, run
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _scan(kb: KnowledgeBase, source: str, path: str = "main.tf", **extra: str) -> list[Finding]:
    """Scan in-memory module files, including sibling files that declare provider constraints."""
    files = [ChangedFile(path=path, head_content=source.encode())]
    files += [ChangedFile(path=p, head_content=c.encode()) for p, c in extra.items()]
    return run(files, kb, default_rules()).findings


# Rootly: preserve the declared provider source in suggestions.


ROOTLY = """terraform {
  required_providers {
    rootly = {
      source = "rootlyhq/rootly"
    }
  }
}
"""


def test_the_fix_never_invents_a_provider_address(kb: KnowledgeBase) -> None:
    """Preserve the declared provider source instead of inventing hashicorp addresses for
    third-party providers.
    """
    findings = [f for f in _scan(kb, ROOTLY) if f.rule_name == "unpinned_version"]
    assert len(findings) == 1, "the finding itself remains valid"
    assert "hashicorp/rootly" not in findings[0].suggestion
    assert findings[0].suggestion == "", (
        "without a known provider version, no exact fix is available — "
        "the finding still explains the missing constraint"
    )


def test_a_known_provider_still_gets_a_real_pin(kb: KnowledgeBase) -> None:
    """Use the known provider major version while preserving the declared source."""
    source = ROOTLY.replace(
        'rootly = {\n      source = "rootlyhq/rootly"', 'aws = {\n      source = "hashicorp/aws"'
    )
    finding = next(f for f in _scan(kb, source) if f.rule_name == "unpinned_version")
    version = next(p.version for p in kb.coverage().providers if p.name == "aws")
    assert 'source  = "hashicorp/aws"' in finding.suggestion
    assert f'version = "~> {version.split(".")[0]}.0"' in finding.suggestion


# wandb: a public managed-policy ARN must not match an AWS secret pattern.


def test_a_managed_policy_arn_is_not_a_leaked_secret(kb: KnowledgeBase) -> None:
    """Check the whole ARN before an unanchored credential pattern matches a substring."""
    source = """resource "aws_iam_role_policy_attachment" "ecr" {
  role       = "some-role"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}
"""
    assert not [f for f in _scan(kb, source) if f.rule_name.startswith("credential_value")]


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        # A public SSH key is not a secret.
        ("public_key", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA8sX2Y1mZ0kQnJ8"),
        # An EKS OIDC fingerprint published by its identity provider.
        ("thumbprint", "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"),
        # A publicly served DNS record.
        ("records", "gv-9f8Hs2kLmQpR4tYuVwXzAbCdEfGhIjKlMnOpQrStUv"),
    ],
)
def test_values_that_are_public_by_definition_are_not_accused(
    kb: KnowledgeBase, attribute: str, value: str
) -> None:
    """Public attributes can hold high-entropy values without containing secrets."""
    source = f'resource "aws_thing" "t" {{\n  {attribute} = "{value}"\n}}\n'
    assert not [f for f in _scan(kb, source) if f.rule_name.startswith("credential_value")]


def test_a_secret_buried_in_a_larger_value_is_still_found(kb: KnowledgeBase) -> None:
    """Whitespace must not hide known credentials embedded in scripts or larger values."""
    source = """resource "aws_instance" "app" {
  ami       = "ami-0abcdef1234567890"
  user_data = "#!/bin/bash\\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\necho ok\\n"
}
"""
    assert [f for f in _scan(kb, source) if f.rule_name == "credential_value_aws_access_key"]


# binbashar: respect the repository's pinned provider version.


PINNED_3 = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}
"""

EIP = """resource "aws_eip" "nat" {
  vpc = true
}
"""


def test_an_attribute_valid_in_the_pinned_version_is_not_called_hallucinated(
    kb: KnowledgeBase,
) -> None:
    """Do not reject an older provider's valid attribute using an incompatible newer schema."""
    findings = _scan(kb, EIP, **{"versions.tf": PINNED_3})
    assert not [f for f in findings if f.rule_name == "unknown_attribute"]


def test_the_scan_says_which_provider_it_stayed_silent_about(kb: KnowledgeBase) -> None:
    """Explicitly report skipped schema coverage."""
    files = [
        ChangedFile(path="main.tf", head_content=EIP.encode()),
        ChangedFile(path="versions.tf", head_content=PINNED_3.encode()),
    ]
    notes = run(files, kb, default_rules()).notes
    assert len(notes) == 1
    assert "~> 3.0" in notes[0] and "aws" in notes[0]


def test_a_pin_that_covers_our_schema_is_still_judged(kb: KnowledgeBase) -> None:
    """Continue schema checks when the pinned range includes the loaded schema."""
    pinned_6 = PINNED_3.replace("~> 3.0", "~> 6.0")
    findings = _scan(kb, EIP, **{"versions.tf": pinned_6})
    assert [f for f in findings if f.rule_name == "unknown_attribute"]


def test_a_pinned_provider_does_not_silence_value_rules(kb: KnowledgeBase) -> None:
    """Provider pinning must not suppress schema-independent value checks."""
    source = """resource "aws_db_instance" "prod" {
  identifier = "prod"
  password   = "hunter2correcthorsebattery"
}
"""
    findings = _scan(kb, source, **{"versions.tf": PINNED_3})
    assert [f for f in findings if f.rule_name == "hardcoded_credential"]


# Provider constraint parsing.


@pytest.mark.parametrize(
    ("constraint", "version", "allowed"),
    [
        ("~> 3.0", "3.75.2", True),
        ("~> 3.0", "4.0.0", False),
        ("~> 3.0.1", "3.0.9", True),
        ("~> 3.0.1", "3.1.0", False),
        # A lower bound without an upper bound permits the next major version.
        (">= 3.93.0", "4.81.0", True),
        (">= 4.0, < 5.0", "4.81.0", True),
        (">= 4.0, < 5.0", "5.0.0", False),
        ("= 6.59.0", "6.59.0", True),
        ("!= 6.59.0", "6.59.0", False),
        # Without a constraint, use the loaded schema.
        ("", "6.59.0", True),
        # An unreadable constraint must not silently suppress valid findings.
        ("something odd", "6.59.0", True),
    ],
)
def test_terraform_version_constraints(constraint: str, version: str, allowed: bool) -> None:
    assert providerversion.allows(constraint, version) is allowed


def test_constraints_are_read_from_the_short_form_too() -> None:
    """Support the legacy shorthand provider constraint syntax."""
    source = b'terraform {\n  required_providers {\n    aws = "~> 5.0"\n  }\n}\n'
    assert providerversion.constraints_in(source) == {"aws": "~> 5.0"}
