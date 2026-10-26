"""False positives reported from real repositories, and the line each fix draws.

Placeholders are not secrets, the entropy fallback measures only names that announce a secret,
and an IAM statement is judged on its own effect and condition.
"""

from __future__ import annotations

import pytest

from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Finding
from tfpdf.rules import default_rules, run
from tfpdf.rules.entropy import looks_like_placeholder
from tfpdf.rules.iam import policy_statements
from tfpdf.schema import KnowledgeBase
from tfpdf.schema import load as load_schema


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_schema()


def _rule_names(kb: KnowledgeBase, source: str) -> list[str]:
    result = run([ChangedFile(path="main.tf", head_content=source.encode())], kb, default_rules())
    return [finding.rule_name for finding in result.findings]


def _findings(kb: KnowledgeBase, source: str, rule_name: str) -> list[Finding]:
    result = run([ChangedFile(path="main.tf", head_content=source.encode())], kb, default_rules())
    return [finding for finding in result.findings if finding.rule_name == rule_name]


@pytest.mark.parametrize(
    "value",
    [
        "REPLACE ME",
        "replace-with-your-token",
        "changeme",
        "change_me",
        "dummy-cloudflare-tokens-0123456789abcdef",
        "sk-placeholder-not-a-real-key",
        "not_a_real_secret",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
)
def test_placeholders_are_recognized(value: str) -> None:
    assert looks_like_placeholder(value)


@pytest.mark.parametrize(
    "value",
    ["Orders-db-2026-Pa55", "AKIA0Y9X18KP0M9Z1Q8T", "x8Qz!Lm2#Vp9@Rt4$Wn7%Yb1^Hd6&Kf3*Gs5"],
)
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    assert not looks_like_placeholder(value)


def test_a_placeholder_password_is_not_a_hardcoded_credential(kb: KnowledgeBase) -> None:
    source = 'resource "aws_db_instance" "db" {\n  password = "REPLACE ME"\n}\n'
    assert "hardcoded_credential" not in _rule_names(kb, source)


def test_entropy_is_not_measured_on_a_module_source(kb: KnowledgeBase) -> None:
    source = (
        'module "network" {\n'
        '  source = "git::ssh://git@github.com/acme-corp/terraform-modules.git//network?ref=9f2c7b1e4a"\n'
        "}\n"
    )
    assert "credential_value_entropy" not in _rule_names(kb, source)


def test_entropy_is_still_measured_under_a_secret_like_name(kb: KnowledgeBase) -> None:
    source = (
        'resource "aws_ssm_parameter" "p" {\n'
        '  license_key = "x8Qz!Lm2#Vp9@Rt4$Wn7%Yb1^Hd6&Kf3*Gs5"\n'
        "}\n"
    )
    assert "credential_value_entropy" in _rule_names(kb, source)


def test_a_deny_statement_grants_nothing(kb: KnowledgeBase) -> None:
    source = """resource "aws_iam_policy" "guardrail" {
  name = "guardrail"
  policy = jsonencode({
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*", Principal = "*" }]
  })
}
"""
    assert _findings(kb, source, "iam_wildcard") == []


def test_a_condition_narrows_only_its_own_statement(kb: KnowledgeBase) -> None:
    source = """resource "aws_s3_bucket_policy" "site" {
  bucket = "acme-site"
  policy = jsonencode({
    Statement = [
      { Effect = "Allow", Principal = "*", Action = "s3:GetObject",
        Condition = { StringEquals = { "aws:PrincipalOrgID" = "o-1" } } },
      { Effect = "Allow", Principal = "*", Action = "s3:ListBucket" },
    ]
  })
}
"""
    findings = _findings(kb, source, "iam_wildcard")
    assert [f.line for f in findings] == [7], "the finding points at the unconditional statement"


def test_a_policy_built_from_variables_is_still_read_as_text(kb: KnowledgeBase) -> None:
    source = """resource "aws_iam_policy" "built" {
  name = "built"
  policy = jsonencode({
    Statement = [{ Effect = var.effect, Action = "*", Resource = "*" }]
  })
}
"""
    assert policy_statements("policy = jsonencode({ Effect = var.effect })") is None
    assert len(_findings(kb, source, "iam_wildcard")) == 1


def test_a_deny_policy_document_with_a_wildcard_principal_is_a_guardrail(
    kb: KnowledgeBase,
) -> None:
    source = """data "aws_iam_policy_document" "deny_http" {
  statement {
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
"""
    assert "iam_document_wildcard_principal" not in _rule_names(kb, source)
