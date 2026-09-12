"""Detect overly broad permissions in IAM policy documents."""

from __future__ import annotations

import re

from .. import cloudname
from ..parser import Attribute, Resource
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase
from .base import FileInput

#: The attributes whose value is an IAM policy document.
#:
#: Matched by exact name rather than by suffix. "policy" as a substring appears
#: on plenty of attributes that hold a policy *name* or ARN — policy_arn,
#: iam_policy_name, ssl_policy — and reading one of those as a document would
#: produce a finding about text that is not a policy at all.
_POLICY_ATTR_NAMES = frozenset(
    {
        "policy",
        "assume_role_policy",
        "policy_document",
        "access_policy",
        "repository_policy",
        "bucket_policy",
    }
)

#: Action = "*" / "Action": "*" / Action = ["*"], in HCL object syntax or JSON.
#: NotAction is deliberately absent: it is rare, and its wildcard semantics are
#: inverted.
_WILDCARD_ACTION_RE = re.compile(r'"?\bAction"?\s*[:=]\s*(?:\[\s*)?"\*"', re.IGNORECASE)

#: Resource = "*", used only to decide whether a wildcard action is an
#: account-wide grant or merely a broad one.
_WILDCARD_RESOURCE_RE = re.compile(r'"?\bResource"?\s*[:=]\s*(?:\[\s*)?"\*"', re.IGNORECASE)

#: Principal = "*" and Principal = { AWS = "*" }, the two spellings of
#: "anyone". The optional middle group absorbs the AWS/Service wrapper without
#: allowing a nested brace, so it cannot run past the end of the principal
#: block and match an unrelated star further down.
_WILDCARD_PRINCIPAL_RE = re.compile(
    r'"?\bPrincipal"?\s*[:=]\s*(?:\{[^{}]*?"?AWS"?\s*[:=]\s*)?(?:\[\s*)?"\*"', re.IGNORECASE
)

#: Any Condition key at all. Its presence suppresses the principal check.
_CONDITION_RE = re.compile(r'"?\bCondition"?\s*[:=]', re.IGNORECASE)


class IAMWildcardRule:
    """Flag IAM policies granting all actions or access to all principals."""

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        if not file_input.head_source:
            # Without the raw source there is nothing to read: this rule's
            # whole input is the text the parser could not evaluate. Unit tests
            # that build a FileInput by hand simply get no findings, which is
            # the same contract the fix-emitting rules already have.
            return []

        findings: list[Finding] = []
        for resource in file_input.head_resources:
            # Sorted, not raw dict order: findings are compared against a golden
            # file, and source order would make that file rewrite itself when
            # someone reorders two attributes.
            for name in sorted(resource.attributes):
                if name not in _POLICY_ATTR_NAMES:
                    continue
                attribute = resource.attributes[name]
                body = attribute.range.slice(file_input.head_source).decode(
                    "utf-8", errors="replace"
                )
                if not body:
                    continue
                findings.extend(_check_policy_body(file_input.path, resource, attribute, body))
        return findings


def _check_policy_body(
    path: str, resource: Resource, attribute: Attribute, body: str
) -> list[Finding]:
    findings: list[Finding] = []

    match = _WILDCARD_ACTION_RE.search(body)
    if match is not None:
        if _WILDCARD_RESOURCE_RE.search(body):
            detail = (
                f'the IAM policy on {resource.address()} grants Action "*" on Resource "*" — '
                "this is unrestricted administrator access to the account, which is almost "
                "never what a service needs"
            )
        else:
            detail = (
                f'the IAM policy on {resource.address()} grants Action "*" — every action in '
                "every AWS service, including the IAM calls that would let a holder grant "
                "itself anything else"
            )
        findings.append(
            Finding(
                file=path,
                line=_line_of_offset(body, match.start(), attribute.range.start.line),
                category=Category.PERMISSIVE_IAM,
                rule_name="iam_wildcard",
                severity=Severity.HIGH,
                resource=resource.address(),
                cloud_name=cloudname.of(resource),
                message=detail,
                suggestion=(
                    "# Name the actions this actually needs, and the resources it needs "
                    "them on:\n"
                    'Action   = ["s3:GetObject", "s3:PutObject"]\n'
                    'Resource = ["${aws_s3_bucket.data.arn}/*"]'
                ),
            )
        )

    # A public principal narrowed by a Condition is the org-wide pattern and is
    # correct; see the class docstring for why this suppression is
    # document-wide rather than per-statement.
    if not _CONDITION_RE.search(body):
        pm = _WILDCARD_PRINCIPAL_RE.search(body)
        if pm is not None:
            findings.append(
                Finding(
                    file=path,
                    line=_line_of_offset(body, pm.start(), attribute.range.start.line),
                    category=Category.PERMISSIVE_IAM,
                    rule_name="iam_wildcard",
                    severity=Severity.HIGH,
                    resource=resource.address(),
                    cloud_name=cloudname.of(resource),
                    message=(
                        f'the policy on {resource.address()} names Principal "*" with no '
                        "Condition — this grants the listed actions to every AWS account "
                        "on earth, not to every principal in yours"
                    ),
                    suggestion=(
                        '# Name the accounts or roles, or keep "*" and narrow it:\n'
                        "Condition = {\n"
                        '  StringEquals = { "aws:PrincipalOrgID" = "o-example" }\n'
                        "}"
                    ),
                )
            )

    return findings


def _line_of_offset(body: str, offset: int, start_line: int) -> int:
    """Convert an attribute-relative text offset to a source line so nested wildcard findings point
    to their actual location.
    """
    if offset < 0 or offset > len(body):
        return start_line
    return start_line + body[:offset].count("\n")
