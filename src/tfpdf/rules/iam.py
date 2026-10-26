"""Detect overly broad permissions in IAM policy documents."""

from __future__ import annotations

import json
import re
from typing import Any

from .. import cloudname, hcl
from ..hcl import Value
from ..hcl.ast import FunctionCallExpr
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
    """Judge a policy statement by statement when its value can be evaluated, and fall back to
    reading its text when it cannot."""
    statements = policy_statements(body)
    if statements is None:
        return _check_policy_text(path, resource, attribute, body)

    # The wildcard spellings found in the text, in order. The n-th statement carrying a
    # wildcard is the n-th match, which is how a finding points at its own statement.
    action_offsets = [match.start() for match in _WILDCARD_ACTION_RE.finditer(body)]
    principal_offsets = [match.start() for match in _WILDCARD_PRINCIPAL_RE.finditer(body)]

    action_finding: Finding | None = None
    principal_finding: Finding | None = None
    statements_with_wildcard_action = 0
    statements_with_wildcard_principal = 0
    for statement in statements:
        # A Deny grants nothing: denying every action or every principal is a guardrail.
        allows = str(statement.get("Effect", "Allow")) != "Deny"

        if _names_wildcard(statement.get("Action")):
            if allows and action_finding is None:
                action_finding = _wildcard_action_finding(
                    path,
                    resource,
                    attribute,
                    body,
                    _nth(action_offsets, statements_with_wildcard_action),
                    account_wide=_names_wildcard(statement.get("Resource")),
                )
            statements_with_wildcard_action += 1

        if _is_wildcard_principal(statement.get("Principal")):
            # A condition narrows who the wildcard is, for its own statement only.
            if allows and "Condition" not in statement and principal_finding is None:
                principal_finding = _wildcard_principal_finding(
                    path,
                    resource,
                    attribute,
                    body,
                    _nth(principal_offsets, statements_with_wildcard_principal),
                )
            statements_with_wildcard_principal += 1

    return [finding for finding in (action_finding, principal_finding) if finding is not None]


def _check_policy_text(
    path: str, resource: Resource, attribute: Attribute, body: str
) -> list[Finding]:
    """Read a policy that cannot be evaluated, such as one built from variables, as text. The
    effect of a statement is not known here, and a condition anywhere silences the principal
    check."""
    findings: list[Finding] = []

    match = _WILDCARD_ACTION_RE.search(body)
    if match is not None:
        findings.append(
            _wildcard_action_finding(
                path,
                resource,
                attribute,
                body,
                match.start(),
                account_wide=_WILDCARD_RESOURCE_RE.search(body) is not None,
            )
        )

    if not _CONDITION_RE.search(body):
        principal_match = _WILDCARD_PRINCIPAL_RE.search(body)
        if principal_match is not None:
            findings.append(
                _wildcard_principal_finding(
                    path, resource, attribute, body, principal_match.start()
                )
            )

    return findings


def policy_statements(body: str) -> list[dict[str, Any]] | None:
    """Return the statements of a policy attribute (`policy = ...`) when its value can be
    evaluated: a JSON string, or `jsonencode()` of literals. None when it depends on anything the
    scanner cannot resolve, or is not a policy document."""
    file, diagnostics = hcl.parse_config(body.encode(), "policy.tf")
    if diagnostics.has_errors() or len(file.body.attributes) != 1:
        return None
    expression = next(iter(file.body.attributes.values())).expr

    document: Any
    if isinstance(expression, FunctionCallExpr):
        if expression.name != "jsonencode" or len(expression.args) != 1:
            return None
        value, value_diagnostics = expression.args[0].value(None)
        if value_diagnostics.has_errors() or not value.is_wholly_known():
            return None
        document = _as_python(value)
    else:
        value, value_diagnostics = expression.value(None)
        if (
            value_diagnostics.has_errors()
            or not value.is_wholly_known()
            or value.is_null()
            or value.type != hcl.STRING
        ):
            return None
        try:
            document = json.loads(value.as_string())
        except ValueError:
            return None

    if not isinstance(document, dict):
        return None
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(isinstance(s, dict) for s in statements):
        return None
    return statements


def _as_python(value: Value) -> Any:
    """Convert an evaluated HCL value to the JSON-shaped Python data jsonencode would produce."""
    if value.is_null():
        return None
    value_type = value.type
    if value_type == hcl.STRING:
        return value.as_string()
    if value_type == hcl.BOOL:
        return value.true()
    if value_type == hcl.NUMBER:
        return value.as_number_string()
    if value_type.is_object_type() or value_type.is_map_type():
        return {key: _as_python(element) for key, element in value.as_value_map().items()}
    return [_as_python(element) for element in value.as_value_slice()]


def _names_wildcard(value: Any) -> bool:
    """Whether an Action or Resource value is, or contains, "*"."""
    if isinstance(value, list):
        return "*" in value
    return bool(value == "*")


def _is_wildcard_principal(principal: Any) -> bool:
    """Principal = "*" or Principal = { AWS = "*" }, the two spellings of anyone."""
    if isinstance(principal, dict):
        return _names_wildcard(principal.get("AWS"))
    return _names_wildcard(principal)


def _nth(offsets: list[int], index: int) -> int:
    """The offset of the index-th wildcard in the text, or the first one if the text and the
    evaluated statements disagree, or -1 (the attribute's own line) if there is none."""
    if index < len(offsets):
        return offsets[index]
    return offsets[0] if offsets else -1


def _wildcard_action_finding(
    path: str,
    resource: Resource,
    attribute: Attribute,
    body: str,
    offset: int,
    *,
    account_wide: bool,
) -> Finding:
    if account_wide:
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
    return Finding(
        file=path,
        line=_line_of_offset(body, offset, attribute.range.start.line),
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


def _wildcard_principal_finding(
    path: str, resource: Resource, attribute: Attribute, body: str, offset: int
) -> Finding:
    return Finding(
        file=path,
        line=_line_of_offset(body, offset, attribute.range.start.line),
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


def _line_of_offset(body: str, offset: int, start_line: int) -> int:
    """Convert an attribute-relative text offset to a source line so nested wildcard findings point
    to their actual location.
    """
    if offset < 0 or offset > len(body):
        return start_line
    return start_line + body[:offset].count("\n")
