"""Check Terraform variable files for hardcoded credentials."""

from __future__ import annotations

import json

from . import hcl
from .hcl import HCLParseError, Value
from .report.finding import Category, Finding, Severity
from .rules import is_credential_attr_name, is_open_cidr, match_credential_value_pattern
from .rules.entropy import byte_len, looks_like_secret

#: Wording note: the same scan runs pre-commit (--staged/--uncommitted) and on
#: a PR, and the right advice differs. Before the commit the fix is simply
#: "don't"; after it, the value is disclosed and deleting the line does not
#: undo that. Saying "already committed" would be wrong in the first case and
#: saying nothing about rotation would be negligent in the second, so the
#: rotation clause is stated as the condition it actually is.
_REMEDY = (
    " — variable values belong outside the repository (a TF_VAR_ environment variable, a "
    "gitignored tfvars file, or your secret manager). If this file is already committed, "
    "the value is disclosed: rotate it."
)


def is_tfvars_path(path: str) -> bool:
    """Recognize Terraform variable files, including .auto.tfvars and JSON forms."""
    return path.endswith((".tfvars", ".tfvars.json"))


def scan_file(path: str, source: bytes) -> list[Finding]:
    """Check .tfvars and .tfvars.json files for credentials and unrestricted CIDRs."""
    if path.endswith(".json"):
        return _scan_json(path, source)
    return _scan_hcl(path, source)


def _scan_hcl(path: str, source: bytes) -> list[Finding]:
    file, diags = hcl.parse_config(source, path)
    if diags.has_errors():
        raise HCLParseError(diags)

    # A .tfvars file is a flat list of `name = value` assignments; it declares
    # no blocks. Anything block-shaped is not a variable assignment and has no
    # value to judge.
    findings: list[Finding] = []
    for name, attribute in file.body.attributes.items():
        findings.extend(_scan_value(path, name, attribute, attribute.src_range.start.line))
    return findings


def _scan_value(path: str, name: str, attribute: hcl.Attribute, line: int) -> list[Finding]:
    """Evaluate a variable and check its value."""
    v, diags = attribute.expr.value(None)
    if diags.has_errors() or v.is_null() or not v.is_wholly_known():
        return []
    return _judge(path, name, v, line)


def _judge(path: str, name: str, v: Value, line: int) -> list[Finding]:
    """Inspect values recursively through objects and tuples to detect nested credentials."""
    t = v.type

    if t.is_object_type() or t.is_map_type():
        out: list[Finding] = []
        for k, elem in sorted(v.as_value_map().items()):
            # The nested key is what names the secret, but the finding is
            # reported against the top-level variable path so the reader can
            # find it: "database.password", not a bare "password".
            out.extend(_judge(path, f"{name}.{k}", elem, line))
        return out

    if t.is_tuple_type() or t.is_list_type() or t.is_set_type():
        out = []
        for elem in v.as_value_slice():
            out.extend(_judge(path, name, elem, line))
        return out

    if t is hcl.STRING:
        return _judge_string(path, name, v.as_string(), line)
    return []


def _judge_string(path: str, name: str, value: str, line: int) -> list[Finding]:
    if not value:
        return []

    # The attribute name is the last path segment: for `db = { password = "x" }`
    # the credential-ness lives in "password", not in "db.password".
    leaf = name.rsplit(".", 1)[-1]

    def finding(rule_name: str, severity: Severity, message: str) -> list[Finding]:
        return [
            Finding(
                file=path,
                line=line,
                category=Category.TUTORIAL_PATTERN,
                rule_name=rule_name,
                severity=severity,
                resource=name,
                message=message,
            )
        ]

    if is_credential_attr_name(leaf):
        return finding(
            "tfvars_credential_name",
            Severity.CRITICAL,
            f'"{name}" is a hardcoded credential in a .tfvars file' + _REMEDY,
        )

    label, ok = match_credential_value_pattern(value)
    if ok:
        return finding(
            "tfvars_credential_value",
            Severity.CRITICAL,
            f'"{name}" matches pattern: {label}' + _REMEDY,
        )

    if is_open_cidr(value):
        return finding(
            "tfvars_open_cidr",
            Severity.HIGH,
            f'"{name}" is {value}, open to the entire internet — narrow this range',
        )

    bits, ok = looks_like_secret(value)
    if ok:
        return finding(
            "tfvars_high_entropy",
            Severity.HIGH,
            f'"{name}" is a high-entropy string ({bits:.1f} bits/char over '
            f"{byte_len(value)} chars) — the statistical signature of a machine-generated "
            f"secret; if it is one{_REMEDY}",
        )
    return []


def _scan_json(path: str, source: bytes) -> list[Finding]:
    """Scan the JSON variable-file format, which the HCL parser does not read."""
    try:
        document = json.loads(source)
    except json.JSONDecodeError as exc:
        raise ValueError(f"json parse error in {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"json parse error in {path}: top level is not an object")

    findings: list[Finding] = []
    for name, v in document.items():
        findings.extend(_judge_json(path, name, v))
    return findings


def _judge_json(path: str, name: str, v: object) -> list[Finding]:
    """Apply the same recursive checks as _judge to decoded JSON."""
    if isinstance(v, str):
        return _judge_string(path, name, v, 1)
    if isinstance(v, dict):
        out: list[Finding] = []
        for k, elem in v.items():
            out.extend(_judge_json(path, f"{name}.{k}", elem))
        return out
    if isinstance(v, list):
        out = []
        for elem in v:
            out.extend(_judge_json(path, name, elem))
        return out
    return []
