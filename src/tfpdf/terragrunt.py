"""Scan des fichiers terragrunt.hcl.

Port de internal/terragrunt/terragrunt.go.

Le format de configuration propre à Terragrunt, qui n'est pas un fichier de
ressources .tf, vérifié pour les mêmes motifs d'identifiants en dur et de CIDR
grand ouverts que les règles de motif de tutoriel attrapent dans les blocs de
ressources Terraform. Le map `inputs` de Terragrunt — et `remote_state.config` —
porte couramment exactement le genre de secret que cet outil existe pour
attraper, mais chaque fichier terragrunt.hcl était auparavant entièrement
invisible au scanner : il ne considérait que les fichiers terminant en .tf.
"""

from __future__ import annotations

from . import hcl
from .hcl import HCLParseError
from .hcl.ast import Expression
from .hcl.exprutil import expr_as_keyword, expr_map
from .report.finding import Category, Finding, Severity
from .rules import is_credential_attr_name, is_open_cidr, match_credential_value_pattern


def scan_file(path: str, source: bytes) -> list[Finding]:
    """Scanne le map `inputs` et le map `remote_state.config` d'un fichier
    terragrunt.hcl, à la recherche d'identifiants en dur et de CIDR grand
    ouverts.

    Lève `HCLParseError` plutôt que de sauter le fichier en silence — même
    convention que `parser.parse_file`.
    """
    file, diags = hcl.parse_config(source, path)
    if diags.has_errors():
        raise HCLParseError(diags)

    findings: list[Finding] = []

    inputs = file.body.attributes.get("inputs")
    if inputs is not None:
        findings.extend(_scan_map_expr(path, "inputs", inputs.expr))

    for block in file.body.blocks:
        if block.type != "remote_state":
            continue
        config = block.body.attributes.get("config")
        if config is not None:
            findings.extend(_scan_map_expr(path, "remote_state.config", config.expr))

    return findings


def _scan_map_expr(path: str, key_path: str, expr: Expression) -> list[Finding]:
    """Parcourt une expression de construction d'objet clé par clé, en
    descendant dans les maps imbriqués, et signale toute feuille de type chaîne
    qui ressemble à un identifiant en dur ou à un bloc CIDR grand ouvert.

    Les expressions qui référencent une variable, un local ou la sortie d'une
    dépendance ne peuvent pas être évaluées statiquement et sont sautées — la
    même philosophie « pas de plan, pas d'état, uniquement des valeurs résolubles
    statiquement » que `tfpdf.parser`.
    """
    pairs = expr_map(expr)
    if pairs is None:
        return []  # not a map/object literal — nothing further to inspect here

    findings: list[Finding] = []
    for pair in pairs:
        key_name = expr_as_keyword(pair.key)
        if not key_name:
            key_name = _string_key(pair.key)
        full_key = f"{key_path}.{key_name}" if key_name else key_path

        if expr_map(pair.value) is not None:
            findings.extend(_scan_map_expr(path, full_key, pair.value))
            continue

        v, vdiags = pair.value.value(None)
        if vdiags.has_errors() or v.is_null() or v.type is not hcl.STRING:
            continue
        str_val = v.as_string()
        line = pair.value.range.start.line

        if key_name and str_val and is_credential_attr_name(key_name):
            findings.append(
                Finding(
                    file=path,
                    line=line,
                    category=Category.TUTORIAL_PATTERN,
                    severity=Severity.CRITICAL,
                    resource=key_path,
                    message=(
                        f"{full_key} is a hardcoded string literal, not a variable or "
                        "secret reference — credentials must not be committed in plain text"
                    ),
                )
            )
            continue

        label, ok = match_credential_value_pattern(str_val)
        if ok:
            findings.append(
                Finding(
                    file=path,
                    line=line,
                    category=Category.TUTORIAL_PATTERN,
                    severity=Severity.CRITICAL,
                    resource=key_path,
                    message=(
                        f"{full_key} value matches pattern: {label} — remove from source "
                        "and use a secret reference"
                    ),
                )
            )
            continue

        if is_open_cidr(str_val):
            findings.append(
                Finding(
                    file=path,
                    line=line,
                    category=Category.TUTORIAL_PATTERN,
                    severity=Severity.HIGH,
                    resource=key_path,
                    message=f'{full_key} = "0.0.0.0/0" allows traffic from anywhere',
                )
            )

    return findings


def _string_key(key_expr: Expression) -> str:
    """Le texte littéral d'une clé de map entre guillemets, ou « » pour une clé
    calculée."""
    v, diags = key_expr.value(None)
    if diags.has_errors() or v.is_null() or v.type is not hcl.STRING:
        return ""
    return v.as_string()
