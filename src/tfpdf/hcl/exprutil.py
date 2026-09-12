"""Inspect expression structure without evaluating it.

Terragrunt inputs must be inspected entry by entry: an unresolved dependency
in one value must not hide literal secrets elsewhere in the same object.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ast import Expression, ObjectConsExpr, ObjectConsKeyExpr, ParenthesesExpr, ScopeTraversalExpr


@dataclass(slots=True, frozen=True)
class KeyValuePair:
    key: Expression
    value: Expression


def expr_map(expr: Expression) -> list[KeyValuePair] | None:
    """Return key/value expression pairs for an object constructor, or None for other expressions."""
    inner = _unwrap(expr)
    if not isinstance(inner, ObjectConsExpr):
        return None
    return [KeyValuePair(key=item.key, value=item.value_expr) for item in inner.items]


def expr_as_keyword(expr: Expression) -> str:
    """Return a bare identifier, or an empty string for quoted or computed keys. Callers can still
    inspect the value without a key name.
    """
    inner = _unwrap(expr)
    if isinstance(inner, ObjectConsKeyExpr):
        inner = _unwrap(inner.wrapped)
    if isinstance(inner, ScopeTraversalExpr) and len(inner.traversal) == 1:
        return inner.traversal.root_name
    return ""


def _unwrap(expr: Expression) -> Expression:
    while isinstance(expr, ParenthesesExpr):
        expr = expr.wrapped
    return expr
