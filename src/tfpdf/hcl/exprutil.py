"""Questions structurelles sur une expression, sans l'évaluer.

Porte les deux aides `hcl.Expr*` que le scanner utilise : `ExprMap` et
`ExprAsKeyword`. Toutes deux existent parce que le `inputs = { … }` de Terragrunt
doit être parcouru clé par clé plutôt qu'évalué d'un bloc — la plupart de ses
valeurs référencent des dépendances et ne se résolvent à rien, et un map qui
échouerait entièrement à s'évaluer emporterait avec lui chaque secret littéral
qu'il contient.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ast import Expression, ObjectConsExpr, ObjectConsKeyExpr, ParenthesesExpr, ScopeTraversalExpr


@dataclass(slots=True, frozen=True)
class KeyValuePair:
    key: Expression
    value: Expression


def expr_map(expr: Expression) -> list[KeyValuePair] | None:
    """Les paires clé/valeur d'une expression de construction d'objet, ou None
    si l'expression n'en est pas une.

    None est la réponse « ce n'est pas un littéral de map », correspondant à ce
    que l'appelant Go fait d'un diagnostic : arrêter de descendre, il n'y a rien
    de plus à inspecter.
    """
    inner = _unwrap(expr)
    if not isinstance(inner, ObjectConsExpr):
        return None
    return [KeyValuePair(key=item.key, value=item.value_expr) for item in inner.items]


def expr_as_keyword(expr: Expression) -> str:
    """L'identifiant nu dont une expression est faite, ou « ».

    `inputs = { db_password = "x" }` donne la clé sous forme de traversée à une
    seule étape — un mot-clé — tandis que `"db-password" = "x"` donne un
    littéral de chaîne. Tout le reste, c'est-à-dire une clé calculée, rend « »,
    et l'appelant inspecte quand même la valeur, simplement sans clé pointée
    dans ses messages.
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
