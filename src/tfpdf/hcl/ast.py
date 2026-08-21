"""L'AST des expressions et des corps, avec l'évaluation attachée à chaque nœud.

L'évaluation vit sur les nœuds (`expr.value(ctx)`) plutôt que dans un visiteur
séparé, à l'image du `Expression.Value(ctx)` de hclsyntax, pour que les deux se
lisent côte à côte quand une découverte diffère entre le scanner Go et le
scanner Python.

**Les appels de fonction échouent toujours à s'évaluer.** Il n'y a aucune table
de fonctions, ni ici ni dans `EvalContext`, et c'est l'omission la plus lourde
de conséquences de ce paquet. `policy = jsonencode({ Statement = [{ Action =
"*" }] })` est la forme qu'emploie la documentation du fournisseur AWS et celle
que reproduit le Terraform généré ; elle ne se résout à rien, ce qui est
pourquoi `rules.iam_wildcard` travaille sur la plage de source brute de
l'attribut plutôt que sur sa valeur. Implémenter `jsonencode` ici
n'améliorerait pas cette règle : cela changerait discrètement quelle écriture
elle attrape, en laissant la forme heredoc à un autre chemin de code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import InvalidOperation

from . import values as cty
from .diagnostics import Diagnostics, error
from .pos import Range
from .traversal import (
    EvalContext,
    Traversal,
    TraverseAttr,
    TraverseIndex,
    TraverseRoot,
)
from .values import Value

#: Scope name RelativeTraversalExpr parks an intermediate value under while it
#: walks. Not a valid HCL identifier, so it can never collide with a real one.
_REL_ROOT = "__rel"


class Expression(ABC):
    """Classe de base de tout nœud d'expression."""

    range: Range

    @abstractmethod
    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        """Évalue. Rend (valeur, diagnostics) ; vérifier `diags.has_errors()`
        avant de faire confiance à la valeur, exactement comme le font les
        appelants Go."""

    def variables(self) -> list[Traversal]:
        """Chaque traversée absolue que cette expression lit, dans l'ordre de la
        source."""
        return []


# --- leaves ---------------------------------------------------------------


@dataclass(slots=True)
class LiteralValueExpr(Expression):
    value_: Value
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return self.value_, Diagnostics()


@dataclass(slots=True)
class ScopeTraversalExpr(Expression):
    """Une référence enracinée dans la portée : `var.x`, `local.y`,
    `aws_db_instance.a.id`."""

    traversal: Traversal
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return self.traversal.traverse(context)

    def variables(self) -> list[Traversal]:
        return [self.traversal]


@dataclass(slots=True)
class RelativeTraversalExpr(Expression):
    """Des étapes appliquées au résultat d'une autre expression :
    `foo()[0].bar`."""

    source: Expression
    traversal: Traversal
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        current, diags = self.source.value(context)
        if diags.has_errors():
            return cty.DYNAMIC_VAL, diags

        # Walk one step at a time by rooting a synthetic traversal at the value
        # reached so far, so the step semantics live in exactly one place
        # (Traversal.traverse) rather than being reimplemented here.
        for step in self.traversal:
            if isinstance(step, (TraverseAttr, TraverseIndex)):
                sub = Traversal([TraverseRoot(_REL_ROOT, step.range), step])
            else:  # pragma: no cover - a root cannot appear mid-traversal
                return cty.DYNAMIC_VAL, error("Invalid traversal", subject=self.range)
            current, sub_diags = sub.traverse(EvalContext({_REL_ROOT: current}))
            if sub_diags.has_errors():
                return cty.DYNAMIC_VAL, sub_diags
        return current, Diagnostics()

    def variables(self) -> list[Traversal]:
        return self.source.variables()


# --- templates ------------------------------------------------------------


@dataclass(slots=True)
class TemplateExpr(Expression):
    """Une chaîne entre guillemets ou un heredoc : une suite de parties
    littérales et interpolées."""

    parts: list[Expression]
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        if not self.parts:
            return cty.EMPTY_STRING, Diagnostics()

        diags = Diagnostics()
        buffer: list[str] = []
        for part in self.parts:
            v, part_diags = part.value(context)
            diags.extend(part_diags)
            if part_diags.has_errors():
                return cty.DYNAMIC_VAL, diags
            if v.is_unknown():
                return cty.unknown_val(cty.STRING), diags
            if v.is_null():
                # HCL renders a null interpolation as an error rather than as
                # "null"; treating it as unresolvable keeps rules from judging
                # text nobody wrote.
                return cty.DYNAMIC_VAL, diags.extended(
                    error(
                        "Invalid template interpolation value",
                        "The expression is null.",
                        part.range,
                    )
                )
            text, ok = cty.to_string(v)
            if not ok:
                return cty.DYNAMIC_VAL, diags.extended(
                    error(
                        "Invalid template interpolation value",
                        f"Cannot include a {v.type} value in a string template.",
                        part.range,
                    )
                )
            buffer.append(text)
        return cty.string_val("".join(buffer)), diags

    def is_string_literal(self) -> bool:
        return all(isinstance(p, LiteralValueExpr) for p in self.parts)

    def variables(self) -> list[Traversal]:
        out: list[Traversal] = []
        for p in self.parts:
            out.extend(p.variables())
        return out


@dataclass(slots=True)
class TemplateWrapExpr(Expression):
    """Un template qui est exactement une interpolation : `"${var.x}"`.

    HCL laisse passer la valeur enveloppée avec son propre type plutôt que de
    la convertir en chaîne, si bien que `count = "${var.n}"` reste un nombre.
    Fondre ceci dans TemplateExpr transformerait chacune de ces valeurs en
    chaîne et changerait ce que voit une règle sensible au type.
    """

    wrapped: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return self.wrapped.value(context)

    def variables(self) -> list[Traversal]:
        return self.wrapped.variables()


# --- collections ----------------------------------------------------------


@dataclass(slots=True)
class TupleConsExpr(Expression):
    exprs: list[Expression]
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        diags = Diagnostics()
        out: list[Value] = []
        for e in self.exprs:
            v, d = e.value(context)
            diags.extend(d)
            if d.has_errors():
                return cty.DYNAMIC_VAL, diags
            out.append(v)
        return cty.tuple_val(out), diags

    def variables(self) -> list[Traversal]:
        out: list[Traversal] = []
        for e in self.exprs:
            out.extend(e.variables())
        return out


@dataclass(slots=True)
class ObjectConsItem:
    key: Expression
    value_expr: Expression


@dataclass(slots=True)
class ObjectConsExpr(Expression):
    items: list[ObjectConsItem]
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        diags = Diagnostics()
        out: dict[str, Value] = {}
        for item in self.items:
            kv, kd = item.key.value(context)
            diags.extend(kd)
            if kd.has_errors():
                return cty.DYNAMIC_VAL, diags
            key_text, ok = cty.to_string(kv)
            if not ok:
                return cty.DYNAMIC_VAL, diags.extended(
                    error("Invalid object key", "Object keys must be strings.", item.key.range)
                )
            vv, vd = item.value_expr.value(context)
            diags.extend(vd)
            if vd.has_errors():
                return cty.DYNAMIC_VAL, diags
            out[key_text] = vv
        return cty.object_val(out), diags

    def variables(self) -> list[Traversal]:
        out: list[Traversal] = []
        for item in self.items:
            out.extend(item.key.variables())
            out.extend(item.value_expr.variables())
        return out


@dataclass(slots=True)
class ObjectConsKeyExpr(Expression):
    """Une clé d'objet. Un identifiant nu est le *nom*, pas une référence.

    `{ name = "x" }` a pour clé « name » ; il ne lit pas une variable appelée
    `name`. HCL appelle cela la règle de l'« identifiant nu », et s'y tromper
    ferait de chaque clé d'objet une traversée irrésoluble et de chaque objet
    une valeur inévaluable — ce qui désactiverait silencieusement, à son tour,
    les règles fondées sur les valeurs pour tout bloc `tags = {...}` d'un dépôt.
    """

    wrapped: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        bare = self._bare_name()
        if bare is not None:
            return cty.string_val(bare), Diagnostics()
        return self.wrapped.value(context)

    def _bare_name(self) -> str | None:
        if isinstance(self.wrapped, ScopeTraversalExpr) and len(self.wrapped.traversal) == 1:
            return self.wrapped.traversal.root_name
        return None

    def variables(self) -> list[Traversal]:
        if self._bare_name() is not None:
            return []
        return self.wrapped.variables()


# --- operators ------------------------------------------------------------


@dataclass(slots=True)
class ParenthesesExpr(Expression):
    wrapped: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return self.wrapped.value(context)

    def variables(self) -> list[Traversal]:
        return self.wrapped.variables()


@dataclass(slots=True)
class UnaryOpExpr(Expression):
    op: str
    operand: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        v, diags = self.operand.value(context)
        if diags.has_errors() or v.is_unknown() or v.is_null():
            return cty.DYNAMIC_VAL, diags
        if self.op == "-":
            if v.type is not cty.NUMBER:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            return cty.number_val(-v.as_decimal()), diags
        if self.op == "!":
            if v.type is not cty.BOOL:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            return cty.bool_val(not v.true()), diags
        return cty.DYNAMIC_VAL, error(f"Unsupported operator {self.op}", subject=self.range)

    def variables(self) -> list[Traversal]:
        # Without this, `skip_final_snapshot = !var.deletion_protection`
        # resolves to a value but reports no reference, and the finding loses
        # the "(via var.deletion_protection)" clause that tells the reader
        # where the value actually lives.
        return self.operand.variables()


_ARITH = {"+", "-", "*", "/", "%"}
_COMPARE = {"<", "<=", ">", ">="}


@dataclass(slots=True)
class BinaryOpExpr(Expression):
    op: str
    lhs: Expression
    rhs: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        lv, ld = self.lhs.value(context)
        if ld.has_errors():
            return cty.DYNAMIC_VAL, ld
        rv, rd = self.rhs.value(context)
        if rd.has_errors():
            return cty.DYNAMIC_VAL, rd
        diags = ld.extended(rd)

        if lv.is_unknown() or rv.is_unknown():
            return cty.DYNAMIC_VAL, diags

        if self.op == "==":
            return cty.bool_val(_equal(lv, rv)), diags
        if self.op == "!=":
            return cty.bool_val(not _equal(lv, rv)), diags

        if self.op in ("&&", "||"):
            if lv.type is not cty.BOOL or rv.type is not cty.BOOL:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            result = lv.true() and rv.true() if self.op == "&&" else lv.true() or rv.true()
            return cty.bool_val(result), diags

        if self.op == "+" and lv.type is cty.STRING and rv.type is cty.STRING:
            # HCL itself rejects this, but generated Terraform writes it and
            # the value is unambiguous. Concatenating is strictly more
            # informative than refusing, and only ever produces a literal a
            # rule can then judge.
            return cty.string_val(lv.as_string() + rv.as_string()), diags

        if self.op in _ARITH or self.op in _COMPARE:
            if lv.type is not cty.NUMBER or rv.type is not cty.NUMBER:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            a, b = lv.as_decimal(), rv.as_decimal()
            if self.op in _COMPARE:
                cmp = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[self.op]
                return cty.bool_val(cmp), diags
            if self.op in ("/", "%") and b == 0:
                return cty.DYNAMIC_VAL, error("Division by zero", subject=self.range)
            try:
                result_num = {
                    "+": lambda: a + b,
                    "-": lambda: a - b,
                    "*": lambda: a * b,
                    "/": lambda: a / b,
                    "%": lambda: a % b,
                }[self.op]()
            except (InvalidOperation, ArithmeticError):
                return cty.DYNAMIC_VAL, error("Arithmetic error", subject=self.range)
            return cty.number_val(result_num), diags

        return cty.DYNAMIC_VAL, error(f"Unsupported operator {self.op}", subject=self.range)

    def variables(self) -> list[Traversal]:
        return self.lhs.variables() + self.rhs.variables()


def _equal(a: Value, b: Value) -> bool:
    if a.is_null() or b.is_null():
        return a.is_null() and b.is_null()
    if a.type is cty.NUMBER and b.type is cty.NUMBER:
        return a.as_decimal() == b.as_decimal()
    if a.type is not b.type:
        return False
    return bool(a.raw == b.raw)


@dataclass(slots=True)
class ConditionalExpr(Expression):
    condition: Expression
    true_result: Expression
    false_result: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        cv, diags = self.condition.value(context)
        if diags.has_errors():
            return cty.DYNAMIC_VAL, diags
        if cv.is_unknown() or cv.is_null() or cv.type is not cty.BOOL:
            # An unresolvable condition means neither branch can be claimed as
            # the value. Reporting one would be a guess, and a guess is how a
            # false positive gets in.
            return cty.DYNAMIC_VAL, diags
        branch = self.true_result if cv.true() else self.false_result
        return branch.value(context)

    def variables(self) -> list[Traversal]:
        return (
            self.condition.variables()
            + self.true_result.variables()
            + self.false_result.variables()
        )


@dataclass(slots=True)
class IndexExpr(Expression):
    collection: Expression
    key: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        cv, cd = self.collection.value(context)
        if cd.has_errors():
            return cty.DYNAMIC_VAL, cd
        kv, kd = self.key.value(context)
        if kd.has_errors():
            return cty.DYNAMIC_VAL, kd
        if cv.is_unknown() or kv.is_unknown() or cv.is_null():
            return cty.DYNAMIC_VAL, cd.extended(kd)
        if isinstance(cv.raw, tuple) and kv.type is cty.NUMBER:
            i = int(kv.as_decimal())
            if 0 <= i < len(cv.raw):
                return cv.raw[i], cd.extended(kd)
            return cty.DYNAMIC_VAL, error("Index out of range", subject=self.range)
        if isinstance(cv.raw, dict) and kv.type is cty.STRING:
            key_text = kv.as_string()
            if key_text in cv.raw:
                return cv.raw[key_text], cd.extended(kd)
            return cty.DYNAMIC_VAL, error("Missing key", subject=self.range)
        return cty.DYNAMIC_VAL, error("Invalid index", subject=self.range)

    def variables(self) -> list[Traversal]:
        return self.collection.variables() + self.key.variables()


@dataclass(slots=True)
class SplatExpr(Expression):
    """`aws_instance.web[*].id` — jamais résoluble statiquement ici, la source
    étant une référence de ressource qu'aucune portée ne détient."""

    source: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return cty.DYNAMIC_VAL, error(
            "Splat expressions are not statically evaluable", subject=self.range
        )

    def variables(self) -> list[Traversal]:
        return self.source.variables()


@dataclass(slots=True)
class FunctionCallExpr(Expression):
    """Un appel. Ne s'évalue jamais — voir la docstring du module.

    `args` est conservé pour que `variables()` rapporte quand même ce que
    l'appel lit, ce qui permet à une découverte de nommer `var.db_password`
    même quand la valeur est passée par une fonction que le scanner refuse
    d'exécuter.
    """

    name: str
    args: list[Expression]
    expand_final: bool = False
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return cty.DYNAMIC_VAL, error(
            "Function calls not allowed",
            f"Cannot statically evaluate a call to {self.name!r}.",
            self.range,
        )

    def variables(self) -> list[Traversal]:
        out: list[Traversal] = []
        for a in self.args:
            out.extend(a.variables())
        return out


@dataclass(slots=True)
class ForExpr(Expression):
    """Une compréhension `for`. Analysée pour que le fichier s'analyse encore,
    jamais évaluée : en résoudre une demande la collection qu'elle parcourt, qui
    est une ressource ou une variable de plan dans tous les cas que le scanner
    rencontre.
    """

    collection: Expression
    key_var: str
    value_var: str
    key_expr: Expression | None
    value_expr: Expression
    condition: Expression | None = None
    is_object: bool = False
    group: bool = False
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return cty.DYNAMIC_VAL, error(
            "For expressions are not statically evaluable", subject=self.range
        )

    def variables(self) -> list[Traversal]:
        return self.collection.variables()


# --- body ----------------------------------------------------------------


@dataclass(slots=True)
class Attribute:
    name: str
    expr: Expression
    src_range: Range
    name_range: Range
    equals_range: Range


@dataclass(slots=True)
class Block:
    type: str
    labels: list[str]
    body: Body
    type_range: Range
    label_ranges: list[Range]
    open_brace_range: Range
    close_brace_range: Range

    def def_range(self) -> Range:
        """L'en-tête du bloc — `resource "aws_db_instance" "prod"` — c'est-à-dire
        l'endroit où pointe une découverte portant sur le bloc entier."""
        out = self.type_range
        for r in self.label_ranges:
            out = out.merge(r)
        return out


@dataclass(slots=True)
class Body:
    attributes: dict[str, Attribute] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)
    src_range: Range = field(default_factory=Range)

    def blocks_of_type(self, block_type: str) -> list[Block]:
        return [b for b in self.blocks if b.type == block_type]


@dataclass(slots=True)
class File:
    body: Body
    source: bytes
    filename: str
