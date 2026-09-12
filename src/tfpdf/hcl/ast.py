"""HCL expression and body nodes with static evaluation.

Function calls deliberately remain unevaluated. Rules such as iam_wildcard
inspect raw attribute source to cover jsonencode calls and heredocs. Adding
function evaluation would change rule behavior and requires regression tests.
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
    """Base class for expression nodes."""

    range: Range

    @abstractmethod
    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        """Return (value, diagnostics). Check diagnostics.has_errors() before using the value."""

    def variables(self) -> list[Traversal]:
        """Return absolute references read by this expression, in source order."""
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
    """A reference rooted in scope, such as var.x, local.y, or aws_db_instance.a.id."""

    traversal: Traversal
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        return self.traversal.traverse(context)

    def variables(self) -> list[Traversal]:
        return [self.traversal]


@dataclass(slots=True)
class RelativeTraversalExpr(Expression):
    """Attribute or index steps applied to another expression, such as foo()[0].bar."""

    source: Expression
    traversal: Traversal
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        current, diagnostics = self.source.value(context)
        if diagnostics.has_errors():
            return cty.DYNAMIC_VAL, diagnostics

        # Walk one step at a time by rooting a synthetic traversal at the value
        # reached so far, so the step semantics live in exactly one place
        # (Traversal.traverse) rather than being reimplemented here.
        for step in self.traversal:
            if isinstance(step, (TraverseAttr, TraverseIndex)):
                step_traversal = Traversal([TraverseRoot(_REL_ROOT, step.range), step])
            else:  # pragma: no cover - a root cannot appear mid-traversal
                return cty.DYNAMIC_VAL, error("Invalid traversal", subject=self.range)
            current, step_diagnostics = step_traversal.traverse(EvalContext({_REL_ROOT: current}))
            if step_diagnostics.has_errors():
                return cty.DYNAMIC_VAL, step_diagnostics
        return current, Diagnostics()

    def variables(self) -> list[Traversal]:
        return self.source.variables()


# --- templates ------------------------------------------------------------


@dataclass(slots=True)
class TemplateExpr(Expression):
    """A quoted string or heredoc containing literal and interpolated parts."""

    parts: list[Expression]
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        if not self.parts:
            return cty.EMPTY_STRING, Diagnostics()

        diagnostics = Diagnostics()
        buffer: list[str] = []
        for part in self.parts:
            part_value, part_diagnostics = part.value(context)
            diagnostics.extend(part_diagnostics)
            if part_diagnostics.has_errors():
                return cty.DYNAMIC_VAL, diagnostics
            if part_value.is_unknown():
                return cty.unknown_val(cty.STRING), diagnostics
            if part_value.is_null():
                # HCL renders a null interpolation as an error rather than as
                # "null"; treating it as unresolvable keeps rules from judging
                # text nobody wrote.
                return cty.DYNAMIC_VAL, diagnostics.extended(
                    error(
                        "Invalid template interpolation value",
                        "The expression is null.",
                        part.range,
                    )
                )
            text, is_convertible = cty.to_string(part_value)
            if not is_convertible:
                return cty.DYNAMIC_VAL, diagnostics.extended(
                    error(
                        "Invalid template interpolation value",
                        f"Cannot include a {part_value.type} value in a string template.",
                        part.range,
                    )
                )
            buffer.append(text)
        return cty.string_val("".join(buffer)), diagnostics

    def is_string_literal(self) -> bool:
        return all(isinstance(part, LiteralValueExpr) for part in self.parts)

    def variables(self) -> list[Traversal]:
        traversals: list[Traversal] = []
        for part in self.parts:
            traversals.extend(part.variables())
        return traversals


@dataclass(slots=True)
class TemplateWrapExpr(Expression):
    """A template containing only one interpolation, such as "${var.x}". Preserve its value's type
    instead of coercing it to a string.
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
        diagnostics = Diagnostics()
        elements: list[Value] = []
        for expression in self.exprs:
            element_value, element_diagnostics = expression.value(context)
            diagnostics.extend(element_diagnostics)
            if element_diagnostics.has_errors():
                return cty.DYNAMIC_VAL, diagnostics
            elements.append(element_value)
        return cty.tuple_val(elements), diagnostics

    def variables(self) -> list[Traversal]:
        traversals: list[Traversal] = []
        for expression in self.exprs:
            traversals.extend(expression.variables())
        return traversals


@dataclass(slots=True)
class ObjectConsItem:
    key: Expression
    value_expr: Expression


@dataclass(slots=True)
class ObjectConsExpr(Expression):
    items: list[ObjectConsItem]
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        diagnostics = Diagnostics()
        entries: dict[str, Value] = {}
        for item in self.items:
            key_value, key_diagnostics = item.key.value(context)
            diagnostics.extend(key_diagnostics)
            if key_diagnostics.has_errors():
                return cty.DYNAMIC_VAL, diagnostics
            key_text, is_string_key = cty.to_string(key_value)
            if not is_string_key:
                return cty.DYNAMIC_VAL, diagnostics.extended(
                    error("Invalid object key", "Object keys must be strings.", item.key.range)
                )
            element_value, value_diagnostics = item.value_expr.value(context)
            diagnostics.extend(value_diagnostics)
            if value_diagnostics.has_errors():
                return cty.DYNAMIC_VAL, diagnostics
            entries[key_text] = element_value
        return cty.object_val(entries), diagnostics

    def variables(self) -> list[Traversal]:
        traversals: list[Traversal] = []
        for item in self.items:
            traversals.extend(item.key.variables())
            traversals.extend(item.value_expr.variables())
        return traversals


@dataclass(slots=True)
class ObjectConsKeyExpr(Expression):
    """An object key. A bare identifier in { name = "x" } names the key; it does not reference a
    variable.
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
        operand_value, diagnostics = self.operand.value(context)
        if diagnostics.has_errors() or operand_value.is_unknown() or operand_value.is_null():
            return cty.DYNAMIC_VAL, diagnostics
        if self.op == "-":
            if operand_value.type is not cty.NUMBER:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            return cty.number_val(-operand_value.as_decimal()), diagnostics
        if self.op == "!":
            if operand_value.type is not cty.BOOL:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            return cty.bool_val(not operand_value.true()), diagnostics
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
        left_value, left_diagnostics = self.lhs.value(context)
        if left_diagnostics.has_errors():
            return cty.DYNAMIC_VAL, left_diagnostics
        right_value, right_diagnostics = self.rhs.value(context)
        if right_diagnostics.has_errors():
            return cty.DYNAMIC_VAL, right_diagnostics
        diagnostics = left_diagnostics.extended(right_diagnostics)

        if left_value.is_unknown() or right_value.is_unknown():
            return cty.DYNAMIC_VAL, diagnostics

        if self.op == "==":
            return cty.bool_val(_equal(left_value, right_value)), diagnostics
        if self.op == "!=":
            return cty.bool_val(not _equal(left_value, right_value)), diagnostics

        if self.op in ("&&", "||"):
            if left_value.type is not cty.BOOL or right_value.type is not cty.BOOL:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            result = (
                left_value.true() and right_value.true()
                if self.op == "&&"
                else left_value.true() or right_value.true()
            )
            return cty.bool_val(result), diagnostics

        if self.op == "+" and left_value.type is cty.STRING and right_value.type is cty.STRING:
            # HCL itself rejects this, but generated Terraform writes it and
            # the value is unambiguous. Concatenating is strictly more
            # informative than refusing, and only ever produces a literal a
            # rule can then judge.
            return cty.string_val(left_value.as_string() + right_value.as_string()), diagnostics

        if self.op in _ARITH or self.op in _COMPARE:
            if left_value.type is not cty.NUMBER or right_value.type is not cty.NUMBER:
                return cty.DYNAMIC_VAL, error("Invalid operand", subject=self.range)
            left_number, right_number = left_value.as_decimal(), right_value.as_decimal()
            if self.op in _COMPARE:
                comparison_result = {
                    "<": left_number < right_number,
                    "<=": left_number <= right_number,
                    ">": left_number > right_number,
                    ">=": left_number >= right_number,
                }[self.op]
                return cty.bool_val(comparison_result), diagnostics
            if self.op in ("/", "%") and right_number == 0:
                return cty.DYNAMIC_VAL, error("Division by zero", subject=self.range)
            try:
                numeric_result = {
                    "+": lambda: left_number + right_number,
                    "-": lambda: left_number - right_number,
                    "*": lambda: left_number * right_number,
                    "/": lambda: left_number / right_number,
                    "%": lambda: left_number % right_number,
                }[self.op]()
            except (InvalidOperation, ArithmeticError):
                return cty.DYNAMIC_VAL, error("Arithmetic error", subject=self.range)
            return cty.number_val(numeric_result), diagnostics

        return cty.DYNAMIC_VAL, error(f"Unsupported operator {self.op}", subject=self.range)

    def variables(self) -> list[Traversal]:
        return self.lhs.variables() + self.rhs.variables()


def _equal(left_value: Value, right_value: Value) -> bool:
    if left_value.is_null() or right_value.is_null():
        return left_value.is_null() and right_value.is_null()
    if left_value.type is cty.NUMBER and right_value.type is cty.NUMBER:
        return left_value.as_decimal() == right_value.as_decimal()
    if left_value.type is not right_value.type:
        return False
    return bool(left_value.raw == right_value.raw)


@dataclass(slots=True)
class ConditionalExpr(Expression):
    condition: Expression
    true_result: Expression
    false_result: Expression
    range: Range = field(default_factory=Range)

    def value(self, context: EvalContext | None = None) -> tuple[Value, Diagnostics]:
        condition_value, diagnostics = self.condition.value(context)
        if diagnostics.has_errors():
            return cty.DYNAMIC_VAL, diagnostics
        if (
            condition_value.is_unknown()
            or condition_value.is_null()
            or condition_value.type is not cty.BOOL
        ):
            # An unresolvable condition means neither branch can be claimed as
            # the value. Reporting one would be a guess, and a guess is how a
            # false positive gets in.
            return cty.DYNAMIC_VAL, diagnostics
        branch = self.true_result if condition_value.true() else self.false_result
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
        collection_value, collection_diagnostics = self.collection.value(context)
        if collection_diagnostics.has_errors():
            return cty.DYNAMIC_VAL, collection_diagnostics
        key_value, key_diagnostics = self.key.value(context)
        if key_diagnostics.has_errors():
            return cty.DYNAMIC_VAL, key_diagnostics
        if collection_value.is_unknown() or key_value.is_unknown() or collection_value.is_null():
            return cty.DYNAMIC_VAL, collection_diagnostics.extended(key_diagnostics)
        if isinstance(collection_value.raw, tuple) and key_value.type is cty.NUMBER:
            element_index = int(key_value.as_decimal())
            if 0 <= element_index < len(collection_value.raw):
                return collection_value.raw[element_index], collection_diagnostics.extended(
                    key_diagnostics
                )
            return cty.DYNAMIC_VAL, error("Index out of range", subject=self.range)
        if isinstance(collection_value.raw, dict) and key_value.type is cty.STRING:
            key_text = key_value.as_string()
            if key_text in collection_value.raw:
                return collection_value.raw[key_text], collection_diagnostics.extended(
                    key_diagnostics
                )
            return cty.DYNAMIC_VAL, error("Missing key", subject=self.range)
        return cty.DYNAMIC_VAL, error("Invalid index", subject=self.range)

    def variables(self) -> list[Traversal]:
        return self.collection.variables() + self.key.variables()


@dataclass(slots=True)
class SplatExpr(Expression):
    """A splat such as aws_instance.web[*].id, which this static evaluator cannot resolve."""

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
    """An unevaluated function call. Keep its arguments so variables() can still report input
    references.
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
        traversals: list[Traversal] = []
        for argument in self.args:
            traversals.extend(argument.variables())
        return traversals


@dataclass(slots=True)
class ForExpr(Expression):
    """A for comprehension, parsed to preserve file structure but not evaluated statically."""

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
        """Return the block header range used by findings that apply to the whole block."""
        header_range = self.type_range
        for label_range in self.label_ranges:
            header_range = header_range.merge(label_range)
        return header_range


@dataclass(slots=True)
class Body:
    attributes: dict[str, Attribute] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)
    src_range: Range = field(default_factory=Range)

    def blocks_of_type(self, block_type: str) -> list[Block]:
        return [block for block in self.blocks if block.type == block_type]


@dataclass(slots=True)
class File:
    body: Body
    source: bytes
    filename: str
