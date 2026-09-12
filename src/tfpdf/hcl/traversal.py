"""References such as var.db_password and local.admin_pw.

Traversals resolve variable defaults and locals through an evaluation context.
They also supply resolved_from in findings so readers can locate the literal
behind an indirect reference.
"""

from __future__ import annotations

from dataclasses import dataclass

from .diagnostics import Diagnostics, error
from .pos import Range
from .values import DYNAMIC_VAL, NUMBER, STRING, Value

#: Shared zero Range. Frozen and immutable, so one instance is safe as a
#: dataclass default and avoids a fresh allocation per traversal step.
NO_RANGE = Range()


@dataclass(frozen=True, slots=True)
class TraverseRoot:
    name: str
    range: Range = NO_RANGE


@dataclass(frozen=True, slots=True)
class TraverseAttr:
    name: str
    range: Range = NO_RANGE


@dataclass(frozen=True, slots=True)
class TraverseIndex:
    key: Value
    range: Range = NO_RANGE


Step = TraverseRoot | TraverseAttr | TraverseIndex


class Traversal(list[Step]):
    """A reference as traversal steps, starting with TraverseRoot for absolute references."""

    @property
    def root_name(self) -> str:
        if self and isinstance(self[0], TraverseRoot):
            return self[0].name
        return ""

    @property
    def range(self) -> Range:
        if not self:
            return Range()
        out = self[0].range
        for step in self[1:]:
            out = out.merge(step.range)
        return out

    def render(self, max_steps: int = 2) -> str:
        """Render up to max_steps reference steps to identify the variable or local behind a
        finding.
        """
        parts: list[str] = []
        for step_index, step in enumerate(self):
            if isinstance(step, TraverseRoot):
                parts.append(step.name)
            elif isinstance(step, TraverseAttr):
                parts.append("." + step.name)
            else:
                # An index or a splat: the root is still the useful part, and
                # rendering `[0]` into a message adds nothing a reader can act
                # on. Matches firstTraversalName's `default:` branch.
                pass
            if step_index > max_steps - 1:
                break
        return "".join(parts)

    def traverse(self, context: EvalContext | None) -> tuple[Value, Diagnostics]:
        """Resolve a reference in scope, returning diagnostics when unavailable. Missing defaults,
        resource attributes, and plan-time values must not be guessed.
        """
        if not self:
            return DYNAMIC_VAL, error("Invalid traversal", "Empty reference.")
        root = self[0]
        if not isinstance(root, TraverseRoot):
            return DYNAMIC_VAL, error("Invalid traversal", "Reference has no root.", self.range)
        if context is None:
            return DYNAMIC_VAL, error(
                "Variables not allowed",
                "Variables may not be used here.",
                root.range,
            )

        current = context.lookup(root.name)
        if current is None:
            return DYNAMIC_VAL, error(
                "Unknown variable",
                f"There is no variable named {root.name!r}.",
                root.range,
            )

        for step in self[1:]:
            if current.is_null() or current.is_unknown():
                return DYNAMIC_VAL, error(
                    "Unresolvable reference", "Value is not statically known.", step.range
                )
            if isinstance(step, TraverseAttr):
                if not isinstance(current.raw, dict) or step.name not in current.raw:
                    return DYNAMIC_VAL, error(
                        "Unsupported attribute",
                        f"This value has no attribute named {step.name!r}.",
                        step.range,
                    )
                current = current.raw[step.name]
            elif isinstance(step, TraverseIndex):
                current = _index(current, step)
                if current is None:
                    return DYNAMIC_VAL, error(
                        "Invalid index", "This value cannot be indexed.", step.range
                    )
        return current, Diagnostics()


def _index(collection: Value, step: TraverseIndex) -> Value | None:
    key = step.key
    raw = collection.raw
    if isinstance(raw, tuple):
        if key.type is not NUMBER:
            return None
        step_index = int(key.as_decimal())
        if step_index < 0 or step_index >= len(raw):
            return None
        element: Value = raw[step_index]
        return element
    if isinstance(raw, dict):
        if key.type is not STRING:
            return None
        entry: Value | None = raw.get(key.as_string())
        return entry
    return None


class EvalContext:
    """A scope for resolving references. There is deliberately no function table; rules inspect
    unevaluated calls through their source ranges.
    """

    __slots__ = ("parent", "variables")

    def __init__(
        self, variables: dict[str, Value] | None = None, parent: EvalContext | None = None
    ) -> None:
        self.variables: dict[str, Value] = variables or {}
        self.parent = parent

    def lookup(self, name: str) -> Value | None:
        context: EvalContext | None = self
        while context is not None:
            if name in context.variables:
                return context.variables[name]
            context = context.parent
        return None

    def child(self, variables: dict[str, Value]) -> EvalContext:
        return EvalContext(variables, parent=self)
