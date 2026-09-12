"""A deliberately limited cty-style value model for static analysis.

UNKNOWN differs from explicit null (None). is_wholly_known() checks nested
collections so rules never treat a partial value as complete. Numbers use
Decimal to preserve exact values and stable rendering.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any


class Kind(Enum):
    STRING = "string"
    NUMBER = "number"
    BOOL = "bool"
    LIST = "list"
    SET = "set"
    TUPLE = "tuple"
    MAP = "map"
    OBJECT = "object"
    DYNAMIC = "dynamic"


@dataclass(frozen=True, slots=True)
class Type:
    """A value's type. Collection element types are not tracked because scanner rules do not
    inspect them.
    """

    kind: Kind

    def is_primitive(self) -> bool:
        return self.kind in (Kind.STRING, Kind.NUMBER, Kind.BOOL)

    def is_list_type(self) -> bool:
        return self.kind is Kind.LIST

    def is_set_type(self) -> bool:
        return self.kind is Kind.SET

    def is_tuple_type(self) -> bool:
        return self.kind is Kind.TUPLE

    def is_map_type(self) -> bool:
        return self.kind is Kind.MAP

    def is_object_type(self) -> bool:
        return self.kind is Kind.OBJECT

    def is_collection_type(self) -> bool:
        return self.kind in (Kind.LIST, Kind.SET, Kind.TUPLE, Kind.MAP, Kind.OBJECT)

    def __str__(self) -> str:
        return self.kind.value


STRING = Type(Kind.STRING)
NUMBER = Type(Kind.NUMBER)
BOOL = Type(Kind.BOOL)
LIST = Type(Kind.LIST)
SET = Type(Kind.SET)
TUPLE = Type(Kind.TUPLE)
MAP = Type(Kind.MAP)
OBJECT = Type(Kind.OBJECT)
DYNAMIC = Type(Kind.DYNAMIC)


class _Unknown:
    """Sentinel for a value that exists but cannot be determined statically."""

    _instance: _Unknown | None = None

    def __new__(cls) -> _Unknown:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<unknown>"


_UNKNOWN_MARKER = _Unknown()


@dataclass(frozen=True, slots=True)
class Value:
    """A cty-style value. raw holds str, Decimal, bool, a tuple of Values, a dict of Values, None
    for null, or _UNKNOWN_MARKER.
    """

    type: Type
    raw: Any = None

    # --- state predicates -------------------------------------------------

    def is_null(self) -> bool:
        return self.raw is None

    def is_unknown(self) -> bool:
        return self.raw is _UNKNOWN_MARKER

    def is_wholly_known(self) -> bool:
        """Return False if this value or any nested element is unknown."""
        if self.is_unknown():
            return False
        if self.is_null():
            return True
        if isinstance(self.raw, tuple):
            return all(element_value.is_wholly_known() for element_value in self.raw)
        if isinstance(self.raw, dict):
            return all(element_value.is_wholly_known() for element_value in self.raw.values())
        return True

    # --- accessors --------------------------------------------------------

    def as_string(self) -> str:
        if self.type is not STRING or not isinstance(self.raw, str):
            raise TypeError(f"as_string on a {self.type} value")
        return self.raw

    def true(self) -> bool:
        if self.type is not BOOL or not isinstance(self.raw, bool):
            raise TypeError(f"true() on a {self.type} value")
        return self.raw

    def as_decimal(self) -> Decimal:
        if self.type is not NUMBER or not isinstance(self.raw, Decimal):
            raise TypeError(f"as_decimal on a {self.type} value")
        return self.raw

    def as_number_string(self) -> str:
        """Render a number using Go big.Float.String() conventions: ten significant digits and no
        trailing .0 for integers.
        """
        return format_number(self.as_decimal())

    def as_value_slice(self) -> tuple[Value, ...]:
        if not isinstance(self.raw, tuple):
            raise TypeError(f"as_value_slice on a {self.type} value")
        return self.raw

    def as_value_map(self) -> dict[str, Value]:
        if not isinstance(self.raw, dict):
            raise TypeError(f"as_value_map on a {self.type} value")
        return dict(self.raw)

    def element_iterator(self) -> Iterator[tuple[Value, Value]]:
        """Yield (key, value) pairs deterministically. Sequence keys are NUMBER values; mapping
        keys are sorted STRING values.
        """
        if isinstance(self.raw, tuple):
            for i, element_value in enumerate(self.raw):
                yield number_val(i), element_value
        elif isinstance(self.raw, dict):
            for element_key in sorted(self.raw):
                yield string_val(element_key), self.raw[element_key]

    def __str__(self) -> str:
        if self.is_unknown():
            return "<unknown>"
        if self.is_null():
            return "<null>"
        if self.type is STRING:
            return repr(self.raw)
        if self.type is NUMBER:
            return self.as_number_string()
        if self.type is BOOL:
            return "true" if self.raw else "false"
        return repr(self.raw)


def format_number(d: Decimal) -> str:
    """Format a Decimal using Go big.Float's Text('g', 10) conventions."""
    if d == d.to_integral_value() and abs(d) < Decimal(10) ** 10:
        # Integers render bare: 3306, not 3306.0 and not 3.306e+03.
        return str(int(d))
    formatted = f"{d:.10g}"
    # Python writes e-05 / e+12; Go writes the same, but normalises a lone
    # "e+00" away. Strip an exponent of zero rather than emit it.
    if formatted.endswith(("e+00", "e-00")):
        formatted = formatted[:-4]
    return formatted


# --- constructors --------------------------------------------------------


def string_val(s: str) -> Value:
    return Value(STRING, s)


def number_val(n: int | float | Decimal | str) -> Value:
    if isinstance(n, Decimal):
        return Value(NUMBER, n)
    try:
        return Value(NUMBER, Decimal(str(n)))
    except InvalidOperation as exc:  # pragma: no cover - guarded by the lexer
        raise ValueError(f"not a number: {n!r}") from exc


def bool_val(b: bool) -> Value:
    return Value(BOOL, bool(b))


def tuple_val(elements: Sequence[Value]) -> Value:
    return Value(TUPLE, tuple(elements))


def list_val(elements: Sequence[Value]) -> Value:
    return Value(LIST, tuple(elements))


def set_val(elements: Sequence[Value]) -> Value:
    return Value(SET, tuple(elements))


def object_val(attrs: Mapping[str, Value]) -> Value:
    return Value(OBJECT, dict(attrs))


def map_val(entries: Mapping[str, Value]) -> Value:
    return Value(MAP, dict(entries))


def null_val(t: Type = DYNAMIC) -> Value:
    return Value(t, None)


def unknown_val(t: Type = DYNAMIC) -> Value:
    return Value(t, _UNKNOWN_MARKER)


#: A value that is present but unknowable — what every unresolvable reference
#: evaluates to.
DYNAMIC_VAL = unknown_val(DYNAMIC)

#: The null literal.
NULL_VAL = null_val(DYNAMIC)

TRUE = bool_val(True)
FALSE = bool_val(False)
EMPTY_STRING = string_val("")


# --- conversions ---------------------------------------------------------


def to_string(v: Value) -> tuple[str, bool]:
    """Convert strings, numbers, and booleans as HCL template interpolation does. Return (text,
    success); reject other types.
    """
    if v.is_null() or v.is_unknown():
        return "", False
    if v.type is STRING:
        return v.as_string(), True
    if v.type is NUMBER:
        return v.as_number_string(), True
    if v.type is BOOL:
        return ("true" if v.true() else "false"), True
    return "", False


def from_python(obj_value: Any) -> Value:
    """Convert decoded JSON into a Value shared by variable-file and plan checks."""
    if obj_value is None:
        return NULL_VAL
    if isinstance(obj_value, bool):
        return bool_val(obj_value)
    if isinstance(obj_value, (int, float, Decimal)):
        return number_val(obj_value)
    if isinstance(obj_value, str):
        return string_val(obj_value)
    if isinstance(obj_value, Mapping):
        return object_val(
            {
                str(element_key): from_python(element_value)
                for element_key, element_value in obj_value.items()
            }
        )
    if isinstance(obj_value, Sequence):
        return tuple_val([from_python(element_value) for element_value in obj_value])
    return DYNAMIC_VAL
