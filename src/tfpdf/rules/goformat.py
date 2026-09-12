"""Rend une valeur issue d'un JSON décodé comme le `fmt.Sprint` de Go."""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any


def sprint(v: Any) -> str:
    """Rend une valeur issue d'un décodage JSON comme le ferait le `fmt.Sprint`
    de Go."""
    if v is None:
        return "<nil>"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        # Every JSON number is a float64 on the Go side, including one written
        # without a fractional part. Converting a Python int here is what makes
        # 5 and 5.0 compare equal, and it reproduces Go's precision loss on an
        # integer too large for a float64 rather than hiding it.
        return format_float(float(v))
    if isinstance(v, (list, tuple)):
        return "[" + " ".join(sprint(e) for e in v) + "]"
    if isinstance(v, dict):
        # fmt sorts map keys (Go 1.12+), so the output is deterministic.
        return "map[" + " ".join(f"{k}:{sprint(v[k])}" for k in sorted(v)) + "]"
    return str(v)


def format_float(f: float) -> str:
    """Rend un float64 comme le fait le `%v` de Go — `strconv.FormatFloat(f, 'g', -1, 64)`."""
    if math.isnan(f):
        return "NaN"
    if math.isinf(f):
        return "+Inf" if f > 0 else "-Inf"
    if f == 0:
        # Go prints negative zero as "-0"; repr agrees on the sign bit.
        return "-0" if math.copysign(1.0, f) < 0 else "0"

    sign = "-" if f < 0 else ""
    # repr gives the shortest digits that round-trip, which is the same set Go
    # computes; normalize strips the trailing zero repr leaves on integral
    # values ("100.0") so the digit count matches Go's.
    d = Decimal(repr(abs(f))).normalize()
    _, digits, exponent = d.as_tuple()
    assert isinstance(exponent, int)  # never 'n'/'N'/'F' for a finite Decimal
    exp = len(digits) - 1 + exponent

    if exp < -4 or exp >= 6:
        text = "".join(str(x) for x in digits)
        mantissa = text[0] + ("." + text[1:] if len(text) > 1 else "")
        return f"{sign}{mantissa}e{'+' if exp >= 0 else '-'}{abs(exp):02d}"

    return sign + format(d, "f")
