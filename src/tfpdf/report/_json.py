"""Une sérialisation qui correspond octet pour octet au `json.MarshalIndent(v, "", " ")` de Go."""

from __future__ import annotations

import json
from typing import Any

# Applied to the serialised text rather than to the values: the JSON grammar
# uses none of these characters outside string literals, so a global
# replacement can only ever touch string content. An already-escaped sequence
# is spelled `<` and contains no `<`, so it is not re-escaped either.
_GO_ESCAPES = (
    ("<", "\\u003c"),
    (">", "\\u003e"),
    ("&", "\\u0026"),
    ("\u2028", "\\u2028"),
    ("\u2029", "\\u2029"),
)


#: Above this, Go's JSON encoder switches a float64 to exponent notation
#: (`1e+21`), which `json.dumps` cannot be asked to emit for a specific value.
#: Nothing this scanner serialises comes close — the only floats are coarse
#: USD/month cost estimates — so the bound is enforced rather than handled.
_GO_FLOAT_EXP_THRESHOLD = 1e21


def _go_numbers(v: Any) -> Any:
    """Réécrit les flottants entiers en entiers, comme Go écrit un float64."""
    if isinstance(v, bool):
        return v  # bool is an int subclass; it must stay true/false
    if isinstance(v, float):
        if abs(v) >= _GO_FLOAT_EXP_THRESHOLD:
            raise ValueError(
                f"{v!r} is large enough that Go would write it in exponent notation; "
                "this encoder cannot reproduce that"
            )
        return int(v) if v.is_integer() else v
    if isinstance(v, dict):
        return {k: _go_numbers(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_go_numbers(x) for x in v]
    return v


def marshal_indent(v: Any) -> bytes:
    """Sérialise comme le ferait `json.MarshalIndent(v, "", "  ")` de Go."""
    out = json.dumps(_go_numbers(v), indent=2, ensure_ascii=False)
    for raw, escaped in _GO_ESCAPES:
        out = out.replace(raw, escaped)
    return out.encode()


def marshal(v: Any) -> bytes:
    """Sérialise comme le ferait `json.Marshal` de Go : compact, sans espaces."""
    out = json.dumps(_go_numbers(v), separators=(",", ":"), ensure_ascii=False)
    for raw, escaped in _GO_ESCAPES:
        out = out.replace(raw, escaped)
    return out.encode()
