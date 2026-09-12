"""Mise en forme des messages des règles déclaratives."""

from __future__ import annotations

import re

#: Also matches a `${…}` so it can decline to substitute one. Rule text is
#: HCL-adjacent — a fix that writes an interpolation would otherwise have its
#: inner braces eaten.
_TEMPLATE_TOKEN = re.compile(r"\$?\{([a-z_]+)\}")

_GO_ESCAPES = {
    "\a": r"\a",
    "\b": r"\b",
    "\f": r"\f",
    "\n": r"\n",
    "\r": r"\r",
    "\t": r"\t",
    "\v": r"\v",
    "\\": "\\\\",
    '"': r"\"",
}


def expand(template: str, variables: dict[str, str]) -> str:
    """Substitue les jetons connus et laisse tout le reste octet pour octet."""
    if not template:
        return ""

    def repl(m: re.Match[str]) -> str:
        tok = m.group(0)
        if tok[0] == "$":
            return tok  # an interpolation, not a placeholder
        return variables.get(m.group(1), tok)

    return _TEMPLATE_TOKEN.sub(repl, template)


def expand_all(tmpls: list[str], variables: dict[str, str]) -> list[str]:
    """`expand` sur une liste, pour les corps de correctifs multi-lignes."""
    return [expand(t, variables) for t in tmpls]


def go_quote(s: str) -> str:
    """Rend `s` comme le fait le `strconv.Quote` de Go."""
    out = ['"']
    for ch in s:
        esc = _GO_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        elif ord(ch) < 0x10000:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(f"\\U{ord(ch):08x}")
    out.append('"')
    return "".join(out)
