"""Mise en forme des messages des règles déclaratives.

Port de internal/rules/template.go.

Un ensemble fixe de jetons `{placeholder}`, substitués depuis ce que le matcher
a trouvé. Délibérément pas un langage d'expression : un fichier de règles décide
de la formulation, pas du flot de contrôle, et dès qu'un template peut calculer
il cesse d'être une donnée.
"""

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
    """Substitue les jetons connus et laisse tout le reste octet pour octet.

    Les jetons inconnus survivent intacts à dessein : les templates de correctif
    et de suggestion contiennent de véritables accolades HCL (`variable "x" {`),
    et un moteur qui les avalerait ou lèverait dessus ne pourrait pas écrire de
    Terraform.
    """
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
    """Rend `s` comme le fait le `strconv.Quote` de Go.

    Utilisé pour les valeurs de remplissage `{attr_q}`, `{value_q}` et
    `{name_q}`, qui mettent un identifiant ou une valeur entre guillemets dans
    un message de découverte. Le `repr` de Python n'est pas un substitut : il
    préfère les apostrophes, si bien que chaque message sortirait avec les
    mauvais guillemets et que chaque fichier témoin différerait.

    Le non-ASCII imprimable est gardé tel quel, comme le fait Go ; seuls les
    caractères de contrôle et les deux caractères structurels sont échappés.
    """
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
