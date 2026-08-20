"""Une sérialisation qui correspond octet pour octet au
`json.MarshalIndent(v, "", "  ")` de Go.

Deux documents que ce scanner produit sont consommés par des machines
configurées contre la sortie de la version Go — un dépôt SARIF et un rapport
GitLab Code Quality — donc « du JSON sémantiquement équivalent » n'est pas la
barre. Les deux différences qui mordent réellement :

  * L'encodeur de Go échappe `<`, `>` et `&` en HTML par défaut, et échappe
    aussi U+2028 et U+2029. Le message d'une découverte cite du texte source :
    une règle qui rapporte sur `cidr_blocks = ["0.0.0.0/0"]` va bien, mais une
    règle qui cite une politique façon XML ou un `&&` ne va pas.
  * Go émet le non-ASCII en UTF-8 brut ; le `json.dumps` de Python l'échappe en
    `\\uXXXX` sauf instruction contraire. Chaque tiret cadratin d'un message de
    règle différerait.

Les deux sont traités ici, pour qu'aucun appelant n'ait à s'en souvenir.
"""

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
    """Réécrit les flottants entiers en entiers, comme Go écrit un float64.

    Go sérialise `float64(70)` en `70` ; le `json` de Python écrit `70.0`. Les
    données de tarification du paquet de règles sont le seul endroit où des
    flottants atteignent un document sérialisé, et un pack régénéré doit être
    comparable au pack commité.
    """
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
    """Sérialise comme le ferait `json.Marshal` de Go : compact, sans espaces.

    Utilisé pour les packs de règles générés, qui sont comparés aux packs
    commités — une espace après chaque deux-points ferait plusieurs centaines de
    kilo-octets de différence sur le pack AWS complet, et un diff que personne ne
    peut lire.
    """
    out = json.dumps(_go_numbers(v), separators=(",", ":"), ensure_ascii=False)
    for raw, escaped in _GO_ESCAPES:
        out = out.replace(raw, escaped)
    return out.encode()
