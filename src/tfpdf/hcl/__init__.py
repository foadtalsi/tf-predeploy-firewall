"""Un analyseur HCL2 qui conserve la ligne et la colonne exactes de chaque
élément.

Surface publique, calquée sur `hashicorp/hcl/v2` pour que les deux scanners se
lisent côte à côte :

    parse_config(src, filename) -> (File, Diagnostics)
    File.body.attributes: dict[str, Attribute]
    File.body.blocks: list[Block]
    Attribute.expr.value(ctx) -> (Value, Diagnostics)
    Attribute.expr.variables() -> list[Traversal]
    EvalContext(variables={"var": object_val({...})})

Écrit dans l'arbre plutôt que pris sur PyPI : les bibliothèques disponibles
rendent des dictionnaires et perdent ligne et colonne. Or chaque sortie de ce
scanner est positionnelle — commentaire de PR sur la bonne ligne, région SARIF,
bloc `suggestion`, correspondance `# tf-firewall-ignore:`. Un analyseur qui perd
les positions ne perd pas une fonctionnalité, il perd le produit.
"""

from .ast import Attribute, Block, Body, Expression, File
from .diagnostics import Diagnostic, Diagnostics, HCLParseError, Severity
from .lexer import Lexer, tokenize
from .parser import parse_config
from .pos import INITIAL_POS, Pos, Range
from .traversal import (
    EvalContext,
    Traversal,
    TraverseAttr,
    TraverseIndex,
    TraverseRoot,
)
from .values import (
    BOOL,
    DYNAMIC,
    DYNAMIC_VAL,
    LIST,
    MAP,
    NULL_VAL,
    NUMBER,
    OBJECT,
    SET,
    STRING,
    TUPLE,
    Kind,
    Type,
    Value,
    bool_val,
    from_python,
    list_val,
    map_val,
    null_val,
    number_val,
    object_val,
    set_val,
    string_val,
    to_string,
    tuple_val,
    unknown_val,
)

__all__ = [
    "BOOL",
    "DYNAMIC",
    "DYNAMIC_VAL",
    "INITIAL_POS",
    "LIST",
    "MAP",
    "NULL_VAL",
    "NUMBER",
    "OBJECT",
    "SET",
    "STRING",
    "TUPLE",
    "Attribute",
    "Block",
    "Body",
    "Diagnostic",
    "Diagnostics",
    "EvalContext",
    "Expression",
    "File",
    "HCLParseError",
    "Kind",
    "Lexer",
    "Pos",
    "Range",
    "Severity",
    "Traversal",
    "TraverseAttr",
    "TraverseIndex",
    "TraverseRoot",
    "Type",
    "Value",
    "bool_val",
    "from_python",
    "list_val",
    "map_val",
    "null_val",
    "number_val",
    "object_val",
    "parse_config",
    "set_val",
    "string_val",
    "to_string",
    "tokenize",
    "tuple_val",
    "unknown_val",
]
