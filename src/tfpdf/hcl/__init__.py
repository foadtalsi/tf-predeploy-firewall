"""Parse HCL2 while preserving source positions for findings and review suggestions.

Public API: parse_config(source, filename) returns (File, Diagnostics).
Inspect File.body.attributes and File.body.blocks; evaluate expressions with
expr.value(EvalContext(...)) or inspect references with expr.variables().
Unlike dictionary-only parsers, this package retains byte offsets, lines, and
columns required by inline ignores, SARIF regions, and code-host suggestions.
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
