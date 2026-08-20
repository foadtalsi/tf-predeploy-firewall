"""Normalise de la source .tf brute en le modèle Resource qu'inspecte le
moteur de règles.

Port de internal/parser. Enveloppe `tfpdf.hcl` pour que les règles ne touchent
jamais directement à l'AST.
"""

from .hcl import (
    cty_value_to_string,
    first_traversal_name,
    parse_file,
    parse_file_with_context,
)
from .model import Attribute, Kind, NestedBlock, Resource, type_from_address
from .scope import build_scope

__all__ = [
    "Attribute",
    "Kind",
    "NestedBlock",
    "Resource",
    "build_scope",
    "cty_value_to_string",
    "first_traversal_name",
    "parse_file",
    "parse_file_with_context",
    "type_from_address",
]
