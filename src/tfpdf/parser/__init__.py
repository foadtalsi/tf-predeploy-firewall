"""Normalize Terraform source into the Resource model inspected by rules."""

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
