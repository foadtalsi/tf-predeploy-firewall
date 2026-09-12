"""Resolve variable defaults and locals for static analysis."""

from __future__ import annotations

from .. import hcl
from ..hcl import EvalContext, Value


def build_scope(files_by_path: dict[str, bytes]) -> EvalContext | None:
    """Build a directory's evaluation context from Terraform file contents indexed by path."""
    locals_: dict[str, Value] = {}
    vars_: dict[str, Value] = {}

    for path, source in files_by_path.items():
        file, diags = hcl.parse_config(source, path)
        if diags.has_errors():
            # One unparseable file must not cost us the scope of the rest of
            # the directory; the engine reports that file's parse error itself.
            continue

        for block in file.body.blocks:
            if block.type == "locals":
                for name, attribute in block.body.attributes.items():
                    value, diagnostics = attribute.expr.value(None)
                    if not diagnostics.has_errors() and value.is_wholly_known():
                        locals_[name] = value
            elif block.type == "variable" and len(block.labels) == 1:
                # Only `default` is a value we can know statically. A variable
                # without one is supplied at plan time, so it stays unknown.
                default = block.body.attributes.get("default")
                if default is None:
                    continue
                value, diagnostics = default.expr.value(None)
                if not diagnostics.has_errors() and value.is_wholly_known():
                    vars_[block.labels[0]] = value

    if not locals_ and not vars_:
        return None

    variables: dict[str, Value] = {}
    if locals_:
        variables["local"] = hcl.object_val(locals_)
    if vars_:
        variables["var"] = hcl.object_val(vars_)
    return EvalContext(variables)
