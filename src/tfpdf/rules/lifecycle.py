"""Protections contre la destruction des ressources persistantes."""

from __future__ import annotations

from .. import cloudname
from ..parser import Kind
from ..report.finding import Category, Finding, Fix, Severity
from ..schema import KnowledgeBase
from .base import FileInput
from .fix import as_fix, insert_into_block, replace_attr_line


class MissingLifecycleRule:
    """Signale les ressources critiques à état — bases de données, volumes, … —
    qui ne déclarent pas lifecycle { prevent_destroy = true }, et restent donc
    exposées à une suppression accidentelle par un apply négligent."""

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        if knowledge_base is None:
            return []
        findings: list[Finding] = []

        for resource in file_input.head_resources:
            # prevent_destroy guards a managed resource. Modules and data
            # sources have nothing for it to protect.
            if resource.kind is not Kind.RESOURCE:
                continue
            if not knowledge_base.is_critical(resource.type):
                continue
            if resource.prevent_destroy_value is True:
                continue  # properly protected

            line = resource.def_range.start.line
            fix: Fix | None = None

            if resource.has_lifecycle_block and resource.prevent_destroy_value is False:
                # lifecycle block exists but prevent_destroy is explicitly false
                line = resource.prevent_destroy_range.start.line
                detail = (
                    f"{resource.type} explicitly sets prevent_destroy = false — remove this or "
                    "set it to true to protect against accidental deletion"
                )
                suggestion = "  prevent_destroy = true"
                # Flipping one literal in place: the narrowest fix there is.
                fix = as_fix(
                    replace_attr_line(
                        file_input.head_source,
                        resource.prevent_destroy_range,
                        "prevent_destroy",
                        "prevent_destroy = true",
                    )
                )
            elif resource.has_lifecycle_block and resource.prevent_destroy_value is None:
                # lifecycle block exists but prevent_destroy is absent from it
                detail = (
                    f"{resource.type} has a lifecycle block but is missing prevent_destroy = true "
                    "— add it to guard against accidental deletion"
                )
                suggestion = "  prevent_destroy = true"
                fix = as_fix(
                    insert_into_block(
                        file_input.head_source, resource.lifecycle_range, "prevent_destroy = true"
                    )
                )
            else:
                # no lifecycle block at all
                detail = (
                    f"{resource.type} is a stateful/critical resource with no "
                    "lifecycle { prevent_destroy = true } guard"
                )
                suggestion = "lifecycle {\n  prevent_destroy = true\n}"
                # The block goes just inside the resource header. Anywhere in
                # the body would be equally valid HCL, but the header is the
                # one line guaranteed to exist and to be unambiguous.
                fix = as_fix(
                    insert_into_block(
                        file_input.head_source,
                        resource.def_range,
                        "lifecycle {",
                        "  prevent_destroy = true",
                        "}",
                    )
                )

            findings.append(
                Finding(
                    file=file_input.path,
                    line=line,
                    category=Category.MISSING_LIFECYCLE,
                    rule_name="missing_lifecycle",
                    severity=Severity.MEDIUM,
                    resource=resource.address(),
                    cloud_name=cloudname.of(resource),
                    message=detail,
                    suggestion=suggestion,
                    fix=fix,
                )
            )

        return findings
