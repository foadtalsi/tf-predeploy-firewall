"""Validation des attributs et détection des remplacements à partir du schéma."""

from __future__ import annotations

from .. import cloudname
from ..parser import Attribute, Kind, NestedBlock
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase
from .base import FileInput


class UnknownAttributeRule:
    """Signale les attributs absents du schéma connu pour un type de ressource
    — signature courante d'une hallucination d'IA : un attribut qui « sonne
    juste » mais n'existe pas.

    Seuls les types couverts par un pack de règles chargé sont vérifiés ; les
    types non couverts sont sautés, pour éviter les faux positifs sur des
    attributs réels mais non décrits.
    """

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        if knowledge_base is None:
            return []
        findings: list[Finding] = []

        for resource in file_input.head_resources:
            # Module inputs are someone else's variables and data sources are
            # read paths — neither has an entry in a provider resource pack, so
            # there is nothing to validate an argument name against.
            if resource.kind is not Kind.RESOURCE:
                continue
            res_schema = knowledge_base.resource_schema(resource.type)
            if res_schema is None:
                continue

            allowed_top = set(res_schema.top_level)
            for name in sorted(resource.attributes):
                if name in allowed_top:
                    continue
                findings.append(
                    Finding(
                        file=file_input.path,
                        line=resource.attributes[name].range.start.line,
                        category=Category.UNKNOWN_ATTRIBUTE,
                        rule_name="unknown_attribute",
                        severity=Severity.HIGH,
                        resource=resource.address(),
                        cloud_name=cloudname.of(resource),
                        message=(
                            f'attribute "{name}" is not a known argument of {resource.type} — '
                            "likely hallucinated or deprecated; verify against the provider docs"
                        ),
                    )
                )

            # Only validate block types explicitly listed in the schema;
            # uncurated block types (dynamic, provisioner, …) are skipped.
            for blk in resource.blocks:
                allowed_attrs = res_schema.nested_blocks.get(blk.type)
                if allowed_attrs is None:
                    continue
                allowed_blk = set(allowed_attrs)
                for name in sorted(blk.attributes):
                    if name in allowed_blk:
                        continue
                    findings.append(
                        Finding(
                            file=file_input.path,
                            line=blk.attributes[name].range.start.line,
                            category=Category.UNKNOWN_ATTRIBUTE,
                            rule_name="unknown_attribute",
                            severity=Severity.HIGH,
                            resource=resource.address(),
                            cloud_name=cloudname.of(resource),
                            message=(
                                f'attribute "{name}" inside {blk.type} block is not a known '
                                "argument — likely hallucinated or deprecated; verify against "
                                "the provider docs"
                            ),
                        )
                    )

        return findings


# --- ForceNew -------------------------------------------------------------


class ForceNewChangeRule:
    """Signale les modifications d'attributs connus comme ForceNew dans le
    schéma du fournisseur, sur une ressource qui existait déjà avant ce
    changement.

    Sans plan ni état, on ne peut pas savoir ce qui est réellement déployé, mais
    « cet attribut a changé sur une adresse de ressource préexistante » est un
    indicateur fiable : l'appliquer détruira et recréera la ressource.
    """

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        if knowledge_base is None:
            return []
        findings: list[Finding] = []

        for resource in file_input.head_resources:
            # Only a managed resource is destroyed and recreated. A module call
            # has no ForceNew surface of its own, and a data source is never
            # replaced because it is never created.
            if resource.kind is not Kind.RESOURCE:
                continue
            base = file_input.base_resources.get(resource.address())
            if base is None:
                continue

            spec = knowledge_base.force_new(resource.type)
            if spec is None:
                continue

            severity = (
                Severity.CRITICAL if knowledge_base.is_critical(resource.type) else Severity.HIGH
            )

            for attr_name in spec.top_level:
                f = _compare_attr(
                    file_input.path,
                    resource.address(),
                    resource.type,
                    attr_name,
                    "",
                    resource.attributes.get(attr_name),
                    base.attributes.get(attr_name),
                    severity,
                )
                if f is not None:
                    findings.append(f)

            # Attributes inside nested blocks (root_block_device, …).
            for block_type, force_new_attrs in spec.nested_blocks.items():
                head_blk = _find_block(resource.blocks, block_type)
                base_blk = _find_block(base.blocks, block_type)
                if head_blk is None or base_blk is None:
                    continue  # block absent in one revision; not a value change
                for attr_name in force_new_attrs:
                    f = _compare_attr(
                        file_input.path,
                        resource.address(),
                        resource.type,
                        attr_name,
                        block_type,
                        head_blk.attributes.get(attr_name),
                        base_blk.attributes.get(attr_name),
                        severity,
                    )
                    if f is not None:
                        findings.append(f)

        return findings


def _compare_attr(
    path: str,
    resource: str,
    res_type: str,
    attr_name: str,
    block_context: str,
    head: Attribute | None,
    base: Attribute | None,
    severity: Severity,
) -> Finding | None:
    if head is None or base is None:
        return None

    location = f"{block_context}.{attr_name}" if block_context else attr_name

    # When both revisions have the attribute but one or both values reference a
    # variable/expression we can't resolve statically, emit a lower-severity
    # informational finding instead of silently skipping — the user should
    # verify the value won't change at plan time.
    if not head.is_literal or not base.is_literal:
        return Finding(
            file=path,
            line=head.range.start.line,
            category=Category.FORCE_NEW_CHANGE,
            rule_name="force_new_change",
            severity=Severity.LOW,
            resource=resource,
            message=(
                f'"{location}" is a ForceNew attribute on {res_type} and uses a non-literal '
                "expression — verify the resolved value won't change at plan time "
                "(would trigger destroy+recreate)"
            ),
        )
    if head.raw_value == base.raw_value:
        return None

    return Finding(
        file=path,
        line=head.range.start.line,
        category=Category.FORCE_NEW_CHANGE,
        rule_name="force_new_change",
        severity=severity,
        resource=resource,
        message=(
            f'"{location}" changed from "{base.raw_value}" to "{head.raw_value}" — this '
            f"attribute is ForceNew on {res_type} and will destroy + recreate the resource "
            "on apply"
        ),
    )


def _find_block(blocks: list[NestedBlock], block_type: str) -> NestedBlock | None:
    for block in blocks:
        if block.type == block_type:
            return block
    return None
