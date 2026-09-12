"""Identify attributes actually changed by this pull request's Terraform diff."""

from __future__ import annotations

from ..parser import Attribute, NestedBlock, Resource

#: One attribute inside the PR's own diff, either top-level ("engine") or
#: inside a nested block ("root_block_device.volume_type").
ChangedAttrKey = str


def changed_attrs_for_resource(head: Resource | None, base: Resource | None) -> set[ChangedAttrKey]:
    """Return attributes whose literal values or presence differ between base and head."""
    changed: set[ChangedAttrKey] = set()
    if head is None or base is None:
        return changed

    _diff_attr_maps(head.attributes, base.attributes, "", changed)

    head_blocks = _blocks_by_type(head.blocks)
    base_blocks = _blocks_by_type(base.blocks)
    for block_type, head_blk in head_blocks.items():
        base_blk = base_blocks.get(block_type)
        if base_blk is None:
            continue  # whole block is new; not a per-attribute drift comparison
        _diff_attr_maps(head_blk.attributes, base_blk.attributes, block_type + ".", changed)

    return changed


def _blocks_by_type(blocks: list[NestedBlock]) -> dict[str, NestedBlock]:
    return {block.type: block for block in blocks}


def _diff_attr_maps(
    head: dict[str, Attribute],
    base: dict[str, Attribute],
    prefix: str,
    out: set[ChangedAttrKey],
) -> None:
    for name, head_attr in head.items():
        base_attr = base.get(name)
        if base_attr is None:
            out.add(prefix + name)
            continue
        if (
            not head_attr.is_literal
            or not base_attr.is_literal
            or head_attr.raw_value != base_attr.raw_value
        ):
            out.add(prefix + name)
    for name in base:
        if name not in head:
            out.add(prefix + name)


def bare_resource_address(plan_addr: str) -> str:
    """Reduce a plan address to the type.name form used by the HCL parser."""
    addr = plan_addr
    index = addr.find("[")
    if index >= 0:
        # An instance key suffix only ever appears on the final segment, so it
        # is safe to strip before splitting on ".".
        close_idx = addr.rfind("]")
        addr = addr[:index] + addr[close_idx + 1 :] if close_idx > index else addr[:index]
    parts = addr.split(".")
    if len(parts) < 2:
        return addr
    return parts[-2] + "." + parts[-1]
