"""Quels attributs le diff .tf propre à cette PR a réellement touchés.

Port de internal/rules/changedattrs.go.

Les règles fondées sur le plan s'en servent pour savoir si une valeur que le
plan dit changée a bien été touchée par cette PR, ou si elle a dérivé depuis une
autre source : édition en console, autre pipeline, valeur par défaut d'un
fournisseur qui a bougé.
"""

from __future__ import annotations

from ..parser import Attribute, NestedBlock, Resource

#: One attribute inside the PR's own diff, either top-level ("engine") or
#: inside a nested block ("root_block_device.volume_type").
ChangedAttrKey = str


def changed_attrs_for_resource(head: Resource | None, base: Resource | None) -> set[ChangedAttrKey]:
    """Les clés d'attributs dont la valeur littérale diffère entre la base et la
    tête, ou dont la présence a changé (ajouté ou retiré).

    Les expressions non littérales (var.x, data.foo.bar) sont traitées
    prudemment comme « changées » — nous ne pouvons pas prouver qu'elles ne
    l'ont pas été, et il vaut mieux sous-rapporter la dérive que la
    sur-rapporter.
    """
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
    return {b.type: b for b in blocks}


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
    """Réduit une adresse de plan terraform à la forme nue « type.nom » que
    produit l'analyseur HCL.

    Une adresse de plan peut porter un préfixe de chemin de module
    (« module.vpc.module.subnets.aws_subnet.private ») et/ou un suffixe de clé
    d'instance issu de count ou for_each (« aws_instance.web[0] »,
    `aws_instance.web["prod"]`), dont le scan HCL statique ne sait rien : il ne
    voit jamais que le type et l'étiquette propres au bloc de ressource. Sans
    cette normalisation, chaque ressource à l'intérieur d'un module — la
    disposition de très loin la plus courante dans la vraie vie — ou derrière un
    count ou un for_each échouerait à s'apparier avec l'ensemble des attributs
    modifiés, et serait mal rapportée comme une dérive.
    """
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
