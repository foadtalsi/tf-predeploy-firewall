"""Transformation de source .tf brute en le modèle Resource normalisé.

Port de internal/parser/hcl.go.
"""

from __future__ import annotations

from .. import hcl
from ..hcl import Block, EvalContext, HCLParseError, Value
from ..hcl.ast import Expression
from .model import Attribute, Kind, NestedBlock, Resource


def parse_file(filename: str, src: bytes) -> list[Resource]:
    """Analyse un fichier .tf et rend les blocs qu'il déclare.

    Lève `HCLParseError` sur du HCL malformé ; les appelants doivent traiter un
    échec d'analyse comme une découverte à eux plutôt que de faire tomber tout
    le scan.
    """
    return parse_file_with_context(filename, src, None)


def parse_file_with_context(filename: str, src: bytes, ctx: EvalContext | None) -> list[Resource]:
    """`parse_file`, avec une portée pour résoudre les références.

    Sans contexte, `password = var.db_password` est simplement irrésoluble et
    chaque règle le saute. Avec un contexte construit depuis les blocs `locals`
    et les valeurs par défaut de `variable` du répertoire environnant (voir
    `build_scope`), cette même ligne se résout en la valeur qu'elle portera
    réellement — c'est ainsi qu'un mot de passe laissé dans une valeur par
    défaut est attrapé au lieu de se cacher à une indirection de distance.

    Une référence que la portée ne peut pas résoudre reste non résolue plutôt
    que devinée, si bien qu'une portée plus riche ne trouve jamais que davantage,
    jamais autre chose.
    """
    body = _parse_body(filename, src)

    resources: list[Resource] = []
    for block in body.blocks:
        if block.type == "resource" and len(block.labels) == 2:
            resources.append(
                _block_to_resource(
                    filename, block, Kind.RESOURCE, block.labels[0], block.labels[1], ctx
                )
            )
        elif block.type == "data" and len(block.labels) == 2:
            resources.append(
                _block_to_resource(
                    filename, block, Kind.DATA, block.labels[0], block.labels[1], ctx
                )
            )
        elif block.type == "module" and len(block.labels) == 1:
            # A module call has no type of its own; "module" stands in so
            # schema-driven rules, which look types up in a provider pack,
            # find nothing and skip it.
            resources.append(
                _block_to_resource(filename, block, Kind.MODULE, "module", block.labels[0], ctx)
            )
    return resources


def _parse_body(filename: str, src: bytes) -> hcl.Body:
    file, diags = hcl.parse_config(src, filename)
    if diags.has_errors():
        raise HCLParseError(diags)
    return file.body


def _block_to_resource(
    filename: str,
    block: Block,
    kind: Kind,
    type_name: str,
    name: str,
    ctx: EvalContext | None,
) -> Resource:
    r = Resource(kind=kind, type=type_name, name=name, file=filename, def_range=block.def_range())

    for attr_name, attr in block.body.attributes.items():
        r.attributes[attr_name] = _attr_to_attribute(attr_name, attr, ctx)

    for nested in block.body.blocks:
        if nested.type == "lifecycle":
            r.has_lifecycle_block = True
            r.lifecycle_range = nested.def_range()
            pd_attr = nested.body.attributes.get("prevent_destroy")
            if pd_attr is not None:
                r.prevent_destroy_range = pd_attr.src_range
                v, diags = pd_attr.expr.value(ctx)
                if not diags.has_errors() and v.type is hcl.BOOL and not v.is_null():
                    r.prevent_destroy_value = v.true()
            continue
        nb = NestedBlock(type=nested.type, labels=list(nested.labels), range=nested.def_range())
        for attr_name, attr in nested.body.attributes.items():
            nb.attributes[attr_name] = _attr_to_attribute(attr_name, attr, ctx)
        r.blocks.append(nb)

    return r


def _attr_to_attribute(name: str, attr: hcl.Attribute, ctx: EvalContext | None) -> Attribute:
    a = Attribute(name=name, range=attr.src_range)

    # Try the expression on its own first. If that works, the value was written
    # inline and there is no indirection worth reporting.
    v, diags = attr.expr.value(None)
    if not diags.has_errors():
        a.is_literal = True
        a.raw_value = cty_value_to_string(v)
        return a

    if ctx is None:
        # References a variable/resource/function we cannot resolve (no plan,
        # no state). Leave raw_value empty; rules that need a literal simply
        # skip this attribute.
        return a

    v, diags = attr.expr.value(ctx)
    if diags.has_errors() or not v.is_wholly_known():
        return a
    a.is_literal = True
    a.raw_value = cty_value_to_string(v)
    a.resolved_from = first_traversal_name(attr.expr)
    return a


def first_traversal_name(expr: Expression) -> str:
    """Rend la référence dont une expression lit sa valeur —
    « var.db_password », « local.admin_pw » — pour usage dans un message de
    découverte."""
    for traversal in expr.variables():
        name = traversal.render(max_steps=2)
        if name:
            return name
    return ""


def cty_value_to_string(v: Value) -> str:
    """Rend une valeur littérale en texte brut, pour la comparaison de motifs :
    comparer des valeurs d'attributs ForceNew d'une révision à l'autre, ou
    chercher « 0.0.0.0/0 » par expression régulière.

    **Défaut connu, porté tel quel plutôt que corrigé ici.** Un objet ou un map
    rend `""` — seuls les chaînes, nombres, booléens et séquences sont traités.
    Une règle personnalisée « doit avoir des tags » écrite ainsi :

        attribute: tags
        pattern: ".+"
        negate: true

    voit donc `""` pour `tags = { env = "prod" }`, conclut que le motif n'a pas
    correspondu, et **se déclenche sur une ressource qui définit bien des
    tags**. C'est un faux positif qui bloque une PR chez un client.

    Le comportement a été confirmé identique côté Go — mêmes deux découvertes
    sur les mêmes deux lignes — et
    `test_customrules.py::test_negated_rule_misfires_on_an_object_valued_attribute`
    l'épingle, pour que le port reste fidèle et qu'une correction apparaisse
    comme un changement délibéré des deux côtés à la fois. L'endroit naturel
    pour corriger est ici : rendre un objet comme ses paires `clé=valeur`
    triées.
    """
    if v.is_null() or v.is_unknown():
        return ""
    if v.type is hcl.STRING:
        return v.as_string()
    if v.type is hcl.BOOL:
        return "true" if v.true() else "false"
    if v.type is hcl.NUMBER:
        return v.as_number_string()
    if v.type.is_list_type() or v.type.is_tuple_type() or v.type.is_set_type():
        return ",".join(cty_value_to_string(ev) for _, ev in v.element_iterator())
    return ""
