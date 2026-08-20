"""Le modèle de blocs normalisé sur lequel travaille le moteur de règles.

Port de internal/parser/model.go. Les règles voient ces types et ne touchent
jamais à l'AST HCL, si bien qu'un changement dans la façon dont le HCL est
analysé ne peut pas se propager dans trente fichiers de règles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..hcl import Range


class Kind(StrEnum):
    """Les natures de bloc de premier niveau que ce paquet normalise.

    Elles partagent un seul type parce que toute règle qui s'intéresse aux
    *valeurs* — un mot de passe en dur, un CIDR ouvert — s'y intéresse de façon
    identique ; seules les règles ayant besoin d'un schéma de fournisseur sont
    réservées aux ressources.
    """

    #: A `resource "aws_db_instance" "prod" { … }` block.
    RESOURCE = "resource"

    #: A `module "rds" { … }` call. Its arguments are inputs to someone else's
    #: module, so there is no schema to validate their names against — but a
    #: password passed to a module is just as hardcoded as one passed to a
    #: resource, and mature Terraform repos are mostly module calls, so
    #: ignoring them made the scanner blind exactly where it mattered most.
    MODULE = "module"

    #: A `data "aws_ami" "ubuntu" { … }` block. Data sources read rather than
    #: create, so lifecycle and ForceNew rules do not apply, but their
    #: arguments can still carry credentials.
    DATA = "data"


@dataclass(slots=True)
class Attribute:
    """Un unique `nom = valeur` à l'intérieur d'un bloc."""

    name: str
    #: Range of the whole `name = value` span.
    range: Range = field(default_factory=Range)
    #: The literal string form of the expression when it evaluated statically
    #: (string/number/bool/list of these). Empty when the expression depends on
    #: something that cannot be resolved.
    raw_value: str = ""
    is_literal: bool = False
    #: The reference this value came from — "var.db_password", "local.admin_pw"
    #: — when the literal was reached by following a variable default or a
    #: local rather than being written inline.
    #:
    #: It exists so a finding can point at where the value actually lives. A
    #: report saying `password` is hardcoded, on a line that only reads
    #: `password = var.db_password`, otherwise looks like a false positive to
    #: the person reading it.
    resolved_from: str = ""


@dataclass(slots=True)
class NestedBlock:
    """Un sous-bloc nommé dans le corps d'une ressource : `ingress { … }`,
    `root_block_device { … }`."""

    type: str
    labels: list[str] = field(default_factory=list)
    range: Range = field(default_factory=Range)
    attributes: dict[str, Attribute] = field(default_factory=dict)


@dataclass(slots=True)
class Resource:
    """Une vue normalisée d'un bloc de premier niveau, indépendante de l'AST
    HCL."""

    #: What sort of block this came from. Rules that depend on the provider
    #: schema (unknown attributes, ForceNew, prevent_destroy) must check this
    #: and act only on RESOURCE.
    kind: Kind
    type: str
    name: str
    file: str

    #: Source range of the block header, the fallback location for findings.
    def_range: Range = field(default_factory=Range)

    attributes: dict[str, Attribute] = field(default_factory=dict)

    #: Non-lifecycle nested blocks, so rules can inspect attributes inside them
    #: (e.g. cidr_blocks in ingress).
    blocks: list[NestedBlock] = field(default_factory=list)

    has_lifecycle_block: bool = False
    #: None when prevent_destroy is absent or not a literal bool.
    prevent_destroy_value: bool | None = None
    prevent_destroy_range: Range = field(default_factory=Range)

    #: Header range of the `lifecycle {` block, when one exists. Only
    #: meaningful alongside has_lifecycle_block; it lets a rule point at the
    #: block it needs to add a setting to, rather than at the whole resource.
    lifecycle_range: Range = field(default_factory=Range)

    def address(self) -> str:
        """L'identifiant canonique, correspondant à l'adresse qu'utilise
        Terraform."""
        if self.kind is Kind.MODULE:
            return "module." + self.name
        if self.kind is Kind.DATA:
            return "data." + self.type + "." + self.name
        return self.type + "." + self.name


def type_from_address(addr: str) -> tuple[str, bool, bool]:
    """Relit le type de ressource du fournisseur depuis une adresse Terraform.

    L'inverse de `Resource.address`, et des adresses qu'emploie `terraform show
    -json`, qui suivent la même grammaire. Elle existe pour que tout ce qui ne
    détient qu'une adresse — une découverte, une entrée de plan — puisse quand
    même atteindre la documentation du fournisseur pour ce type.

    Rend (type_de_ressource, est_source_de_données, ok). `ok` vaut False pour
    les adresses sans type propre : un appel de module, ou le « - » de
    remplacement que porte une découverte concernant tout un fichier.
    """
    parts = addr.split(".")

    # A plan address can be nested arbitrarily deep in modules
    # (module.a.module.b.aws_db_instance.this); peel them off.
    while len(parts) >= 3 and parts[0] == "module":
        parts = parts[2:]
    if len(parts) < 2:
        return "", False, False

    if parts[0] == "data":
        if len(parts) < 3:
            return "", False, False
        return parts[1], True, True
    if parts[0] == "module":
        return "", False, False
    return parts[0], False, True
