"""Port de internal/parser/parser_test.go et address_test.go, cas pour
cas."""

from __future__ import annotations

import pytest

from tfpdf.hcl import HCLParseError
from tfpdf.parser import (
    Kind,
    Resource,
    build_scope,
    parse_file,
    parse_file_with_context,
    type_from_address,
)

SAMPLE_TF = b"""
resource "aws_db_instance" "primary" {
  identifier = "prod-db"
  engine     = "postgres"
  username   = "admin"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = "vpc-123"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def test_parse_file_top_level_attributes() -> None:
    resources = parse_file("test.tf", SAMPLE_TF)
    assert len(resources) == 2

    db = resources[0]
    assert db.address() == "aws_db_instance.primary"
    assert "identifier" in db.attributes
    attribute = db.attributes["identifier"]
    assert attribute.is_literal
    assert attribute.raw_value == "prod-db"


def test_parse_file_lifecycle_block() -> None:
    db = parse_file("test.tf", SAMPLE_TF)[0]
    assert db.has_lifecycle_block
    assert db.prevent_destroy_value is not None
    assert db.prevent_destroy_value is True


def test_parse_file_nested_blocks() -> None:
    sg = parse_file("test.tf", SAMPLE_TF)[1]
    assert sg.address() == "aws_security_group.web"
    assert len(sg.blocks) == 1

    blk = sg.blocks[0]
    assert blk.type == "ingress"
    cidr = blk.attributes.get("cidr_blocks")
    assert cidr is not None
    assert cidr.is_literal
    assert cidr.raw_value == "0.0.0.0/0"


def test_parse_file_malformed_hcl() -> None:
    with pytest.raises(HCLParseError):
        parse_file("bad.tf", b'resource "aws_instance" "x" {')


def test_parse_file_parses_resources_modules_and_data_sources() -> None:
    """Les appels de module et les sources de données sont analysés au même
    titre que les ressources : un dépôt Terraform mûr est surtout fait d'appels
    de module, et un mot de passe passé à un module est exactement aussi en dur
    qu'un mot de passe passé à une ressource. Les blocs de déclaration
    (variable, locals, output) ne le sont pas — ils déclarent, ils ne configurent
    pas d'infrastructure."""
    source = b"""
variable "region" { default = "us-east-1" }
locals { env = "prod" }
output "vpc_id" { value = "x" }

data "aws_ami" "ubuntu" { most_recent = true }
module "rds" {
  source          = "./modules/rds"
  master_password = "hunter2"
}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
"""
    by_addr = {r.address(): r for r in parse_file("test.tf", source)}
    assert len(by_addr) == 3, f"expected 3 blocks, got {sorted(by_addr)}"

    assert by_addr["aws_vpc.main"].kind is Kind.RESOURCE
    assert by_addr["module.rds"].kind is Kind.MODULE
    assert by_addr["data.aws_ami.ubuntu"].kind is Kind.DATA

    # The module's arguments must be readable, since that is the whole point.
    pw = by_addr["module.rds"].attributes.get("master_password")
    assert pw is not None and pw.raw_value == "hunter2"


def test_parse_file_with_context_resolves_vars_and_locals() -> None:
    """Résolution à travers une valeur par défaut de variable ou un local : la
    valeur qu'une règle voit doit être la valeur que l'attribut porte
    réellement, pas le texte de la référence."""
    source = b"""
variable "db_password" { default = "changeme" }
locals { admin_user = "root" }

resource "aws_db_instance" "prod" {
  password = var.db_password
  username = local.admin_user
  engine   = "postgres"
}
"""
    scope = build_scope({"main.tf": source})
    assert scope is not None

    attrs = parse_file_with_context("main.tf", source, scope)[0].attributes

    assert attrs["password"].is_literal
    assert attrs["password"].raw_value == "changeme"
    assert attrs["password"].resolved_from == "var.db_password", (
        "a finding on this line has to say where the value lives"
    )

    assert attrs["username"].is_literal
    assert attrs["username"].raw_value == "root"
    assert attrs["username"].resolved_from == "local.admin_user"

    # An inline literal is not "resolved from" anything.
    assert attrs["engine"].is_literal
    assert attrs["engine"].resolved_from == ""


def test_parse_file_with_context_leaves_unresolvable_values_alone() -> None:
    """La portée ne doit jamais inventer de valeur. Une variable sans valeur
    par défaut est fournie au moment du plan, et deviner serait la façon dont les
    faux positifs entrent."""
    source = b"""
variable "db_password" {}

resource "aws_db_instance" "prod" {
  password       = var.db_password
  something_else = aws_kms_key.k.arn
}
"""
    scope = build_scope({"main.tf": source})
    attrs = parse_file_with_context("main.tf", source, scope)[0].attributes
    for name in ("password", "something_else"):
        assert not attrs[name].is_literal, f"{name} must stay unresolved"


def test_build_scope_is_directory_wide() -> None:
    """Terraform porte les locals au niveau du répertoire : un local déclaré
    dans un fichier doit donc être visible en scannant un autre."""
    rds = b'resource "aws_db_instance" "p" { password = local.admin_pw }'
    scope = build_scope(
        {
            "locals.tf": b'locals { admin_pw = "s3cret" }',
            "rds.tf": rds,
        }
    )
    attrs = parse_file_with_context("rds.tf", rds, scope)[0].attributes
    assert attrs["password"].is_literal
    assert attrs["password"].raw_value == "s3cret"


# --- address_test.go ------------------------------------------------------


@pytest.mark.parametrize(
    ("addr", "want_type", "want_data", "want_ok"),
    [
        ("aws_vpc.main", "aws_vpc", False, True),
        ("data.aws_ami.ubuntu", "aws_ami", True, True),
        # Plan addresses nest through modules, arbitrarily deep.
        ("module.rds.aws_db_instance.this", "aws_db_instance", False, True),
        ("module.a.module.b.aws_db_instance.this", "aws_db_instance", False, True),
        ("module.vpc.data.aws_availability_zones.available", "aws_availability_zones", True, True),
        # for_each / count keys hang off the name, never the type.
        ("aws_instance.web[0]", "aws_instance", False, True),
        ('module.envs["prod"].aws_vpc.main', "aws_vpc", False, True),
        # A module call has no type of its own.
        ("module.rds", "", False, False),
        # The placeholder a whole-file finding carries.
        ("-", "", False, False),
        ("", "", False, False),
    ],
)
def test_type_from_address(addr: str, want_type: str, want_data: bool, want_ok: bool) -> None:
    assert type_from_address(addr) == (want_type, want_data, want_ok)


def test_type_from_address_round_trips_with_address() -> None:
    """address() et type_from_address doivent s'accorder, sinon un lien pointe
    vers la mauvaise page pour exactement les blocs que l'analyseur produit."""
    for r in (
        Resource(kind=Kind.RESOURCE, type="aws_vpc", name="main", file="f.tf"),
        Resource(kind=Kind.DATA, type="aws_ami", name="ubuntu", file="f.tf"),
    ):
        got_type, got_data, ok = type_from_address(r.address())
        assert ok
        assert got_type == r.type
        assert got_data is (r.kind is Kind.DATA)

    module = Resource(kind=Kind.MODULE, type="module", name="rds", file="f.tf")
    _, _, ok = type_from_address(module.address())
    assert not ok, "a module call must not resolve to a resource type"
