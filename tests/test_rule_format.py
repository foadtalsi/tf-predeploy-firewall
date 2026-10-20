"""Resource-level exclusions in a rule pack's match block."""

from __future__ import annotations

from tfpdf import ruledef
from tfpdf.parser import parse_file
from tfpdf.rules.declarative import matches_resource

_PACK = """
version: 1
rules:
  - id: open_ingress
    category: tutorial_pattern
    severity: high
    match:
      scope: attribute
      skip_resource_types: [aws_vpc_security_group_egress_rule]
      skip_when_attribute_equals: {type: egress}
      attr_name_contains: cidr
      literal: true
      value_contains: 0.0.0.0/0
    message: "{attr_q} is open"
"""

_SOURCE = b"""
resource "aws_security_group_rule" "ingress" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "egress" {
  type        = "egress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "type_from_variable" {
  type        = var.direction
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_egress_rule" "egress" {
  cidr_ipv4 = "0.0.0.0/0"
}
"""


def test_skip_conditions_exclude_matching_resources_only() -> None:
    match = ruledef.load(_PACK).rules[0].match
    assert match is not None

    matched = [
        resource.address()
        for resource in parse_file("main.tf", _SOURCE)
        if matches_resource(match, resource)
    ]

    # A value the scanner cannot evaluate does not trigger a skip.
    assert matched == [
        "aws_security_group_rule.ingress",
        "aws_security_group_rule.type_from_variable",
    ]


def test_skip_conditions_survive_the_yaml_export() -> None:
    pack = ruledef.load(_PACK)
    match = ruledef.load(ruledef.toyaml.to_yaml(pack)).rules[0].match
    assert match is not None
    assert match.skip_resource_types == ["aws_vpc_security_group_egress_rule"]
    assert match.skip_when_attribute_equals == {"type": "egress"}
