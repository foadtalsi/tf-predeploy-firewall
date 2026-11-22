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


_FIREWALL_PACK = """
version: 1
rules:
  - id: open_firewall
    category: tutorial_pattern
    severity: high
    match:
      scope: attribute
      skip_when_resource_contains: [deny]
      attr_names: [source_ranges]
      literal: true
      value_contains: 0.0.0.0/0
    message: "{attr_q} is open"
"""

_FIREWALL_SOURCE = b"""
resource "google_compute_firewall" "allow" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
  }
}

resource "google_compute_firewall" "deny" {
  source_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "tcp"
  }
}

# Only a top-level block counts: a nested `deny` is some other setting.
resource "google_compute_firewall" "nested" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    deny {
    }
  }
}
"""


def test_a_resource_holding_a_named_block_is_skipped() -> None:
    match = ruledef.load(_FIREWALL_PACK).rules[0].match
    assert match is not None

    matched = [
        resource.address()
        for resource in parse_file("main.tf", _FIREWALL_SOURCE)
        if matches_resource(match, resource)
    ]
    assert matched == ["google_compute_firewall.allow", "google_compute_firewall.nested"]


def test_skip_when_resource_contains_survives_the_yaml_export() -> None:
    pack = ruledef.load(_FIREWALL_PACK)
    match = ruledef.load(ruledef.toyaml.to_yaml(pack)).rules[0].match
    assert match is not None
    assert match.skip_when_resource_contains == ["deny"]
