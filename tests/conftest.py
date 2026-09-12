"""Shared pytest configuration. --update-docs regenerates docs/rules.md from the built-in pack
without changing frozen Go fixtures.
"""

from __future__ import annotations

from pytest import Parser


def pytest_addoption(parser: Parser) -> None:
    parser.addoption(
        "--update-docs",
        action="store_true",
        default=False,
        help="rewrite docs/rules.md from the rule pack instead of comparing it",
    )
