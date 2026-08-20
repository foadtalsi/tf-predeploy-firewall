"""Configuration pytest partagée.

`--update-docs` est le port du `go test ./internal/report -run RuleDocs -update`
de Go : docs/rules.md est généré depuis le pack de règles, et chaque `helpUri`
SARIF pointe dedans — le fichier doit donc être régénérable par quiconque édite
le pack, plutôt que tenu à jour à la main.
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
