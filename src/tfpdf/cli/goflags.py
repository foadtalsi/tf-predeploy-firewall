"""Réécrit argv pour qu'argparse accepte la ligne de commande que le paquet
`flag` de Go acceptait.

Deux divergences, non cosmétiques parce que les invocations existent déjà dans
la nature :

* **Options longues à un seul tiret.** `flag` traite `-base-ref` et `--base-ref`
  comme le même drapeau, et chaque README, ligne `entry:` de pre-commit et
  workflow écrit à la main peut utiliser l'une ou l'autre. C'est ce que ce
  module corrige.
* **`-bool=false`.** `flag` accepte une valeur accolée à un booléen, et
  l'`action.yml` publié passe `--full-repo-scan=${{ inputs.full-repo-scan }}`.
  Traité là où les drapeaux sont déclarés, pas ici.
"""

from __future__ import annotations

import re

#: A single-dash long option, with or without an attached value. Deliberately
#: requires a letter after the dash, so a bare "-", a "--" separator and a
#: negative number are all left alone.
_SINGLE_DASH_LONG = re.compile(r"^-([a-zA-Z][a-zA-Z0-9-]*)(=.*)?$", re.DOTALL)


def normalize_argv(argv: list[str]) -> list[str]:
    """Réécrit les options longues à tiret simple, à la Go, sous la forme à
    double tiret.

    S'arrête à un séparateur `--`, comme le font les deux analyseurs : tout ce
    qui suit est un opérande et non un drapeau, et en réécrire un changerait son
    sens.
    """
    normalized_arguments: list[str] = []
    for argument_index, argument in enumerate(argv):
        if argument == "--":
            normalized_arguments.extend(argv[argument_index:])
            break
        match = _SINGLE_DASH_LONG.match(argument)
        # A one-letter option is left as-is: this CLI has none, and rewriting
        # "-h" would break the one short flag argparse provides itself.
        if match is not None and len(match.group(1)) > 1:
            normalized_arguments.append("-" + argument)
        else:
            normalized_arguments.append(argument)
    return normalized_arguments
