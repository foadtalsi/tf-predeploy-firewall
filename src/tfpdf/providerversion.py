"""Ce que le dépôt épingle, contre ce que le schéma embarqué décrit.

Le scanner juge « cet argument existe-t-il ? » contre **une** version de
fournisseur : celle du pack qu'il porte. La page d'accueil, elle, promet
« whether an argument exists in the provider you're actually pinned to ».

Les deux se contredisaient, et ça se voyait sur du vrai code. Un dépôt qui
déclare `aws = "~> 3.0"` écrit légitimement `vpc = true` sur un `aws_eip` :
l'attribut n'a disparu qu'en 6.x. Le scanner le signalait quand même, en
« attribut inconnu », severity high, avec un lien vers la documentation 6.59.0 —
c'est-à-dire une accusation confiante et fausse, sur exactement le point qui
distingue ce produit de `terraform validate`.

Ce module lit la contrainte et répond à une seule question : **le schéma que
nous portons est-il dans la fourchette que ce module a épinglée ?** Quand la
réponse est non, les découvertes tirées du schéma sont retirées pour ce
fournisseur. Se taire vaut mieux qu'avoir tort avec assurance — nous n'avons pas
le schéma de la version qu'ils utilisent, donc nous n'avons rien à en dire.

Ce qui n'est PAS retiré : tout ce qui juge une valeur écrite plutôt qu'un
schéma — credentials, entropie, CIDR ouverts, prevent_destroy, versions non
épinglées. Ces règles ne dépendent d'aucune version de fournisseur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Un opérateur suivi d'une version, tel qu'il s'écrit dans Terraform. Une
#: contrainte sans opérateur (`"3.1.0"`) vaut `=`, comme chez Terraform.
_TERM = re.compile(r"^\s*(>=|<=|!=|~>|>|<|=)?\s*v?([0-9]+(?:\.[0-9]+)*)\s*$")

#: `name = { … version = "…" … }` dans un bloc required_providers, et la forme
#: courte `name = "…"` que Terraform accepte encore.
_ENTRY_BLOCK = re.compile(r"([a-z][a-z0-9_-]*)\s*=\s*\{(.*?)\}", re.DOTALL)
_ENTRY_SHORT = re.compile(r'([a-z][a-z0-9_-]*)\s*=\s*"([^"]*)"')
_VERSION_IN_ENTRY = re.compile(r'version\s*=\s*"([^"]*)"')


def parse_version(text: str) -> tuple[int, ...]:
    """« 6.59.0 » vers (6, 59, 0). Les composants absents valent zéro à la
    comparaison, pas ici : `~>` a besoin de savoir combien on lui en a donné."""
    return tuple(int(part) for part in text.split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Compare deux versions en complétant la plus courte par des zéros, ce qui
    fait de « 3 » et « 3.0.0 » la même chose — comme chez Terraform."""
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


@dataclass(frozen=True, slots=True)
class Term:
    operator: str
    version: tuple[int, ...]

    def allows(self, candidate: tuple[int, ...]) -> bool:
        order = _compare(candidate, self.version)
        if self.operator == ">=":
            return order >= 0
        if self.operator == ">":
            return order > 0
        if self.operator == "<=":
            return order <= 0
        if self.operator == "<":
            return order < 0
        if self.operator == "!=":
            return order != 0
        if self.operator == "=":
            return order == 0
        if self.operator == "~>":
            # « autorise le composant le plus à droite à monter ». `~> 3.0` va
            # de 3.0 à 4.0 exclu ; `~> 3.0.1` s'arrête à 3.1.0. La borne haute
            # dépend donc du nombre de composants ÉCRITS, pas de leur valeur —
            # c'est la seule règle de Terraform qu'on ne peut pas deviner en
            # comparant des nombres.
            if order < 0:
                return False
            ceiling = self.version[:-1]
            if not ceiling:
                # `~> 3` n'a pas de composant à figer : tout 3.x et au-delà.
                return True
            bumped = (*ceiling[:-1], ceiling[-1] + 1)
            return _compare(candidate, bumped) < 0
        return True


def parse_constraint(text: str) -> list[Term]:
    """Les termes d'une contrainte Terraform, séparés par des virgules et tous
    exigés. Un terme incompréhensible est ignoré plutôt que devinné : la
    conséquence d'une contrainte mal lue serait de faire taire des découvertes
    justes."""
    terms: list[Term] = []
    for piece in text.split(","):
        found = _TERM.match(piece)
        if found is None:
            continue
        terms.append(Term(found.group(1) or "=", parse_version(found.group(2))))
    return terms


def allows(constraint: str, version: str) -> bool:
    """Vrai si `version` satisfait la contrainte. Une contrainte vide ou
    illisible autorise tout — c'est le cas d'un dépôt qui n'épingle rien, où le
    schéma le plus récent est précisément le bon pari."""
    terms = parse_constraint(constraint)
    if not terms:
        return True
    candidate = parse_version(version)
    return all(term.allows(candidate) for term in terms)


def constraints_in(source: bytes) -> dict[str, str]:
    """Les contraintes déclarées dans les blocs `required_providers` d'un
    fichier, par nom local de fournisseur.

    Lit le texte brut plutôt que l'arbre analysé : `terraform { … }` n'est pas
    une ressource, donc il ne passe pas par le modèle Resource, et c'est déjà
    ainsi que la règle des versions non épinglées le lit.
    """
    text = source.decode("utf-8", errors="replace")
    found: dict[str, str] = {}
    index = 0
    while True:
        start = text.find("required_providers", index)
        if start < 0:
            return found
        open_index = text.find("{", start)
        if open_index < 0:
            return found
        depth = 0
        end = open_index
        for position in range(open_index, len(text)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    end = position
                    break
        else:
            return found
        body = text[open_index + 1 : end]
        for match in _ENTRY_BLOCK.finditer(body):
            version = _VERSION_IN_ENTRY.search(match.group(2))
            if version is not None:
                found.setdefault(match.group(1), version.group(1))
        # La forme courte est cherchée sur ce dont les entrées à accolades ne
        # rendent pas compte, sans quoi `version = "…"` d'un bloc serait relu
        # comme une entrée nommée « version ».
        without_blocks = _ENTRY_BLOCK.sub("", body)
        for match in _ENTRY_SHORT.finditer(without_blocks):
            found.setdefault(match.group(1), match.group(2))
        index = end + 1


def provider_of(resource_type: str) -> str:
    """Le fournisseur d'un type de ressource : ce qui précède le premier « _ ».

    C'est la convention que Terraform impose aux noms de types et celle sur
    laquelle les packs sont déjà découpés. `aws_eip` → `aws`.
    """
    prefix, separator, _ = resource_type.partition("_")
    return prefix if separator else ""
