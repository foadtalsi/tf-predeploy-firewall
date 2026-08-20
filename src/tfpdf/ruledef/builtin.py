"""Le pack de règles livré avec cette build.

Port de internal/ruledef/builtin.go.

Il vit dans `ruledef` plutôt que dans `rules` pour qu'un module qui n'a besoin
que de *lire* le pack — `report`, quand il rend la documentation d'une catégorie
— n'ait pas à importer le moteur qui l'évalue. Go l'organise pareil, et en
Python ce découpage est porteur plutôt qu'esthétique : `rules` importe `report`
pour ses types de découvertes, donc un `report` qui atteindrait `rules` en
retour serait un cycle.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from .ruledef import Pack, RulePackError, load


def builtin_yaml() -> bytes:
    """Le pack embarqué brut, pour l'outillage qui veut l'afficher ou le copier
    — `--rules-dry-run`, et quiconque démarre son propre pack depuis celui
    intégré plutôt que depuis un fichier vide."""
    return resources.files(__package__).joinpath("rules.yaml").read_bytes()


@lru_cache(maxsize=1)
def builtin() -> Pack:
    """Le pack de règles compilé dans le binaire.

    Analysé une fois et partagé : le pack est immuable après chargement, et
    chaque fichier scanné recompilerait sinon les mêmes expressions régulières.
    """
    try:
        return load(builtin_yaml())
    except RulePackError as exc:
        raise RulePackError(f"the embedded rule pack is invalid: {exc}") from exc
