"""Le pack de règles livré avec cette build.

Il vit dans `ruledef` plutôt que dans `rules` pour qu'un module qui n'a besoin
que de *lire* le pack — `report`, quand il rend la documentation d'une catégorie
— n'ait pas à importer le moteur qui l'évalue. En Python ce découpage est
porteur plutôt qu'esthétique : `rules` importe `report` pour ses types de
découvertes, donc un `report` qui atteindrait `rules` en retour serait un cycle.
"""

from __future__ import annotations

from functools import lru_cache

from . import rules as _rules
from .ruledef import Pack, RulePackError
from .toyaml import to_yaml


@lru_cache(maxsize=1)
def builtin() -> Pack:
    """Le pack de règles compilé dans le binaire.

    Construit une fois et partagé : le pack est immuable après validation, et
    chaque fichier scanné recompilerait sinon les mêmes expressions régulières.
    """
    try:
        return _rules.build()
    except RulePackError as exc:
        raise RulePackError(f"the embedded rule pack is invalid: {exc}") from exc


def builtin_yaml() -> bytes:
    """Le pack embarqué rendu en YAML, pour l'outillage qui veut l'afficher ou
    le copier — `--print-rules`, et quiconque démarre son propre pack depuis
    celui intégré plutôt que depuis un fichier vide.

    Sérialisé à la demande, parce que le pack est du Python depuis que les
    règles y sont écrites. Un client ne peut pas fournir du Python en retour :
    ce qu'il édite et renvoie est du YAML, relu par `load`.
    """
    return to_yaml(builtin())
