"""Sérialise un pack en YAML, dans le format que `load` relit.

Sert un seul usage : `--print-rules` donne au lecteur le point de départ d'un
pack personnalisé. Ce point de départ doit être du YAML et pas du Python,
parce que c'est le seul format qu'un pack fourni par un client peut prendre —
`load` n'importe jamais de code.

Ce que la sortie n'a pas, et qui existait quand ce pack était lui-même un
fichier YAML : les ancres et les alias. Ils sont développés à l'analyse, donc
ce qui sort ici est la forme complète, chaque règle portant ses conditions en
toutes lettres. C'est plus long et c'est mieux comme point de départ — il n'y
a rien à déréférencer pour comprendre ce qu'une règle regarde.
"""

from __future__ import annotations

from typing import Any

import yaml

from .ruledef import CategoryDoc, Fix, Match, Pack, Rule

# L'ordre des clés en sortie. Les dictionnaires Python gardent leur ordre
# d'insertion, donc dresser la liste ici suffit à rendre la sortie stable d'une
# exécution à l'autre — et stable veut dire diffable entre deux versions.
_RULE_KEYS = (
    "id",
    "category",
    "severity",
    "engine",
    "group",
    "label",
    "disabled",
    "params",
    "match",
    "message",
    "suggestion",
    "fix",
)
_MATCH_KEYS = (
    "scope",
    "kinds",
    "resource_types",
    "block_types",
    "attr_names",
    "attr_name_matches",
    "attr_name_not_matches",
    "attr_name_contains",
    "literal",
    "min_length",
    "value_matches",
    "value_contains",
    "value_not_one_of",
    "name_matches",
    "confirm",
    "predicate",
)
_FIX_KEYS = ("action", "lines", "note", "skip_when_resolved")


class _Dumper(yaml.SafeDumper):
    """Force le style bloc sur les chaînes multi-lignes.

    Sans cela, PyYAML rend un message de plusieurs lignes en une seule ligne
    pleine de `\\n` échappés, ce qui est illisible précisément là où le texte
    est destiné à être lu et modifié.
    """


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _represent_str)


def _fields(obj: Match | Fix | Rule, keys: tuple[str, ...], default: Any) -> dict[str, Any]:
    """Ne garde que ce qui diffère du défaut.

    Émettre les champs vides doublerait la taille de la sortie et suggérerait
    qu'ils comptent : un `attr_name_contains: ''` recopié dans un pack
    personnalisé ressemble à une condition, alors qu'il n'en est pas une.
    """
    out: dict[str, Any] = {}
    for key in keys:
        value = getattr(obj, key)
        if value == getattr(default, key):
            continue
        out[key] = value
    return out


def _rule_to_dict(rule: Rule) -> dict[str, Any]:
    out = _fields(rule, _RULE_KEYS, Rule())
    if rule.match is not None:
        out["match"] = _fields(rule.match, _MATCH_KEYS, Match())
    if rule.fix is not None:
        out["fix"] = _fields(rule.fix, _FIX_KEYS, Fix())
    return {key: out[key] for key in _RULE_KEYS if key in out}


def _doc_to_dict(doc: CategoryDoc) -> dict[str, Any]:
    return {
        key: getattr(doc, key)
        for key in ("category", "title", "full_description", "markdown")
        if getattr(doc, key)
    }


def to_yaml(pack: Pack) -> bytes:
    """Rend le pack en YAML. Ce que `load` relit donne le même pack."""
    document: dict[str, Any] = {"version": pack.version}
    if pack.extends:
        document["extends"] = pack.extends
    document["rules"] = [_rule_to_dict(r) for r in pack.rules]
    if pack.docs:
        document["docs"] = [_doc_to_dict(d) for d in pack.docs]

    text = yaml.dump(
        document,
        Dumper=_Dumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    )
    return text.encode("utf-8")
