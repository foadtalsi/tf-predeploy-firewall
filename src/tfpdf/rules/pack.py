"""Le câblage entre le pack de règles et ce moteur.

Port de internal/rules/pack.go.

Transforme des déclarations en règles exécutables, et répond aux questions que
les autres modules posent sur les motifs du pack sans en garder une seconde
copie en Python.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from .. import ruledef
from ..ruledef import Pack, RulePackError
from ..ruledef import Rule as RuleSpec
from .base import Options, Rule, RuleSet
from .declarative import DeclarativeRule
from .detectors import (
    ForceNewChangeRule,
    IAMWildcardRule,
    MissingLifecycleRule,
    StaticCostRule,
    UnknownAttributeRule,
    UnpinnedVersionRule,
)
from .predicates import CONFIRM_PREDICATES, VALUE_PREDICATES, known_predicates

#: The rules this build reaches for by name. The .tfvars and terragrunt
#: scanners judge a value by exactly the same standard as a resource attribute,
#: and they do it by reading these definitions rather than by re-declaring the
#: patterns — two divergent definitions of "looks like a secret" would be a bug
#: waiting to happen.
REQUIRED_IDS = ("hardcoded_credential", "open_cidr")

CREDENTIAL_VALUE_GROUP = "credential_value"


class BrokenBuildError(RuntimeError):
    """Le pack intégré est inutilisable.

    Non survivable, et délibérément attrapée nulle part : tout chemin qui
    « continuerait sans lui » se terminerait par un scanner rapportant une
    exécution propre sur du Terraform qu'il n'a jamais inspecté. Un scanner qui
    ne trouve rien parce qu'il est cassé ne doit pas être confondu avec un
    scanner qui n'a rien trouvé parce qu'il n'y avait rien.
    """


@dataclass(slots=True, frozen=True)
class _PackRefs:
    pack: Pack
    credential_name: re.Pattern[str] | None
    credential_values: tuple[RuleSpec, ...]
    open_cidr: str


def builtin_pack_source() -> bytes:
    """Le YAML du pack de règles intégré, tel que livré."""
    return ruledef.builtin_yaml()


@lru_cache(maxsize=1)
def _load_builtin() -> _PackRefs:
    try:
        pack = ruledef.builtin()
        pack.require_ids(*REQUIRED_IDS)
        _validate_predicates(pack)
        if not pack.group(CREDENTIAL_VALUE_GROUP):
            raise RulePackError(f"rule pack defines no {CREDENTIAL_VALUE_GROUP!r} group")
    except (RulePackError, OSError) as exc:
        raise BrokenBuildError(f"tf-predeploy-firewall: {exc}") from exc

    credential = pack.by_id("hardcoded_credential")
    open_cidr = pack.by_id("open_cidr")
    assert credential is not None and credential.match is not None  # require_ids
    assert open_cidr is not None and open_cidr.match is not None

    values = tuple(
        r for r in pack.group(CREDENTIAL_VALUE_GROUP) if r.match and r.match.value_re is not None
    )

    return _PackRefs(
        pack=pack,
        credential_name=credential.match.attr_name_re,
        credential_values=values,
        open_cidr=open_cidr.match.value_contains,
    )


def builtin_pack() -> Pack:
    """Le pack de règles livré avec cette version."""
    return _load_builtin().pack


def _validate_predicates(p: Pack) -> None:
    """Rejette un pack nommant un prédicat que cette version n'implémente pas.

    Sauter le nom inconnu à la place laisserait la règle chargée, ne
    correspondant à rien, et rapportant un succès — exactement le mode de
    défaillance que tout ce format existe pour éviter.
    """
    confirm, value = known_predicates()
    for r in p.rules:
        if r.match is None:
            continue
        if r.match.confirm and r.match.confirm not in CONFIRM_PREDICATES:
            raise RulePackError(
                f"rule {r.id!r} names unknown confirm predicate {r.match.confirm!r} "
                f"(available: {', '.join(confirm)})"
            )
        if r.match.predicate and r.match.predicate not in VALUE_PREDICATES:
            raise RulePackError(
                f"rule {r.id!r} names unknown predicate {r.match.predicate!r} "
                f"(available: {', '.join(value)})"
            )


@dataclass(slots=True, frozen=True)
class _BuiltRule:
    """Une règle exécutable à côté de la déclaration dont elle vient, pour que
    les appelants puissent filtrer sur ce que le pack en dit sans inspecter des
    types."""

    rule: Rule
    #: The definition, or a group's first member.
    spec: RuleSpec


def _build_rules(p: Pack, opts: Options) -> list[_BuiltRule]:
    out: list[_BuiltRule] = []
    emitted: set[str] = set()

    for spec in p.rules:
        if spec.group:
            if spec.group in emitted:
                continue  # the whole group was emitted with its first member
            emitted.add(spec.group)
            group = p.group(spec.group)
            first = group[0]
            assert first.match is not None  # index() rejects a non-declarative member
            out.append(
                _BuiltRule(rule=DeclarativeRule(specs=group, scope=first.match.scope), spec=first)
            )
        elif spec.match is not None:
            out.append(
                _BuiltRule(rule=DeclarativeRule(specs=[spec], scope=spec.match.scope), spec=spec)
            )
        else:
            rule = _compiled_engine(spec, opts)
            if rule is not None:
                out.append(_BuiltRule(rule=rule, spec=spec))
    return out


def from_pack(p: Pack, opts: Options) -> list[Rule]:
    """Construit le jeu de règles exécutables d'un pack.

    Les règles déclaratives sont regroupées d'abord, pour que des alternatives
    ordonnées soient évaluées par une seule règle et que « la première qui
    correspond gagne » veuille dire quelque chose ; les règles moteur se
    résolvent en leur implémentation compilée. L'ordre suit le pack, ce qui est
    pourquoi le pack se lit de haut en bas dans l'ordre où un lecteur voudrait
    qu'on lui explique les règles.
    """
    return [b.rule for b in _build_rules(p, opts)]


def default_rules(opts: Options) -> list[Rule]:
    """Le jeu de règles intégré, dans l'ordre du pack.

    Les règles elles-mêmes sont des déclarations dans `ruledef/rules.py`, pas
    du code : ce que chacune cherche, comment sa découverte est formulée et ce
    que dit la documentation sont tous des données. Ceci ne fait que résoudre
    ces déclarations en forme exécutable.
    """
    return from_pack(builtin_pack(), opts)


def rules_for_category(p: Pack, category: str, opts: Options) -> Rule:
    """Tout ce qu'un pack définit pour une catégorie, en une seule règle.

    Sert à exécuter ou à raisonner sur une catégorie isolée : rapporter ce
    qu'elle trouverait, et tester ses détecteurs ensemble plutôt qu'une
    déclaration à la fois.

    Construite par le même chemin qu'un scan complet, pour que le regroupement —
    et avec lui la règle du premier qui correspond — se comporte à l'identique.
    Une catégorie évaluée par son propre chemin de code ferait de chaque test
    la vérification d'autre chose.
    """
    out = RuleSet(b.rule for b in _build_rules(p, opts) if b.spec.category == category)
    if not out:
        raise RulePackError(f"pack defines no runnable rules for category {category!r}")
    return out


def _compiled_engine(spec: RuleSpec, opts: Options) -> Rule | None:
    """Résout une règle `engine:` en son implémentation.

    None pour les moteurs qui ne font pas partie d'un scan statique : les règles
    fondées sur le plan tournent depuis leur propre point d'entrée, contre le
    JSON de Terraform plutôt que contre de la source, et sont déclarées dans le
    pack pour être documentées et configurables au même endroit que tout le
    reste.
    """
    engine = spec.engine
    if engine == "unknown_attribute":
        return UnknownAttributeRule()
    if engine == "force_new_change":
        return ForceNewChangeRule()
    if engine == "missing_lifecycle":
        return MissingLifecycleRule()
    if engine == "unpinned_version":
        return UnpinnedVersionRule()
    if engine == "iam_wildcard":
        return IAMWildcardRule()

    if engine == "static_cost":
        threshold = opts.cost_threshold_usd
        if threshold == 0:
            raw = spec.params.get("threshold_usd")
            if raw is not None:
                try:
                    threshold = float(raw)
                except ValueError as exc:
                    raise RulePackError(
                        f"rule {spec.id!r}: threshold_usd {raw!r} is not a number: {exc}"
                    ) from exc
        if threshold <= 0:
            return None
        return StaticCostRule(threshold_usd=threshold)

    if engine in (
        "confirmed_replace",
        "unexpected_drift",
        "large_blast_radius",
        "plan_cost_impact",
    ):
        return None

    raise RulePackError(f"rule {spec.id!r} names unknown engine {spec.engine!r}")


# --- the shared value vocabulary -----------------------------------------


def is_credential_attr_name(name: str) -> bool:
    """Dit si `name` ressemble à un attribut porteur d'identifiant, au seul vu
    de son nom (password, api_key, token, …).

    Exporté aux côtés de `match_credential_value_pattern`, `is_open_cidr` et
    `looks_like_secret` pour que les scanners hors ressources (`tfpdf.tfvars`,
    `tfpdf.terragrunt`) appliquent le même standard aux `inputs` de
    terragrunt.hcl et aux fichiers .tfvars, dont aucun ne passe par une
    `parser.Resource`. Les quatre lisent le pack intégré, donc il existe
    exactement une définition de chacun.
    """
    re_ = _load_builtin().credential_name
    return re_ is not None and re_.search(name) is not None


def match_credential_value_pattern(value: str) -> tuple[str, bool]:
    """Confronte `value` aux formats d'identifiants bien connus que le pack
    déclare, quel que soit l'attribut d'où elle vient.

    Rend l'étiquette lisible du motif trouvé et True, ou ("", False).
    """
    from .entropy import byte_len

    for spec in _load_builtin().credential_values:
        m = spec.match
        assert m is not None and m.value_re is not None  # filtered at load
        if m.min_length > 0 and byte_len(value) < m.min_length:
            continue
        found = m.value_re.search(value)
        if found is None or not found.group(0):
            continue
        if m.confirm and not CONFIRM_PREDICATES[m.confirm](found.group(0)):
            continue
        return spec.label, True
    return "", False


def is_open_cidr(value: str) -> bool:
    """Dit si `value` est le bloc CIDR grand ouvert que cherche la règle
    open_cidr du pack."""
    return value == _load_builtin().open_cidr
