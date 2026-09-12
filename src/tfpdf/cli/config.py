"""Configuration du scanner. Priorité : fichier local < politique distante < environnement."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .. import customrules, ignore
from ..report.finding import Category, Severity


class ConfigError(ValueError):
    """Le fichier de configuration n'a pas pu être lu, analysé ou compris.

    Fatale : un scanner qui tourne sur une configuration mal lue applique
    quelque chose que personne n'a demandé.
    """


@dataclass(slots=True)
class IgnorePathConfig:
    """Exclusion par motif de chemin ; une liste de catégories vide les couvre toutes."""

    path: str = ""
    categories: list[Category | str] = field(default_factory=list)


@dataclass(slots=True)
class Config:
    #: Du texte libre plutôt qu'une `Severity` : voir `Severity.at_least`.
    block_threshold: Severity | str = Severity.HIGH
    ignore_rules: list[Category | str] = field(default_factory=list)
    plan_blast_radius_threshold: int = 10
    cost_impact_threshold_usd: float = 0.0

    #: Supprime les découvertes sous tout un motif de fichier ou de répertoire
    #: (`**` accepté), éventuellement restreint à certaines catégories — le
    #: pendant à grande échelle du commentaire `# tf-firewall-ignore:` (une
    #: ligne) et d'`ignore_rules` (une catégorie partout) : « ne scanne pas
    #: legacy/** du tout », sans parsemer chaque fichier de cette arborescence.
    ignore_paths: list[IgnorePathConfig] = field(default_factory=list)

    #: Identifiants d'utilisateurs ou de groupes demandés comme relecteurs dès
    #: qu'une découverte de sévérité critique est présente. Ceci ne fait que
    #: *demander* la relecture : BLOQUER réellement la fusion dessus exige que
    #: la protection de branche du dépôt ait les relecteurs obligatoires
    #: activés — un réglage ponctuel que cet outil n'a aucun accès API pour
    #: configurer lui-même.
    require_second_reviewer_users: list[str] = field(default_factory=list)
    require_second_reviewer_teams: list[str] = field(default_factory=list)

    #: Poste en commentaire de revue en ligne chaque correctif que le scanner
    #: peut exprimer comme un remplacement exact de lignes, pour qu'il puisse
    #: être appliqué par le bouton en un clic de la forge. Vrai par défaut ;
    #: mettre faux pour les dépôts qui préfèrent garder tout le rapport dans un
    #: seul commentaire.
    suggestions: bool = True

    #: Jamais lu depuis le fichier YAML local — uniquement rempli par
    #: `apply_org_policy` à partir de la politique gérée centralement par le
    #: plan de contrôle. Quand il est posé, il remplace entièrement les
    #: custom_rules de la configuration locale, selon le même précédent « la
    #: politique centrale l'emporte » qu'`ignore_rules`.
    custom_rules_yaml_override: str = ""

    def ignore_path_rules(self) -> list[ignore.PathRule]:
        return [
            ignore.PathRule(pattern=p.path, categories=list(p.categories))
            for p in self.ignore_paths
        ]


def _as_str_list(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x) for x in v]


def load_config(path: str) -> Config:
    """Charge le YAML et les surcharges d'environnement. Un fichier absent conserve les défauts."""
    config = Config()

    data: bytes | None
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        data = None
    except OSError as exc:
        raise ConfigError(f"reading config {path}: {exc}") from exc

    if data is not None:
        try:
            document = yaml.safe_load(data)
        except yaml.YAMLError as exc:
            raise ConfigError(f"parsing config {path}: {exc}") from exc
        if document is not None and not isinstance(document, dict):
            raise ConfigError(f"parsing config {path}: top level is not a mapping")
        if isinstance(document, dict):
            _apply_yaml(config, document)
        if not config.block_threshold:
            config.block_threshold = Severity.HIGH

    _apply_env(config)
    return config


def _apply_yaml(config: Config, document: dict[str, Any]) -> None:
    """N'écrase que les champs réellement présents dans le document."""
    if "block_threshold" in document:
        config.block_threshold = str(document["block_threshold"] or "")
    if "ignore_rules" in document:
        config.ignore_rules = _as_str_list(document["ignore_rules"])
    if document.get("plan_blast_radius_threshold") is not None:
        config.plan_blast_radius_threshold = int(document["plan_blast_radius_threshold"])
    if document.get("cost_impact_threshold_usd") is not None:
        config.cost_impact_threshold_usd = float(document["cost_impact_threshold_usd"])
    if document.get("suggestions") is not None:
        config.suggestions = bool(document["suggestions"])
    if "require_second_reviewer_users" in document:
        config.require_second_reviewer_users = _as_str_list(
            document["require_second_reviewer_users"]
        )
    if "require_second_reviewer_teams" in document:
        config.require_second_reviewer_teams = _as_str_list(
            document["require_second_reviewer_teams"]
        )
    if "ignore_paths" in document:
        entries: list[IgnorePathConfig] = []
        for raw in document["ignore_paths"] or []:
            if not isinstance(raw, dict):
                continue
            entries.append(
                IgnorePathConfig(
                    path=str(raw.get("path", "")),
                    categories=_as_str_list(raw.get("categories")),
                )
            )
        config.ignore_paths = entries


def _apply_env(config: Config) -> None:
    import os

    if env := os.environ.get("SCANNER_BLOCK_THRESHOLD"):
        config.block_threshold = env
    if env := os.environ.get("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD"):
        try:
            config.plan_blast_radius_threshold = int(env)
        except ValueError as exc:
            raise ConfigError(
                f"SCANNER_PLAN_BLAST_RADIUS_THRESHOLD must be an integer, got {env!r}: {exc}"
            ) from exc
    if env := os.environ.get("SCANNER_SUGGESTIONS"):
        config.suggestions = parse_go_bool(env, "SCANNER_SUGGESTIONS")
    if env := os.environ.get("SCANNER_COST_IMPACT_THRESHOLD_USD"):
        try:
            config.cost_impact_threshold_usd = float(env)
        except ValueError as exc:
            raise ConfigError(
                f"SCANNER_COST_IMPACT_THRESHOLD_USD must be a number, got {env!r}: {exc}"
            ) from exc


def parse_go_bool(v: str, what: str) -> bool:
    """Accepte les booléens true/false, 1/0, t/f et leurs variantes de casse prises en charge."""
    if v in ("1", "t", "T", "true", "TRUE", "True"):
        return True
    if v in ("0", "f", "F", "false", "FALSE", "False"):
        return False
    raise ConfigError(f"{what} must be true or false, got {v!r}")


def warn_unknown_threshold(threshold: Severity | str) -> None:
    """Avertit qu'un seuil inconnu conserve le comportement historique : toute sévérité le
    franchit."""
    if str(threshold) in tuple(Severity):
        return
    print(
        f"tf-predeploy-firewall: block threshold {str(threshold)!r} is not one of "
        "low/medium/high/critical — every finding will be treated as reaching it",
        file=sys.stderr,
    )


def load_custom_rules(path: str) -> customrules.Config | None:
    """Lit la section `custom_rules:` du même fichier de configuration YAML."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"reading config {path}: {exc}") from exc

    try:
        config = customrules.load(data)
    except customrules.CustomRuleError as exc:
        raise ConfigError(f"loading custom rules from {path}: {exc}") from exc
    return config if config.rules else None
