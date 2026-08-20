"""La configuration YAML du scanner, et les surcharges d'environnement
par-dessus.

Porte la moitié « chargement de configuration » de
cmd/tf-predeploy-firewall/main.go.

Priorité, du plus faible au plus fort : config.yml du dépôt < politique de
l'organisation < variable d'environnement. Un opérateur peut donc toujours
forcer un réglage localement par variable d'environnement, même quand une
politique d'organisation existe — une échappatoire délibérée, pas un oubli.
"""

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
    """Une entrée d'`ignore_paths` :

    ```yaml
    ignore_paths:
      - path: "legacy/**/*.tf"
        categories: ["missing_lifecycle"]   # optionnel ; omis = toutes
      - path: "sandbox/**"
    ```
    """

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
    """Lit le fichier de configuration, puis applique les surcharges
    d'environnement.

    Un fichier absent veut simplement dire « utilise les valeurs par défaut » :
    les surcharges d'environnement s'appliquent de toute façon, ce qui est
    pourquoi cette fonction ne sort pas tôt dans ce cas.
    """
    cfg = Config()

    data: bytes | None
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        data = None
    except OSError as exc:
        raise ConfigError(f"reading config {path}: {exc}") from exc

    if data is not None:
        try:
            doc = yaml.safe_load(data)
        except yaml.YAMLError as exc:
            raise ConfigError(f"parsing config {path}: {exc}") from exc
        if doc is not None and not isinstance(doc, dict):
            raise ConfigError(f"parsing config {path}: top level is not a mapping")
        if isinstance(doc, dict):
            _apply_yaml(cfg, doc)
        if not cfg.block_threshold:
            cfg.block_threshold = Severity.HIGH

    _apply_env(cfg, path)
    return cfg


def _apply_yaml(cfg: Config, doc: dict[str, Any]) -> None:
    """N'écrase que les champs réellement présents dans le document.

    Go obtient cela gratuitement en désérialisant dans une structure
    pré-remplie ; en Python il faut l'écrire, sans quoi
    `plan_blast_radius_threshold` perdrait sa valeur par défaut de 10 au profit
    d'un zéro dans toute configuration qui n'en parle pas.
    """
    if "block_threshold" in doc:
        cfg.block_threshold = str(doc["block_threshold"] or "")
    if "ignore_rules" in doc:
        cfg.ignore_rules = list(_as_str_list(doc["ignore_rules"]))
    if doc.get("plan_blast_radius_threshold") is not None:
        cfg.plan_blast_radius_threshold = int(doc["plan_blast_radius_threshold"])
    if doc.get("cost_impact_threshold_usd") is not None:
        cfg.cost_impact_threshold_usd = float(doc["cost_impact_threshold_usd"])
    if doc.get("suggestions") is not None:
        cfg.suggestions = bool(doc["suggestions"])
    if "require_second_reviewer_users" in doc:
        cfg.require_second_reviewer_users = _as_str_list(doc["require_second_reviewer_users"])
    if "require_second_reviewer_teams" in doc:
        cfg.require_second_reviewer_teams = _as_str_list(doc["require_second_reviewer_teams"])
    if "ignore_paths" in doc:
        entries: list[IgnorePathConfig] = []
        for raw in doc["ignore_paths"] or []:
            if not isinstance(raw, dict):
                continue
            entries.append(
                IgnorePathConfig(
                    path=str(raw.get("path", "")),
                    categories=list(_as_str_list(raw.get("categories"))),
                )
            )
        cfg.ignore_paths = entries


def _apply_env(cfg: Config, path: str) -> None:
    import os

    if env := os.environ.get("SCANNER_BLOCK_THRESHOLD"):
        cfg.block_threshold = env
    if env := os.environ.get("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD"):
        try:
            cfg.plan_blast_radius_threshold = int(env)
        except ValueError as exc:
            raise ConfigError(
                f"SCANNER_PLAN_BLAST_RADIUS_THRESHOLD must be an integer, got {env!r}: {exc}"
            ) from exc
    if env := os.environ.get("SCANNER_SUGGESTIONS"):
        cfg.suggestions = parse_go_bool(env, "SCANNER_SUGGESTIONS")
    if env := os.environ.get("SCANNER_COST_IMPACT_THRESHOLD_USD"):
        try:
            cfg.cost_impact_threshold_usd = float(env)
        except ValueError as exc:
            raise ConfigError(
                f"SCANNER_COST_IMPACT_THRESHOLD_USD must be a number, got {env!r}: {exc}"
            ) from exc
    del path


def parse_go_bool(v: str, what: str) -> bool:
    """Accepte ce qu'accepte le `strconv.ParseBool` de Go, et rien d'autre.

    `SCANNER_SUGGESTIONS` vient d'une entrée de workflow, où « 1 », « T » et
    « TRUE » sont autant de choses que les gens écrivent. Le `bool(str)` de
    Python accepterait « false » comme vrai, ce qui est la seule réponse qu'il
    ne faut surtout pas deviner.
    """
    if v in ("1", "t", "T", "true", "TRUE", "True"):
        return True
    if v in ("0", "f", "F", "false", "FALSE", "False"):
        return False
    raise ConfigError(f"{what} must be true or false, got {v!r}")


def warn_unknown_threshold(threshold: Severity | str) -> None:
    """Le dit quand le seuil configuré n'est pas une sévérité que cette version
    connaît.

    Absent de l'original Go, et **seul ajout au comportement du CLI** : Go
    classe un seuil non reconnu au rang 0, si bien que `hgih` transforme
    silencieusement le scanner en « bloque sur la moindre découverte ». `HIGH`
    est attrapé aussi, les valeurs étant en minuscules : la mise en majuscules
    évidente fait partie des fautes que ceci trouve.

    La comparaison est laissée exactement comme Go la fait — lever une
    exception transformerait la même faute de frappe en trace d'appel. Seul le
    silence est corrigé.
    """
    if str(threshold) in tuple(Severity):
        return
    print(
        f"tf-predeploy-firewall: block threshold {str(threshold)!r} is not one of "
        "low/medium/high/critical — every finding will be treated as reaching it",
        file=sys.stderr,
    )


def load_custom_rules(path: str) -> customrules.Config | None:
    """Lit la section `custom_rules:` du même fichier de configuration YAML.

    Rend None quand le fichier est absent ou ne définit aucune règle
    personnalisée — c'est une fonctionnalité Growth et plus, que la plupart des
    dépôts n'utiliseront pas, donc son absence ne doit jamais être une erreur.
    """
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"reading config {path}: {exc}") from exc

    try:
        cfg = customrules.load(data)
    except customrules.CustomRuleError as exc:
        raise ConfigError(f"loading custom rules from {path}: {exc}") from exc
    return cfg if cfg.rules else None
