"""Scanner configuration. Environment variables override the local file."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .. import customrules, ignore
from ..report.finding import Category, Severity


class ConfigError(ValueError):
    """A configuration file that could not be read or validated. Stop rather than scan with
    unintended settings.
    """


@dataclass(slots=True)
class IgnorePathConfig:
    """A path exclusion; an empty category list excludes all categories."""

    path: str = ""
    categories: list[Category | str] = field(default_factory=list)


@dataclass(slots=True)
class Config:
    # Free text for legacy threshold handling; see Severity.at_least.
    block_threshold: Severity | str = Severity.HIGH
    ignore_rules: list[Category | str] = field(default_factory=list)
    plan_blast_radius_threshold: int = 10

    # Exclude paths, optionally by category. Supports ** across directory levels.
    ignore_paths: list[IgnorePathConfig] = field(default_factory=list)

    # Request reviewers for critical findings. Enforcing approval still requires repository
    # branch protection.
    require_second_reviewer_users: list[str] = field(default_factory=list)
    require_second_reviewer_teams: list[str] = field(default_factory=list)

    # Post exact fixes as inline suggestions by default; disable to keep only the summary
    # report.
    suggestions: bool = True

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
    """Load YAML and environment overrides, keeping defaults when the file is absent."""
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
    """Override only fields explicitly present in the YAML document."""
    if "block_threshold" in document:
        config.block_threshold = str(document["block_threshold"] or "")
    if "ignore_rules" in document:
        config.ignore_rules = _as_str_list(document["ignore_rules"])
    if document.get("plan_blast_radius_threshold") is not None:
        config.plan_blast_radius_threshold = int(document["plan_blast_radius_threshold"])
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


def parse_go_bool(v: str, what: str) -> bool:
    """Parse true/false, 1/0, t/f, and their supported case variants."""
    if v in ("1", "t", "T", "true", "TRUE", "True"):
        return True
    if v in ("0", "f", "F", "false", "FALSE", "False"):
        return False
    raise ConfigError(f"{what} must be true or false, got {v!r}")


def warn_unknown_threshold(threshold: Severity | str) -> None:
    """Warn that an unknown threshold retains legacy behavior: every severity exceeds it."""
    if str(threshold) in tuple(Severity):
        return
    print(
        f"tf-predeploy-firewall: block threshold {str(threshold)!r} is not one of "
        "low/medium/high/critical — every finding will be treated as reaching it",
        file=sys.stderr,
    )


def load_custom_rules(path: str) -> customrules.Config | None:
    """Read custom_rules from the scanner's YAML configuration file."""
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
