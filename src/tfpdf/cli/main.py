"""Le CLI de TF Pre-Deploy Firewall.

Port de cmd/tf-predeploy-firewall/main.go.

Scanne les fichiers .tf modifiés entre deux références git, rapporte les
découvertes de risque, et éventuellement poste ou met à jour un commentaire de
PR et conditionne le code de sortie à un seuil de sévérité.

Codes de sortie, inchangés depuis la version Go parce que des CI en dépendent :

    0  exécuté, rien au niveau du seuil de blocage ni au-dessus
    1  bloqué — une découverte a atteint le seuil
    2  le scan n'a pas pu tourner (mauvais drapeaux, config illisible, échec git)
    3  le quota du plan de l'organisation est épuisé
"""

from __future__ import annotations

import sys

from .. import (
    diff,
    report,
    ruledef,
)
from .arguments import _env_or as _env_or
from .arguments import build_parser as build_parser
from .config import ConfigError, load_config, warn_unknown_threshold
from .dryrun import run_rules_dry_run
from .forges import (
    repo_full_name,
)
from .goflags import normalize_argv
from .orgpolicy import apply_org_policy
from .pipeline import _die, execute_scan
from .pipeline import blocked_by as blocked_by
from .pipeline import load_knowledge_base as load_knowledge_base
from .pipeline import load_ruleset as load_ruleset

#: "dev" means a from-source build, matching the Go binary's unstamped default.
try:  # pragma: no cover - depends on how the package was installed
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        VERSION = _pkg_version("tf-predeploy-firewall")
    except PackageNotFoundError:
        VERSION = "dev"
except ImportError:  # pragma: no cover
    VERSION = "dev"


def main(argv: list[str] | None = None) -> int:
    """Le CLI. Rend le code de sortie du processus au lieu d'appeler
    `sys.exit`, pour que tout le scan soit testable dans le processus, ce que le
    `main_test.go` de Go ne peut pas faire."""
    parser = build_parser()
    arguments = parser.parse_args(normalize_argv(list(sys.argv[1:] if argv is None else argv)))

    if arguments.version:
        print("tf-predeploy-firewall " + VERSION)
        return 0
    if arguments.print_rules:
        sys.stdout.buffer.write(ruledef.builtin_yaml())
        return 0
    report.set_tool_version(VERSION)

    if (
        sum(
            bool(enabled)
            for enabled in (arguments.staged, arguments.uncommitted, arguments.full_repo_scan)
        )
        > 1
    ):
        return _die("--staged, --uncommitted and --full-repo-scan are mutually exclusive")
    post_comment = bool(arguments.post_comment)
    if arguments.staged or arguments.uncommitted:
        # A local scan has no PR to comment on. GITHUB_TOKEN being exported in a
        # developer's shell is common enough that leaving the default in place
        # would make the hook try (and fail) to post somewhere.
        post_comment = False

    try:
        config = load_config(arguments.config)
    except ConfigError as exc:
        return _die(str(exc))

    if arguments.rules_dry_run:
        # Deliberately before apply_org_policy: an author iterating on the LOCAL
        # file needs to test that file, not the org override that would replace
        # it in a real scan.
        return run_rules_dry_run(arguments.config, arguments.repo_dir)

    # Résolu une seule fois, ici, et non à chacun des trois appels au plan de
    # contrôle : politique, dérogations et usage doivent nommer le MÊME dépôt.
    # S'ils divergeaient, un scan pourrait recevoir la politique de « acme/infra »
    # et être compté sous un autre nom, qui apparaîtrait comme un second dépôt
    # dans le tableau de bord et consommerait un second dépôt du plan.
    arguments.repo_name = repo_full_name(arguments.repo_dir, arguments.repo_name)

    if arguments.license_key:
        apply_org_policy(
            config, arguments.license_key, arguments.license_api_base, arguments.repo_name
        )
    warn_unknown_threshold(config.block_threshold)

    try:
        return execute_scan(arguments, config, post_comment)
    except ConfigError as exc:
        return _die(str(exc))
    except diff.GitError as exc:
        return _die(str(exc))


def run() -> None:
    """Point d'entrée du script de console."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
