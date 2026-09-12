"""CLI entry point. Exit codes: 0 success, 1 blocked, 2 scan error."""

from __future__ import annotations

import sys

#: "dev" means a from-source build, matching the Go binary's unstamped default.
from importlib.metadata import PackageNotFoundError, version

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
from .pipeline import _die, execute_scan
from .pipeline import blocked_by as blocked_by
from .pipeline import load_knowledge_base as load_knowledge_base
from .pipeline import load_ruleset as load_ruleset

try:
    VERSION = version("tf-predeploy-firewall")
except PackageNotFoundError:  # pragma: no cover
    VERSION = "dev"


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return an exit code so callers can test it without exiting the process."""
    parser = build_parser()
    arguments = parser.parse_args(normalize_argv(list(sys.argv[1:] if argv is None else argv)))

    if arguments.version:
        print("tf-predeploy-firewall " + VERSION)
        return 0
    if arguments.print_rules:
        sys.stdout.buffer.write(ruledef.builtin_yaml())
        return 0
    report.set_tool_version(VERSION)

    if sum((arguments.staged, arguments.uncommitted, arguments.full_repo_scan)) > 1:
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
        return run_rules_dry_run(arguments.config, arguments.repo_dir)

    arguments.repo_name = repo_full_name(arguments.repo_dir, arguments.repo_name)
    warn_unknown_threshold(config.block_threshold)

    try:
        return execute_scan(arguments, config, post_comment)
    except (ConfigError, diff.GitError) as exc:
        return _die(str(exc))


def run() -> None:
    """Run the installed console script."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
