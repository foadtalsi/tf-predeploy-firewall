"""Preview custom rules against the whole repository with --rules-dry-run."""

from __future__ import annotations

import sys

from .. import diff, rules
from ..report.finding import Finding
from .config import ConfigError, load_custom_rules


def run_rules_dry_run(config_path: str, repo_dir: str) -> int:
    """Preview custom rules without blocking CI, posting comments, or reporting usage. Return an
    exit code.
    """
    try:
        custom_rules = load_custom_rules(config_path)
    except ConfigError as exc:
        print(f"tf-predeploy-firewall: {exc}", file=sys.stderr)
        return 2
    if custom_rules is None:
        print(
            f"tf-predeploy-firewall: no custom_rules in {config_path} — nothing to dry-run",
            file=sys.stderr,
        )
        return 2

    try:
        files = diff.all_terraform_files(repo_dir)
    except Exception as exc:
        print(f"tf-predeploy-firewall: {exc}", file=sys.stderr)
        return 2

    # Only the custom rules run: the built-ins have their own tests, and mixing
    # their findings in would bury the signal the author came for. No ignores
    # either — an author needs to see what a rule REALLY matches; the real scan
    # applies suppressions later.
    try:
        result = rules.run(
            files, None, [custom_rules.as_engine_rule()], rules.RunOptions(repo_dir=repo_dir)
        )
    except Exception as exc:
        print(f"tf-predeploy-firewall: {exc}", file=sys.stderr)
        return 2

    findings_by_rule: dict[str, list[Finding]] = {}
    for finding in result.findings:
        rule_id = str(finding.category).removeprefix("custom:")
        findings_by_rule.setdefault(rule_id, []).append(finding)

    print(
        f"dry run: {len(custom_rules.rules)} custom rule(s) against {len(files)} .tf file(s) "
        f"in {repo_dir}\n"
    )
    for custom_rule in custom_rules.rules:
        matches = sorted(
            findings_by_rule.get(custom_rule.id, []),
            key=lambda matched_finding: (matched_finding.file, matched_finding.line),
        )
        # "matched nothing" is the line an author most needs to see — a rule
        # that silently matches nothing is indistinguishable from a working one
        # until the incident it should have caught.
        print(f'rule "{custom_rule.id}": {len(matches)} match(es)')
        for matched_finding in matches:
            print(
                f"  {matched_finding.file}:{matched_finding.line}  {matched_finding.resource}  [{matched_finding.severity}] {matched_finding.message}"
            )
        print()
    return 0
