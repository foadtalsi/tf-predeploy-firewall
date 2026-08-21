"""`--rules-dry-run` : que trouveraient mes règles personnalisées, aujourd'hui,
sur tout le dépôt ?

Port de cmd/tf-predeploy-firewall/dryrun.go.
"""

from __future__ import annotations

import sys

from .. import diff, rules
from ..report.finding import Finding
from .config import ConfigError, load_custom_rules


def run_rules_dry_run(config_path: str, repo_dir: str) -> int:
    """Répond à la question que se pose tout auteur de règle personnalisée et
    à laquelle le vrai scan ne peut pas répondre sans risque — sans faire échouer
    la CI, sans poster de commentaires et sans rapporter d'usage. Rend le code de
    sortie du processus.

    Il sort en 0 même quand des règles trouvent quelque chose : les
    correspondances sont ici la boucle de retour de l'auteur, pas des violations.
    La seule chose qui sorte en non-zéro est un fichier de règles qui ne se
    charge pas, parce qu'une configuration inanalysable ferait aussi échouer le
    vrai scan, et que c'est ici l'endroit pour l'apprendre.
    """
    try:
        custom = load_custom_rules(config_path)
    except ConfigError as exc:
        print(f"tf-predeploy-firewall: {exc}", file=sys.stderr)
        return 2
    if custom is None:
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
            files, None, [custom.as_engine_rule()], rules.RunOptions(repo_dir=repo_dir)
        )
    except Exception as exc:
        print(f"tf-predeploy-firewall: {exc}", file=sys.stderr)
        return 2

    by_rule: dict[str, list[Finding]] = {}
    for f in result.findings:
        rule_id = str(f.category).removeprefix("custom:")
        by_rule.setdefault(rule_id, []).append(f)

    print(
        f"dry run: {len(custom.rules)} custom rule(s) against {len(files)} .tf file(s) "
        f"in {repo_dir}\n"
    )
    for r in custom.rules:
        matches = sorted(by_rule.get(r.id, []), key=lambda m: (m.file, m.line))
        # "matched nothing" is the line an author most needs to see — a rule
        # that silently matches nothing is indistinguishable from a working one
        # until the incident it should have caught.
        print(f'rule "{r.id}": {len(matches)} match(es)')
        for m in matches:
            print(f"  {m.file}:{m.line}  {m.resource}  [{m.severity}] {m.message}")
        print()
    return 0
