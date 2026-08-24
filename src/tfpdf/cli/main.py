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

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from .. import (
    baseline,
    cloudread,
    customrules,
    diff,
    ignore,
    planjson,
    report,
    ruledef,
    rules,
    schema,
)
from ..report.finding import Finding, Severity
from ..rules import Options, Rule, sprint
from . import terraformscan
from .config import Config, ConfigError, load_config, load_custom_rules, warn_unknown_threshold
from .dryrun import run_rules_dry_run
from .forges import (
    default_base_ref,
    default_post_comment,
    post_suggestions,
    post_to_pr,
    repo_full_name,
    request_second_reviewer_if_critical,
)
from .goflags import normalize_argv
from .orgpolicy import apply_org_policy, apply_waivers, report_usage

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

_LICENSE_API_BASE_DEFAULT = "https://api.tfpredeployfirewall.com"


def _warn(message: str) -> None:
    print("tf-predeploy-firewall: " + message, file=sys.stderr)


def _wants_markdown_on_stdout(choice: str) -> bool:
    """Dit si stdout reçoit le Markdown plutôt que la mise en forme terminal.

    Le défaut est « auto » plutôt que « text » à cause de ce qui existe déjà :
    des scripts redirigent cette sortie vers un fichier ou la passent à un
    autre outil, et changer ce qu'ils reçoivent casserait sans prévenir. Un
    terminal, lui, n'a jamais rien attendu de particulier.
    """
    if choice == "markdown":
        return True
    if choice == "text":
        return False
    # NO_COLOR n'entre pas ici : il dit de ne pas colorer, pas de changer de
    # format. Les mélanger ferait basculer la sortie entière sur une variable
    # qui ne parle que de couleur.
    return not sys.stdout.isatty()


def _die(message: str) -> int:
    _warn(message)
    return 2


def _env_or(key: str, fallback: str) -> str:
    return os.environ.get(key) or fallback


def _go_bool(v: str) -> bool:
    """`strconv.ParseBool`, pour une valeur attachée à un drapeau booléen."""
    if v in ("1", "t", "T", "true", "TRUE", "True"):
        return True
    if v in ("0", "f", "F", "false", "FALSE", "False"):
        return False
    raise argparse.ArgumentTypeError(f"must be true or false, got {v!r}")


def build_parser() -> argparse.ArgumentParser:
    """Le jeu de drapeaux, correspondant exactement aux noms et défauts de la
    version Go.

    Les booléens prennent une valeur attachée *optionnelle* au lieu d'être en
    `store_true`, parce qu'`action.yml` passe `--full-repo-scan=false`. Voir
    `goflags`.
    """
    p = argparse.ArgumentParser(
        prog="tf-predeploy-firewall",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    def flag_bool(name: str, default: bool, help_: str) -> None:
        p.add_argument(name, nargs="?", const=True, default=default, type=_go_bool, help=help_)

    p.add_argument("--repo-dir", default=".", help="path to the git repository to scan")
    p.add_argument(
        "--base-ref",
        default=default_base_ref(),
        help="git ref to diff against (PR/MR base)",
    )
    p.add_argument("--head-ref", default="HEAD", help="git ref containing the changes")
    flag_bool(
        "--full-repo-scan",
        False,
        "scan every .tf file in repo-dir instead of just the PR diff — for a scheduled "
        "drift audit of already-merged code (e.g. cron), not a PR check. ForceNew-change "
        "detection naturally finds nothing (there's no diff), but unknown-attribute, "
        "tutorial-pattern and missing-lifecycle findings run at full strength against "
        "current content.",
    )
    p.add_argument(
        "--config",
        default=_env_or("SCANNER_CONFIG", "config/default.yml"),
        help="path to YAML config",
    )
    flag_bool(
        "--post-comment",
        default_post_comment(),
        "post/update a PR/MR comment with the results",
    )
    p.add_argument(
        "--sarif-output",
        default="",
        help="write SARIF 2.1.0 JSON to this file (for GitHub Code Scanning)",
    )
    p.add_argument(
        "--codequality-output",
        default="",
        help="write a GitLab Code Quality report to this file — declare it under "
        "artifacts:reports:codequality and findings render in the MR widget, no token "
        "needed",
    )
    p.add_argument(
        "--format",
        default=_env_or("TFPDF_FORMAT", "auto"),
        choices=("auto", "text", "markdown"),
        help='how the report is printed to stdout. "auto" (default) picks the compact '
        "text layout when stdout is a terminal and the PR-comment markdown otherwise, so "
        "redirecting or piping keeps the format every existing script expects. The PR "
        "comment, SARIF and Code Quality outputs are unaffected either way.",
    )
    p.add_argument(
        "--plan-json",
        default="",
        help="path to `terraform show -json <planfile>` output (phase 2: adds "
        "confirmed-replace, drift and blast-radius findings). Optional — this tool never "
        "runs terraform itself; you run the plan, it only reads the file.",
    )
    flag_bool(
        "--cloud-read-access",
        _env_or("TFPDF_CLOUD_READ_ACCESS", "") == "true",
        "use the workflow's existing cloud credentials to read whether the resources a "
        "finding is about already exist, and how much they hold, so severity reflects "
        "the real account instead of the source alone. Off by default, and the whole "
        "scanner works without it. Only ever reads (sts:GetCallerIdentity, "
        "s3:ListObjectsV2 — see docs/cloud-read-access.md for the IAM policy); missing "
        "or refused credentials leave every severity untouched rather than failing the "
        "scan.",
    )
    p.add_argument(
        "--license-key",
        default=_env_or("TFPDF_LICENSE_KEY", ""),
        help="paid-plan API key. Entirely optional — leave unset to run the scanner "
        "exactly as the free, open-source tool it has always been.",
    )
    p.add_argument(
        "--repo-name",
        default=_env_or("TFPDF_REPO_NAME", ""),
        help='the "owner/repo" this scan is reported under, for usage, waivers and org '
        "policy. Only read with a license key. Normally resolved on its own — from "
        "GITHUB_REPOSITORY or CI_PROJECT_PATH on CI, and from the origin remote "
        "otherwise — so pass this only when neither is right.",
    )
    p.add_argument(
        "--license-api-base",
        default=_env_or("TFPDF_LICENSE_API_BASE", _LICENSE_API_BASE_DEFAULT),
        help="control-plane API base URL, override for self-hosted/staging deployments",
    )
    p.add_argument(
        "--baseline",
        default=_env_or("TFPDF_BASELINE", ""),
        help="path to a committed baseline file of accepted pre-existing findings. They "
        "stay visible in the PR comment but don't block a merge; anything new does. "
        "Missing file = no baseline.",
    )
    p.add_argument(
        "--write-baseline",
        default="",
        help="write the current findings to this path as the new baseline and exit "
        "without failing. Run once when adopting the scanner on an existing repo, then "
        "commit the file.",
    )
    p.add_argument(
        "--providers",
        default=_env_or("TFPDF_PROVIDERS", "auto"),
        help='comma-separated providers to fetch extended rule packs for ("aws,azurerm"), '
        'or "auto" to detect them from the resource types in the scanned files.',
    )
    flag_bool(
        "--staged",
        False,
        "scan the staged changes (git index vs HEAD) instead of a ref diff — what a "
        "pre-commit hook wants: the findings arrive before the secret enters history, "
        "while removing it is still an edit and not a rotation",
    )
    flag_bool(
        "--uncommitted",
        False,
        "scan working-tree changes vs HEAD — staged, unstaged and untracked .tf files "
        'alike. The "what would the firewall say?" mode for local use, no refs needed',
    )
    flag_bool(
        "--rules-dry-run",
        False,
        "test the config's custom_rules against the whole repo without failing anything: "
        "prints what each rule matched (including 'matched nothing', which is what a rule "
        "author most needs to see) and exits 0.",
    )
    p.add_argument(
        "--rules",
        default=_env_or("TFPDF_RULES", ""),
        help="path to a rule pack (YAML) to use INSTEAD of the built-in one. Start from "
        "--print-rules rather than a blank file.",
    )
    flag_bool(
        "--print-rules",
        False,
        "print the built-in rule pack to stdout and exit — the starting point for a "
        '--rules file, and the honest answer to "what exactly does this thing look for?"',
    )
    flag_bool("--version", False, "print the version and exit")
    return p


def load_ruleset(path: str, opts: Options) -> list[Rule]:
    """Résout le pack de règles de ce scan : celui livré avec la version, ou un
    fichier externe quand `--rules` en nomme un.

    Un pack externe REMPLACE le jeu intégré au lieu de s'y ajouter, ce qui est
    la seule option honnête : un pack qui ne pourrait qu'ajouter des règles ne
    pourrait pas corriger un faux positif d'une règle intégrée, et c'est la
    première raison pour laquelle on se saisit de cette option. Cela veut dire
    aussi qu'une erreur ici donne un scan tournant sur bien moins de règles que
    l'opérateur ne le croit : l'échange est donc annoncé sur stderr, avec le
    décompte.
    """
    if not path:
        return rules.default_rules(opts)

    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError(f"reading rule pack: {exc}") from exc
    try:
        pack = ruledef.load(data)
    except ruledef.RulePackError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    # `extends: builtin` layers the pack over the shipped rules instead of
    # replacing them. Both outcomes are announced, because both are easy to get
    # wrong in a way that runs perfectly and scans less than the author
    # believes.
    if pack.extends == ruledef.EXTENDS_BUILTIN:
        try:
            merged, merge_report = ruledef.merge(rules.builtin_pack(), pack)
            ruleset = rules.from_pack(merged, opts)
        except ruledef.RulePackError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        _warn(f"rule pack {path} extends the built-in rules: {merge_report}")
        return ruleset

    try:
        ruleset = rules.from_pack(pack, opts)
    except ruledef.RulePackError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    _warn(
        f"using rule pack {path} ({len(pack.rules)} definitions, {len(ruleset)} active) "
        "— the built-in rules are NOT in effect"
    )
    return ruleset


def blocked_by(findings: list[Finding], threshold: Severity | str) -> bool:
    """Dit si une découverte *active* atteint le seuil.

    Les découvertes couvertes par une dérogation sont sautées, ce qui est la
    différence avec `severity.should_block_ignoring_waivers` — voir le nom de
    cette fonction.
    """
    return any(f.severity.at_least(threshold) for f in findings if not f.waived)


def load_knowledge_base(
    license_key: str, api_base: str, providers: list[str]
) -> schema.KnowledgeBase:
    """Construit la base de connaissances du moteur de règles : le pack de base
    gratuit livré avec cette version, plus — pour une organisation sous licence
    — le pack étendu couvrant toute la surface de ressources du fournisseur.

    Sans clé de licence, ceci ne fait aucune entrée-sortie réseau et le scanner
    se comporte exactement comme l'outil gratuit qu'il a toujours été.

    Avec une clé, un pack étendu impossible à récupérer est un avertissement,
    jamais une erreur : le scan continue sur le pack de base. Une couverture qui
    rétrécirait en silence serait ici le pire mode de défaillance possible, donc
    une couverture réduite est toujours énoncée à voix haute plutôt que déduite
    de découvertes absentes.
    """
    if not license_key or not providers:
        return schema.load()

    from .. import licensing

    client = licensing.new_client(license_key, api_base)
    overlays = []
    for provider in providers:
        pack, exception = client.fetch_rule_pack(provider)
        if pack is None:
            _warn(
                f"extended {provider} rule pack unavailable ({exception}) — {provider} "
                "coverage falls back to the embedded pack"
            )
            continue
        if exception is not None:
            # A pack was still produced, so coverage is intact — say that
            # plainly rather than warning about coverage we didn't lose.
            _warn(
                f"could not reach the rule pack service ({exception}) — using the cached "
                f"extended {provider} pack, coverage is unchanged"
            )
        elif pack.from_cache:
            _warn(f"using the cached extended {provider} rule pack")
        overlays.append(pack.reader())

    kb, errs = schema.load_with(*overlays)
    for e in errs:
        _warn(
            f"extended rule pack rejected ({e}) — that provider's coverage falls back "
            "to the embedded pack"
        )
    return kb


def main(argv: list[str] | None = None) -> int:
    """Le CLI. Rend le code de sortie du processus au lieu d'appeler
    `sys.exit`, pour que tout le scan soit testable dans le processus, ce que le
    `main_test.go` de Go ne peut pas faire."""
    parser = build_parser()
    args = parser.parse_args(normalize_argv(list(sys.argv[1:] if argv is None else argv)))

    if args.version:
        print("tf-predeploy-firewall " + VERSION)
        return 0
    if args.print_rules:
        sys.stdout.buffer.write(ruledef.builtin_yaml())
        return 0
    report.set_tool_version(VERSION)

    if sum(bool(x) for x in (args.staged, args.uncommitted, args.full_repo_scan)) > 1:
        return _die("--staged, --uncommitted and --full-repo-scan are mutually exclusive")
    post_comment = bool(args.post_comment)
    if args.staged or args.uncommitted:
        # A local scan has no PR to comment on. GITHUB_TOKEN being exported in a
        # developer's shell is common enough that leaving the default in place
        # would make the hook try (and fail) to post somewhere.
        post_comment = False

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        return _die(str(exc))

    if args.rules_dry_run:
        # Deliberately before apply_org_policy: an author iterating on the LOCAL
        # file needs to test that file, not the org override that would replace
        # it in a real scan.
        return run_rules_dry_run(args.config, args.repo_dir)

    # Résolu une seule fois, ici, et non à chacun des trois appels au plan de
    # contrôle : politique, dérogations et usage doivent nommer le MÊME dépôt.
    # S'ils divergeaient, un scan pourrait recevoir la politique de « acme/infra »
    # et être compté sous un autre nom, qui apparaîtrait comme un second dépôt
    # dans le tableau de bord et consommerait un second dépôt du plan.
    args.repo_name = repo_full_name(args.repo_dir, args.repo_name)

    if args.license_key:
        apply_org_policy(config, args.license_key, args.license_api_base, args.repo_name)
    warn_unknown_threshold(config.block_threshold)

    try:
        return _scan(args, config, post_comment)
    except ConfigError as exc:
        return _die(str(exc))
    except diff.GitError as exc:
        return _die(str(exc))


def _scan(args: argparse.Namespace, config: Config, post_comment: bool) -> int:
    mode = terraformscan.Mode(
        staged=bool(args.staged),
        uncommitted=bool(args.uncommitted),
        full_repo=bool(args.full_repo_scan),
        base_ref=args.base_ref,
        head_ref=args.head_ref,
    )

    # The diff runs before the knowledge base loads, because which extended
    # packs are worth fetching depends on which providers the changed files
    # actually use — fetching an Azure pack to scan an AWS repo would be a
    # network round trip spent on nothing.
    changed = terraformscan.changed_terraform(args.repo_dir, mode)

    from .providers import resolve_providers, warn_uncovered_providers

    kb = load_knowledge_base(
        args.license_key, args.license_api_base, resolve_providers(args.providers, changed)
    )
    coverage = kb.coverage()
    provider_summary = ", ".join(f"{p.name} {p.version}" for p in coverage.providers)
    # `sprint`, not an f-string: Go prints the pack list with %v, which reads
    # "[aws-base azurerm-base]". Python's repr would write
    # "['aws-base', 'azurerm-base']", and the two builds would differ on the one
    # line an operator greps to see what coverage a scan actually had.
    _warn(
        f"rule packs {sprint(coverage.packs)} ({provider_summary}; "
        f"{coverage.resource_types} resource types)"
    )
    warn_uncovered_providers(changed, coverage)

    # The static cost estimator runs only when no plan JSON is supplied — the
    # plan-based cost rule sees counts, for_each and computed values, so when
    # both could run, the better-informed one runs alone rather than billing the
    # same PR twice with numbers that may disagree.
    rule_opts = Options()
    if not args.plan_json:
        rule_opts.cost_threshold_usd = config.cost_impact_threshold_usd
    ruleset = load_ruleset(args.rules, rule_opts)

    if config.custom_rules_yaml_override:
        try:
            custom_rule_set: customrules.Config | None = customrules.load(
                config.custom_rules_yaml_override
            )
        except customrules.CustomRuleError as exc:
            return _die(f"custom rules from org policy: {exc}")
    else:
        custom_rule_set = load_custom_rules(args.config)
    if custom_rule_set is not None:
        ruleset = [*ruleset, custom_rule_set.as_engine_rule()]

    # Opened before the scan so that a misconfigured role is reported once, on
    # its own line, rather than inferred from severities that quietly did not
    # move. Everything about it fails open: `reader` is None whenever anything
    # is missing, and None is the ordinary free path.
    cloud_access, cloud_note = cloudread.open_access(args.cloud_read_access)
    if cloud_note:
        _warn(cloud_note)

    result = rules.run(
        changed,
        kb,
        ruleset,
        rules.RunOptions(
            global_ignore=list(config.ignore_rules),
            # Lets the engine read each scanned file's directory to resolve
            # `var.x` and `local.y` — a credential one indirection away is the
            # common case, not the exotic one.
            repo_dir=args.repo_dir,
            cloud_reader=cloud_access,
        ),
    )
    findings = list(result.findings)

    if args.plan_json:
        # A --plan-json that names a file we can't read or parse is fatal, not a
        # degraded scan: the operator asked for phase 2 explicitly, and silently
        # running phase 1 instead would report a clean plan nobody looked at.
        try:
            pf = planjson.load(args.plan_json)
        except ValueError as exc:
            return _die(str(exc))
        plan_findings = rules.run_plan_rules(
            args.plan_json,
            pf,
            result.changed_attrs,
            kb,
            rules.PlanRuleConfig(
                blast_radius_threshold=config.plan_blast_radius_threshold,
                cost_impact_threshold_usd=config.cost_impact_threshold_usd,
                global_ignore=list(config.ignore_rules),
            ),
        )
        # A confirmed replace from the real plan supersedes phase 1's ForceNew
        # heuristic for the same resource — drop the guess once we have
        # certainty, instead of reporting the same problem twice.
        findings = rules.deduplicate_force_new_against_plan(findings, plan_findings)
        findings += plan_findings

    findings += ignore.apply(
        terraformscan.scan_terragrunt(args.repo_dir, mode, _warn), {}, config.ignore_rules
    )
    findings += ignore.apply(
        terraformscan.scan_tfvars(args.repo_dir, mode, _warn), {}, config.ignore_rules
    )
    findings = ignore.apply_path_rules(findings, config.ignore_path_rules())

    # --write-baseline records the current state and stops. It deliberately runs
    # before waivers are applied: a waiver is a live decision held in the
    # dashboard, and baking one into a committed file would outlive it.
    if args.write_baseline:
        try:
            baseline.write(
                args.write_baseline,
                findings,
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        except OSError as exc:
            return _die(str(exc))
        _warn(
            f"wrote {len(findings)} finding(s) to {args.write_baseline} — commit this "
            "file; they will no longer block a merge, and anything new will"
        )
        return 0

    # A baseline that exists but can't be read is fatal rather than ignored:
    # silently enforcing on a repo that expected a baseline would block every PR
    # in it.
    try:
        base = baseline.load(args.baseline)
    except ValueError as exc:
        return _die(str(exc))
    if base is not None:
        findings = base.apply(findings)
        message = f"baseline {args.baseline} accepts {base.size()} finding(s)"
        if (stale := base.stale()) > 0:
            message += (
                f"; {stale} entr(y/ies) no longer match anything and can be pruned with "
                "--write-baseline"
            )
        _warn(message)

    if args.license_key:
        findings = apply_waivers(findings, args.license_key, args.license_api_base, args.repo_name)

    blocked = blocked_by(findings, config.block_threshold)

    if args.license_key and report_usage(
        args.license_key, args.license_api_base, findings, blocked, args.repo_name
    ):
        return 3

    # Deux rendus du même rapport, et un seul part dans la PR. `body` est le
    # Markdown, inchangé et comparé octet pour octet au scanner Go ; ce qui
    # s'imprime dépend de qui lit.
    body = report.render_markdown(findings, config.block_threshold, blocked)
    if _wants_markdown_on_stdout(args.format):
        print(body)
    else:
        print(report.render_terminal(findings, config.block_threshold, blocked))

    if post_comment:
        try:
            post_to_pr(body)
        except Exception as exc:
            _warn(f"failed to post PR comment: {exc}")
        if config.suggestions:
            post_suggestions(findings)
        request_second_reviewer_if_critical(findings, config)

    if args.sarif_output:
        # Waived findings are excluded from SARIF entirely — a security tab is
        # for open issues, and an accepted finding isn't one; it stays visible in
        # the PR comment's waived section instead.
        try:
            Path(args.sarif_output).write_bytes(
                report.render_sarif([f for f in findings if not f.waived])
            )
        except OSError as exc:
            _warn(f"failed to write SARIF file: {exc}")

    if args.codequality_output:
        # GitLab's MR-widget counterpart to SARIF; the renderer skips waived
        # findings itself.
        try:
            Path(args.codequality_output).write_bytes(report.render_code_quality(findings))
        except OSError as exc:
            _warn(f"failed to write Code Quality report: {exc}")

    return 1 if blocked else 0


def run() -> None:
    """Point d'entrée du script de console."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
