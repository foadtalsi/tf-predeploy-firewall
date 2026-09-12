"""Déroulement du scan, de la sélection des règles à la publication des résultats."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from .. import (
    baseline,
    cloudread,
    customrules,
    ignore,
    planjson,
    report,
    ruledef,
    rules,
    schema,
)
from ..report.finding import Finding, Severity
from ..rules import Options, Rule, sprint
from ..rules.changedattrs import ChangedAttrKey
from . import terraformscan
from .config import Config, ConfigError, load_custom_rules
from .forges import (
    post_suggestions,
    post_to_pr,
    request_second_reviewer_if_critical,
)
from .orgpolicy import apply_waivers, report_usage


def _warn(message: str) -> None:
    print("tf-predeploy-firewall: " + message, file=sys.stderr)


def _die(message: str) -> int:
    _warn(message)
    return 2


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


def blocked_by(findings: list[Finding], threshold: Severity | str) -> bool:
    """Dit si une découverte *active* atteint le seuil.

    Les découvertes couvertes par une dérogation sont sautées, ce qui est la
    différence avec `severity.should_block_ignoring_waivers` — voir le nom de
    cette fonction.
    """
    return any(finding.severity.at_least(threshold) for finding in findings if not finding.waived)


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

    knowledge_base, load_errors = schema.load_with(*overlays)
    for load_error in load_errors:
        _warn(
            f"extended rule pack rejected ({load_error}) — that provider's coverage falls back "
            "to the embedded pack"
        )
    return knowledge_base


def execute_scan(args: argparse.Namespace, config: Config, post_comment: bool) -> int:
    """Collecte, accepte les risques connus, décide du blocage puis publie."""
    findings = _collect_findings(args, config)
    if args.write_baseline:
        return _write_baseline(args.write_baseline, findings)

    findings = _apply_baseline(args.baseline, findings)
    if args.license_key:
        findings = apply_waivers(findings, args.license_key, args.license_api_base, args.repo_name)

    blocked = blocked_by(findings, config.block_threshold)
    if args.license_key and report_usage(
        args.license_key, args.license_api_base, findings, blocked, args.repo_name
    ):
        return 3

    _publish_reports(args, config, findings, blocked, post_comment)
    return 1 if blocked else 0


def _collect_findings(arguments: argparse.Namespace, config: Config) -> list[Finding]:
    """Analyse les sources et le plan avant toute acceptation de risques."""
    mode = terraformscan.Mode(
        staged=bool(arguments.staged),
        uncommitted=bool(arguments.uncommitted),
        full_repo=bool(arguments.full_repo_scan),
        base_ref=arguments.base_ref,
        head_ref=arguments.head_ref,
    )

    # The diff runs before the knowledge base loads, because which extended
    # packs are worth fetching depends on which providers the changed files
    # actually use — fetching an Azure pack to scan an AWS repo would be a
    # network round trip spent on nothing.
    changed_files = terraformscan.changed_terraform(arguments.repo_dir, mode)

    from .providers import resolve_providers, warn_uncovered_providers

    knowledge_base = load_knowledge_base(
        arguments.license_key,
        arguments.license_api_base,
        resolve_providers(arguments.providers, changed_files),
    )
    coverage = knowledge_base.coverage()
    provider_summary = ", ".join(
        f"{provider.name} {provider.version}" for provider in coverage.providers
    )
    # `sprint`, not an f-string: Go prints the pack list with %v, which reads
    # "[aws-base azurerm-base]". Python's repr would write
    # "['aws-base', 'azurerm-base']", and the two builds would differ on the one
    # line an operator greps to see what coverage a scan actually had.
    _warn(
        f"rule packs {sprint(coverage.packs)} ({provider_summary}; "
        f"{coverage.resource_types} resource types)"
    )
    warn_uncovered_providers(changed_files, coverage)

    # The static cost estimator runs only when no plan JSON is supplied — the
    # plan-based cost rule sees counts, for_each and computed values, so when
    # both could run, the better-informed one runs alone rather than billing the
    # same PR twice with numbers that may disagree.
    rule_options = Options()
    if not arguments.plan_json:
        rule_options.cost_threshold_usd = config.cost_impact_threshold_usd
    ruleset = load_ruleset(arguments.rules, rule_options)

    if config.custom_rules_yaml_override:
        try:
            custom_rule_set: customrules.Config | None = customrules.load(
                config.custom_rules_yaml_override
            )
        except customrules.CustomRuleError as exc:
            raise ConfigError(f"custom rules from org policy: {exc}") from exc
    else:
        custom_rule_set = load_custom_rules(arguments.config)
    if custom_rule_set is not None:
        ruleset = [*ruleset, custom_rule_set.as_engine_rule()]

    # Opened before the scan so that a misconfigured role is reported once, on
    # its own line, rather than inferred from severities that quietly did not
    # move. Everything about it fails open: `reader` is None whenever anything
    # is missing, and None is the ordinary free path.
    cloud_access, cloud_note = cloudread.open_access(arguments.cloud_read_access)
    if cloud_note:
        _warn(cloud_note)

    result = rules.run(
        changed_files,
        knowledge_base,
        ruleset,
        rules.RunOptions(
            global_ignore=list(config.ignore_rules),
            # Lets the engine read each scanned file's directory to resolve
            # `var.x` and `local.y` — a credential one indirection away is the
            # common case, not the exotic one.
            repo_dir=arguments.repo_dir,
            cloud_reader=cloud_access,
        ),
    )
    findings = list(result.findings)

    # Dit à voix haute, et pas seulement absent du rapport : un scan qui se tait
    # sur un fournisseur doit dire lequel et pourquoi, sinon « aucune découverte »
    # se lit comme « rien à signaler ».
    for note in result.notes:
        _warn(note)

    if arguments.plan_json:
        findings = _merge_plan_findings(
            arguments, config, findings, result.changed_attrs, knowledge_base
        )

    findings += ignore.apply(
        terraformscan.scan_terragrunt(arguments.repo_dir, mode, _warn), {}, config.ignore_rules
    )
    findings += ignore.apply(
        terraformscan.scan_tfvars(arguments.repo_dir, mode, _warn), {}, config.ignore_rules
    )
    findings = ignore.apply_path_rules(findings, config.ignore_path_rules())

    return findings


def _merge_plan_findings(
    arguments: argparse.Namespace,
    config: Config,
    findings: list[Finding],
    changed_attrs: dict[str, set[ChangedAttrKey]],
    knowledge_base: schema.KnowledgeBase,
) -> list[Finding]:
    """Confirme les remplacements avec le plan et évite les doublons statiques."""
    # A --plan-json that names a file we can't read or parse is fatal, not a
    # degraded scan: the operator asked for phase 2 explicitly, and silently
    # running phase 1 instead would report a clean plan nobody looked at.
    try:
        terraform_plan = planjson.load(arguments.plan_json)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    plan_findings = rules.run_plan_rules(
        arguments.plan_json,
        terraform_plan,
        changed_attrs,
        knowledge_base,
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

    return findings


def _write_baseline(path: str, findings: list[Finding]) -> int:
    """Enregistre les résultats bruts, sans y figer les dérogations distantes."""
    try:
        baseline.write(
            path,
            findings,
            datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except OSError as exc:
        return _die(str(exc))
    _warn(
        f"wrote {len(findings)} finding(s) to {path} — commit this "
        "file; they will no longer block a merge, and anything new will"
    )
    return 0


def _apply_baseline(path: str, findings: list[Finding]) -> list[Finding]:
    """Applique les acceptations locales et signale celles devenues obsolètes."""
    # A baseline that exists but can't be read is fatal rather than ignored:
    # silently enforcing on a repo that expected a baseline would block every PR
    # in it.
    try:
        accepted_baseline = baseline.load(path)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if accepted_baseline is not None:
        findings = accepted_baseline.apply(findings)
        message = f"baseline {path} accepts {accepted_baseline.size()} finding(s)"
        if (stale_count := accepted_baseline.stale()) > 0:
            message += (
                f"; {stale_count} entr(y/ies) no longer match anything and can be pruned with "
                "--write-baseline"
            )
        _warn(message)
        if accepted_baseline.legacy:
            # Dit une fois, en clair, avec la conséquence plutôt que le numéro
            # de version. « format version 1 » n'apprend rien à personne ; « une
            # découverte que vous n'avez jamais acceptée peut être silencieuse »
            # se comprend sans lire le code.
            _warn(
                f"baseline {path} is in the older format, which did not record "
                "which rule each accepted finding came from. Several rules share a "
                "category, so an entry accepted for one of them also silences the "
                "others on the same resource — including findings you never saw. "
                "Regenerate it with --write-baseline to match exactly."
            )

    return findings


def _publish_reports(
    arguments: argparse.Namespace,
    config: Config,
    findings: list[Finding],
    blocked: bool,
    post_comment: bool,
) -> None:
    """Affiche le verdict et publie les formats demandés."""
    # Deux rendus du même rapport, et un seul part dans la PR. `body` est le
    # Markdown, inchangé et comparé octet pour octet au scanner Go ; ce qui
    # s'imprime dépend de qui lit.
    body = report.render_markdown(findings, config.block_threshold, blocked)
    if _wants_markdown_on_stdout(arguments.format):
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

    if arguments.sarif_output:
        # Waived findings are excluded from SARIF entirely — a security tab is
        # for open issues, and an accepted finding isn't one; it stays visible in
        # the PR comment's waived section instead.
        try:
            Path(arguments.sarif_output).write_bytes(
                report.render_sarif([finding for finding in findings if not finding.waived])
            )
        except OSError as exc:
            _warn(f"failed to write SARIF file: {exc}")

    if arguments.codequality_output:
        # GitLab's MR-widget counterpart to SARIF; the renderer skips waived
        # findings itself.
        try:
            Path(arguments.codequality_output).write_bytes(report.render_code_quality(findings))
        except OSError as exc:
            _warn(f"failed to write Code Quality report: {exc}")
