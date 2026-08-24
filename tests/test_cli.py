"""Port des tests unitaires de cmd/tf-predeploy-firewall, cas pour cas :
main_test.go, providers_test.go, policy_test.go, waivers_test.go,
second_reviewer_test.go et suggestions_test.go.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from httpstub import Request, Response, StubServer
from tfpdf.cli import blocked_by
from tfpdf.cli.config import Config, ConfigError, load_config
from tfpdf.cli.forges import (
    ForgeError,
    _pr_number_from_event,
    post_suggestions,
    request_second_reviewer_if_critical,
)
from tfpdf.cli.main import _env_or
from tfpdf.cli.orgpolicy import apply_org_policy, apply_waivers
from tfpdf.cli.providers import resolve_providers, warn_uncovered_providers
from tfpdf.diff import ChangedFile
from tfpdf.report.finding import Category, Finding, Fix, Severity
from tfpdf.schema import Coverage, ProviderCoverage


def _finding(**kw: Any) -> Finding:
    base: dict[str, Any] = {
        "file": "main.tf",
        "line": 1,
        "category": Category.MISSING_LIFECYCLE,
        "severity": Severity.MEDIUM,
        "resource": "aws_db_instance.x",
        "message": "m",
    }
    base.update(kw)
    return Finding(**base)


# --- main_test.go: blocked_by ------------------------------------------------


def test_blocked_by() -> None:
    findings = [_finding(severity=Severity.MEDIUM), _finding(severity=Severity.LOW)]
    assert not blocked_by(findings, Severity.HIGH), "nothing reaches high"
    assert blocked_by(findings, Severity.MEDIUM), "a medium finding meets a medium threshold"


def test_blocked_by_waived_finding_is_skipped() -> None:
    findings = [
        _finding(severity=Severity.CRITICAL, waived=True),
        _finding(severity=Severity.LOW),
    ]
    assert not blocked_by(findings, Severity.HIGH), (
        "the only finding meeting the threshold is waived"
    )


# --- main_test.go: load_config ----------------------------------------------


def test_load_config_missing_file_falls_back_to_defaults(tmp_path: Path) -> None:
    config = load_config(str(tmp_path / "does-not-exist.yml"))
    assert config.block_threshold == Severity.HIGH
    assert config.plan_blast_radius_threshold == 10


def test_load_config_yaml_overrides_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text(
        "block_threshold: critical\nplan_blast_radius_threshold: 3\n"
        "ignore_rules: [tutorial_pattern]\n"
    )
    config = load_config(str(path))
    assert config.block_threshold == "critical"
    assert config.plan_blast_radius_threshold == 3
    assert config.ignore_rules == ["tutorial_pattern"]


def test_load_config_ignore_paths_parsed_and_convertible(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text(
        'ignore_paths:\n  - path: "legacy/**"\n  - path: "sandbox/*.tf"\n'
        "    categories: [missing_lifecycle]\n"
    )
    config = load_config(str(path))

    assert len(config.ignore_paths) == 2
    assert config.ignore_paths[0].path == "legacy/**"
    assert config.ignore_paths[0].categories == []
    assert config.ignore_paths[1].path == "sandbox/*.tf"
    assert len(config.ignore_paths[1].categories) == 1
    assert len(config.ignore_path_rules()) == 2


def test_load_config_env_overrides_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.yml"
    path.write_text("block_threshold: low\nplan_blast_radius_threshold: 5\n")
    monkeypatch.setenv("SCANNER_BLOCK_THRESHOLD", "critical")
    monkeypatch.setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "20")

    config = load_config(str(path))
    assert config.block_threshold == "critical"
    assert config.plan_blast_radius_threshold == 20


def test_load_config_invalid_blast_radius_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "not-a-number")
    with pytest.raises(ConfigError, match="must be an integer"):
        load_config(str(tmp_path / "does-not-exist.yml"))


def test_load_config_keeps_a_yaml_false_for_suggestions(tmp_path: Path) -> None:
    """`suggestions: false` doit survivre, et `suggestions` absent doit garder
    le défaut à vrai. Une vérification « présent dans le document ? » est ce qui
    les sépare — la raison pour laquelle `_apply_yaml` est écrit explicitement
    plutôt qu'en mise à jour de dictionnaire."""
    on = tmp_path / "on.yml"
    on.write_text("block_threshold: high\n")
    assert load_config(str(on)).suggestions is True

    off = tmp_path / "off.yml"
    off.write_text("suggestions: false\n")
    assert load_config(str(off)).suggestions is False


def test_env_or(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TF_FIREWALL_TEST_VAR", "")
    assert _env_or("TF_FIREWALL_TEST_VAR", "fallback") == "fallback"
    monkeypatch.setenv("TF_FIREWALL_TEST_VAR", "set-value")
    assert _env_or("TF_FIREWALL_TEST_VAR", "fallback") == "set-value"


# --- main_test.go: pr_number_from_event -------------------------------------


def test_pr_number_from_event_pr_number_env_takes_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PR_NUMBER", "42")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert _pr_number_from_event() == 42


def test_pr_number_from_event_from_event_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PR_NUMBER", raising=False)
    path = tmp_path / "event.json"
    path.write_text('{"pull_request": {"number": 7}}')
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    assert _pr_number_from_event() == 7


def test_pr_number_from_event_missing_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PR_NUMBER", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    with pytest.raises(ForgeError):
        _pr_number_from_event()


def test_pr_number_from_event_non_pull_request_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PR_NUMBER", raising=False)
    path = tmp_path / "event.json"
    path.write_text('{"ref": "refs/heads/main"}')
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    with pytest.raises(ForgeError, match=r"no pull_request\.number"):
        _pr_number_from_event()


# --- providers_test.go ------------------------------------------------------


def _files(*contents: str) -> list[ChangedFile]:
    return [ChangedFile(path="f.tf", head_content=c.encode()) for c in contents]


def test_resolve_providers_detects_from_block_headers() -> None:
    got = resolve_providers(
        "auto",
        _files(
            '\nresource "aws_db_instance" "prod" {}\ndata "aws_ami" "ubuntu" {}\n'
            'resource "azurerm_mssql_server" "db" {}\n'
        ),
    )
    assert got == ["aws", "azurerm"]


def test_resolve_providers_only_fetches_providers_with_shipped_packs() -> None:
    """Seuls les fournisseurs dont les packs sont réellement livrés peuvent
    être récupérés. En lister un trop tôt faisait annoncer par chaque scan d'un
    dépôt GCP que la couverture « retombe sur le pack embarqué » pour un
    fournisseur qui n'a pas de pack embarqué."""
    got = resolve_providers(
        "auto",
        _files(
            '\nresource "random_pet" "name" {}\nresource "tls_private_key" "k" {}\n'
            'resource "google_sql_database_instance" "db" {}\n'
            'resource "aws_db_instance" "prod" {}\n'
        ),
    )
    assert got == ["aws"], "google ships no pack and must not be fetched"


def test_resolve_providers_empty_for_module_only_changes() -> None:
    """Un diff qui ne touche que des modules n'a besoin d'aucun pack étendu :
    les règles guidées par le schéma sautent les appels de module, il n'y a donc
    rien qu'un pack étendu ajouterait."""
    assert resolve_providers("auto", _files('module "rds" { source = "./m" }')) == []


def test_resolve_providers_explicit_list_bypasses_detection() -> None:
    """Une liste explicite est l'utilisateur qui dit qu'il sait mieux — prise
    telle quelle, noms inconnus compris (le plan de contrôle répond 404 et le
    scan avertit)."""
    got = resolve_providers(" aws, oci ", _files('resource "azurerm_thing" "x" {}'))
    assert got == ["aws", "oci"]


def test_resolve_providers_skips_comments() -> None:
    """Une ressource commentée ne doit pas déclencher de récupération.
    L'expression régulière s'ancre en début de ligne (avec l'indentation
    éventuelle), ce qu'un préfixe `#` casse."""
    assert resolve_providers("auto", _files('# resource "aws_db_instance" "x" {}\n')) == []


_COVERAGE = Coverage(
    providers=[
        ProviderCoverage(name="aws", version="6.59.0"),
        ProviderCoverage(name="azurerm", version="4.81.0"),
    ]
)


@pytest.mark.parametrize(
    ("name", "source", "want"),
    [
        (
            "uncovered provider is reported",
            'resource "google_sql_database_instance" "db" {}',
            "google",
        ),
        (
            "covered providers are silent",
            'resource "aws_vpc" "a" {}\nresource "azurerm_mssql_server" "b" {}\n',
            "",
        ),
        (
            "schemaless providers are not a coverage gap",
            'resource "random_pet" "n" {}\nresource "tls_private_key" "k" {}\n'
            'resource "null_resource" "x" {}\n',
            "",
        ),
        (
            "only the uncovered ones are named",
            'resource "aws_vpc" "a" {}\nresource "oci_core_vcn" "b" {}\n',
            "oci",
        ),
    ],
)
def test_warn_uncovered_providers(
    name: str, source: str, want: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """La moitié silencieuse du même défaut : les règles basées sur les valeurs
    se déclenchent sur n'importe quel fournisseur, si bien qu'un fournisseur non
    couvert produit un rapport qui a l'air d'avoir marché pendant que les règles
    guidées par le schéma restent inertes. Le scan doit le dire."""
    warn_uncovered_providers(_files(source), _COVERAGE)
    exception = capsys.readouterr().err

    if want == "":
        assert exception == "", f"expected silence, got: {exception}"
        return
    assert want in exception
    # The warning has to say what still ran, or it reads as "this scan did
    # nothing" and gets ignored.
    assert "hardcoded credentials" in exception


# --- policy_test.go ---------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_ambient_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Les variables d'intégration continue du développeur ne doivent pas
    déborder dans ces tests."""
    for var in (
        "SCANNER_BLOCK_THRESHOLD",
        "SCANNER_PLAN_BLAST_RADIUS_THRESHOLD",
        "SCANNER_COST_IMPACT_THRESHOLD_USD",
        "SCANNER_SUGGESTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_TOKEN",
        "GITLAB_CI",
        "PR_NUMBER",
        "CI_PROJECT_PATH",
    ):
        monkeypatch.delenv(var, raising=False)


def test_apply_org_policy_overrides_local_config() -> None:
    body = {
        "block_threshold": "critical",
        "ignore_rules": ["tutorial_pattern"],
        "plan_blast_radius_threshold": 3,
    }
    with StubServer(lambda r: Response(body=body)) as srv:
        config = Config(block_threshold=Severity.HIGH, plan_blast_radius_threshold=10)
        apply_org_policy(config, "test-key", srv.url)

    assert config.block_threshold == "critical"
    assert config.plan_blast_radius_threshold == 3
    assert config.ignore_rules == ["tutorial_pattern"]


def test_apply_org_policy_env_var_wins_over_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCANNER_BLOCK_THRESHOLD", "low")
    with StubServer(lambda r: Response(body={"block_threshold": "critical"})) as srv:
        config = Config(block_threshold=Severity.HIGH)
        apply_org_policy(config, "test-key", srv.url)
    assert config.block_threshold == Severity.HIGH, (
        "env precedence leaves the threshold untouched by policy"
    )


def test_apply_org_policy_no_policy_leaves_config_untouched() -> None:
    with StubServer(lambda r: Response(body={})) as srv:
        config = Config(block_threshold=Severity.HIGH, plan_blast_radius_threshold=10)
        apply_org_policy(config, "test-key", srv.url)
    assert config.block_threshold == Severity.HIGH
    assert config.plan_blast_radius_threshold == 10


def test_apply_org_policy_fails_open_on_network_error() -> None:
    config = Config(block_threshold=Severity.HIGH, plan_blast_radius_threshold=10)
    apply_org_policy(config, "test-key", "http://127.0.0.1:1")  # nothing listening
    assert config.block_threshold == Severity.HIGH
    assert config.plan_blast_radius_threshold == 10


def test_apply_org_policy_reviewer_lists_override_local_config() -> None:
    body = {
        "require_second_reviewer_users": ["alice"],
        "require_second_reviewer_teams": ["security-team"],
    }
    with StubServer(lambda r: Response(body=body)) as srv:
        config = Config(block_threshold=Severity.HIGH)
        apply_org_policy(config, "test-key", srv.url)
    assert config.require_second_reviewer_users == ["alice"]
    assert config.require_second_reviewer_teams == ["security-team"]


def test_apply_org_policy_custom_rules_yaml_overrides_local_config() -> None:
    custom = (
        "custom_rules:\n  - id: no-iam-users\n    resource_type: aws_iam_user\n"
        "    severity: medium\n    message: x\n"
    )
    with StubServer(lambda r: Response(body={"custom_rules_yaml": custom})) as srv:
        config = Config(block_threshold=Severity.HIGH)
        apply_org_policy(config, "test-key", srv.url)
    assert config.custom_rules_yaml_override == custom


# --- waivers_test.go --------------------------------------------------------


def test_apply_waivers_matches_by_category_resource_file() -> None:
    body = [
        {
            "category": "missing_lifecycle",
            "resource": "aws_db_instance.legacy",
            "file": "main.tf",
            "justification": "ticketed in INFRA-42",
        }
    ]
    findings = [
        _finding(resource="aws_db_instance.legacy", severity=Severity.CRITICAL),
        # Same category+file, different resource — must NOT match.
        _finding(resource="aws_db_instance.other", severity=Severity.CRITICAL),
    ]

    with StubServer(lambda r: Response(body=body)) as srv:
        got = apply_waivers(findings, "test-key", srv.url, "acme/infra")

    assert got[0].waived and got[0].waiver_note == "ticketed in INFRA-42"
    assert not got[1].waived, "a different resource must remain active"


def test_apply_waivers_line_number_does_not_affect_match() -> None:
    """La ligne de la découverte a dérivé depuis la création de la dérogation —
    l'appariement n'est délibérément PAS sensible à la ligne, donc cela doit
    quand même correspondre."""
    body = [
        {
            "category": "missing_lifecycle",
            "resource": "aws_db_instance.legacy",
            "file": "main.tf",
            "justification": "accepted",
        }
    ]
    findings = [_finding(resource="aws_db_instance.legacy", line=42, severity=Severity.CRITICAL)]

    with StubServer(lambda r: Response(body=body)) as srv:
        assert apply_waivers(findings, "test-key", srv.url, "acme/infra")[0].waived


def test_apply_waivers_without_a_repo_name_leaves_findings_untouched() -> None:
    """Un dépôt que personne n'a su nommer : il n'y a rien à demander au plan
    de contrôle, et surtout rien à accorder par défaut."""
    findings = [_finding(resource="x")]
    got = apply_waivers(findings, "test-key", "http://127.0.0.1:1", "")
    assert not got[0].waived


def test_apply_waivers_fails_open_on_network_error() -> None:
    findings = [_finding(resource="x", severity=Severity.CRITICAL)]
    got = apply_waivers(findings, "test-key", "http://127.0.0.1:1", "acme/infra")  # rien n'écoute
    assert not got[0].waived


# --- second_reviewer_test.go ------------------------------------------------


def test_request_second_reviewer_no_op_without_configured_reviewers() -> None:
    """Aucun jeton ni dépôt posé et aucun relecteur configuré — ceci doit
    rendre la main immédiatement sans essayer de construire un client de PR, ce
    qui échouerait bruyamment sur les variables d'environnement absentes."""
    request_second_reviewer_if_critical([_finding(severity=Severity.CRITICAL)], Config())


def test_request_second_reviewer_no_op_without_critical_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("PR_NUMBER", "1")

    with StubServer(lambda r: Response(status=201, body={})) as srv:
        monkeypatch.setattr("tfpdf.cli.forges.github_api_base_for_test", srv.url)
        config = Config(require_second_reviewer_users=["alice"])
        request_second_reviewer_if_critical([_finding(severity=Severity.HIGH)], config)
        assert srv.calls == 0, "no API call when no finding is critical"


def test_request_second_reviewer_requests_reviewers_on_critical_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("PR_NUMBER", "7")

    with StubServer(lambda r: Response(status=201, body={})) as srv:
        monkeypatch.setattr("tfpdf.cli.forges.github_api_base_for_test", srv.url)
        config = Config(require_second_reviewer_users=["alice"])
        request_second_reviewer_if_critical([_finding(severity=Severity.CRITICAL)], config)

        assert srv.requests[0].path == "/repos/owner/repo/pulls/7/requested_reviewers"


# --- suggestions_test.go ----------------------------------------------------


def _fixable_finding() -> Finding:
    return Finding(
        file="rds.tf",
        line=2,
        category=Category.MISSING_LIFECYCLE,
        severity=Severity.MEDIUM,
        resource="aws_db_instance.prod",
        message="no prevent_destroy guard",
        fix=Fix(
            start_line=2,
            end_line=2,
            lines=[
                'resource "aws_db_instance" "prod" {',
                "  lifecycle {",
                "    prevent_destroy = true",
                "  }",
            ],
        ),
    )


def _suggestion_handler(patch: str) -> tuple[Any, dict[str, Any]]:
    captured: dict[str, Any] = {}

    def handler(r: Request) -> Response:
        if r.method == "GET" and r.path.endswith("/files"):
            if r.query.get("page") == ["1"]:
                return Response(body=[{"filename": "rds.tf", "patch": patch}])
            return Response(body=[])
        if r.method == "GET":
            return Response(body=[])
        if r.method == "POST" and r.path.endswith("/reviews"):
            captured["review"] = r.body
            return Response(body={"id": 1})
        raise AssertionError(f"unexpected request: {r.method} {r.path}")

    return handler, captured


def _with_pr_context(monkeypatch: pytest.MonkeyPatch, srv: StubServer) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("PR_NUMBER", "5")
    monkeypatch.setattr("tfpdf.cli.forges.github_api_base_for_test", srv.url)


def test_post_suggestions_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    handler, captured = _suggestion_handler(
        '@@ -1,3 +1,4 @@\n+resource "aws_db_instance" "prod" {\n+  identifier = "prod"\n+}\n'
    )
    with StubServer(handler) as srv:
        _with_pr_context(monkeypatch, srv)
        post_suggestions([_fixable_finding()])

    review = captured.get("review")
    assert review is not None, "expected a review to be posted"
    comments = review["comments"]
    assert len(comments) == 1
    body = comments[0]["body"]
    assert "```suggestion" in body, body
    assert "prevent_destroy = true" in body, body


def test_post_suggestions_skips_waived_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """An accepted finding is a decision already made; handing someone a button
    to un-accept it would undo the point of the baseline."""
    handler, captured = _suggestion_handler("@@ -1,3 +1,4 @@\n+x\n")
    with StubServer(handler) as srv:
        _with_pr_context(monkeypatch, srv)
        f = _fixable_finding()
        f.waived = True
        f.waiver_note = "accepted in baseline"
        post_suggestions([f])
    assert "review" not in captured


def test_post_suggestions_no_network_when_nothing_is_fixable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La plupart des découvertes n'ont pas de correctif exact. Ce chemin ne
    doit rien coûter — pas même les appels d'API nécessaires pour déterminer où
    se trouve le diff."""
    with StubServer(lambda r: Response(body={})) as srv:
        _with_pr_context(monkeypatch, srv)
        post_suggestions(
            [
                Finding(
                    file="rds.tf",
                    line=1,
                    category=Category.TUTORIAL_PATTERN,
                    severity=Severity.HIGH,
                    resource="aws_security_group.web",
                    message="0.0.0.0/0",
                )
            ]
        )
        assert srv.calls == 0, "no API traffic when no finding carries a fix"


def test_post_suggestions_survives_an_api_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Toute la fonctionnalité est un confort posé par-dessus le commentaire de
    synthèse. Si elle échoue, le verdict du scan ne doit pas en être affecté —
    ce test existe pour attraper un futur remaniement qui la rendrait fatale."""
    with StubServer(lambda r: Response(status=500, body={})) as srv:
        _with_pr_context(monkeypatch, srv)
        post_suggestions([_fixable_finding()])  # must not raise


def test_post_suggestions_respects_the_inline_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    from tfpdf.cli.forges import MAX_INLINE_SUGGESTIONS

    patch = "@@ -1,1 +1,200 @@\n" + "+line\n" * 200
    handler, captured = _suggestion_handler(patch)

    findings = []
    for i in range(1, MAX_INLINE_SUGGESTIONS + 6):
        f = _fixable_finding()
        f.resource = "aws_db_instance.db" + chr(ord("a") + i)
        assert f.fix is not None
        f.fix.start_line = f.fix.end_line = i
        findings.append(f)

    with StubServer(handler) as srv:
        _with_pr_context(monkeypatch, srv)
        post_suggestions(findings)

    assert len(captured["review"]["comments"]) == MAX_INLINE_SUGGESTIONS


def test_the_event_payload_head_sha_is_preferred_over_github_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GITHUB_SHA sur un événement pull_request est le commit de fusion
    éphémère, qui n'est pas un commit de la PR et que GitHub rejette comme
    commit_id d'une revue. Le SHA de tête doit venir de la charge utile de
    l'événement."""
    from tfpdf.cli.forges import head_sha_from_event

    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"head": {"sha": "realheadsha"}}}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_SHA", "ephemeral-merge-commit")

    assert head_sha_from_event() == "realheadsha"

    # And no payload is not an error: GitHub then attaches the review to the
    # latest commit.
    monkeypatch.delenv("GITHUB_EVENT_PATH")
    assert head_sha_from_event() == ""
