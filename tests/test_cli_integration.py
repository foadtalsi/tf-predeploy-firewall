"""Port de cmd/tf-predeploy-firewall/integration_test.go, cas pour cas.

En boîte noire, comme l'original Go : il pilote le vrai script console sur un
vrai dépôt git, si bien qu'une régression dans la façon dont le CLI assemble les
pièces fait échouer un test au lieu de n'apparaître que dans une exécution
manuelle.

La version Go recompile le binaire à chaque exécution ; ici le point d'entrée
est déjà installé dans l'environnement virtuel, donc le sous-processus est celui
qu'obtient un utilisateur.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PLANS = Path(__file__).parent / "data" / "plans"

#: Run the CLI the way a pipeline does — a subprocess, exit code and all — but
#: through this interpreter, so no PATH assumptions and no rebuild step.
_ENTRY = [sys.executable, "-c", "from tfpdf.cli.main import run; run()"]


def _run_scanner(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    # A clean environment: the developer's own GITHUB_TOKEN or CI variables
    # would otherwise make the scan try to post a comment somewhere real.
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("GITHUB_", "GITLAB_", "CI_", "TFPDF_", "SCANNER_"))
    }
    clean.update(env or {})
    return subprocess.run(
        [*_ENTRY, *args],
        capture_output=True,
        text=True,
        env=clean,
        check=False,
    )


def _git(dir_: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=dir_, capture_output=True, text=True, check=True)


def _init_git_repo_with_commits(dir_: Path, base_tf: str, head_tf: str) -> Path:
    """Un dépôt git temporaire avec un commit de base et un commit de tête
    contenant les variantes de main.tf données."""
    _git(dir_, "init", "-q", "-b", "main")
    _git(dir_, "config", "user.email", "test@example.com")
    _git(dir_, "config", "user.name", "test")

    (dir_ / "main.tf").write_text(base_tf)
    _git(dir_, "add", "-A")
    _git(dir_, "commit", "-q", "-m", "base")

    (dir_ / "main.tf").write_text(head_tf)
    _git(dir_, "add", "-A")
    _git(dir_, "commit", "-q", "-m", "head")
    return dir_


def test_static_scan_finds_and_blocks(tmp_path: Path) -> None:
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        'resource "aws_db_instance" "prod" {\n  identifier = "prod-db"\n'
        '  password   = "changeme"\n}',
    )

    p = _run_scanner("--repo-dir", str(repo), "--base-ref", "HEAD~1", "--head-ref", "HEAD")
    out = p.stdout + p.stderr

    assert p.returncode == 1, f"expected exit 1 (blocked), got {p.returncode}\n{out}"
    assert "hardcoded string literal" in out, out
    assert "Merge blocked" in out, out


def test_no_findings_exits_zero(tmp_path: Path) -> None:
    """enable_dns_hostnames est un attribut aws_vpc connu et non ForceNew — une
    mise à jour sur place propre qui ne déclenche aucune règle statique."""
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block            = "10.0.0.0/16"\n'
        "  enable_dns_hostnames  = true\n}",
    )

    p = _run_scanner("--repo-dir", str(repo), "--base-ref", "HEAD~1", "--head-ref", "HEAD")
    out = p.stdout + p.stderr

    assert p.returncode == 0, f"expected exit 0, got {p.returncode}\n{out}"
    assert "No risk patterns detected" in out, out


def test_plan_json_merges_and_deduplicates(tmp_path: Path) -> None:
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_db_instance" "prod" {\n  identifier = "prod-db"\n'
        '  engine     = "postgres"\n}',
        'resource "aws_db_instance" "prod" {\n  identifier = "prod-db"\n  engine     = "mysql"\n}',
    )

    p = _run_scanner(
        "--repo-dir",
        str(repo),
        "--base-ref",
        "HEAD~1",
        "--head-ref",
        "HEAD",
        "--plan-json",
        str(PLANS / "sample_plan.json"),
    )
    out = p.stdout + p.stderr

    assert p.returncode == 1, f"expected exit 1, got {p.returncode}\n{out}"
    assert "Confirmed destroy/replace" in out, out
    assert "ForceNew change on stateful resource" not in out, (
        "the phase-1 heuristic must be deduplicated away once the plan confirms it"
    )


def test_missing_plan_json_file_exits_with_error(tmp_path: Path) -> None:
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }',
        'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }\n'
        'resource "aws_vpc" "extra" { cidr_block = "10.1.0.0/16" }',
    )

    p = _run_scanner(
        "--repo-dir",
        str(repo),
        "--base-ref",
        "HEAD~1",
        "--head-ref",
        "HEAD",
        "--plan-json",
        str(repo / "does-not-exist.json"),
    )
    assert p.returncode == 2, f"expected exit 2, got {p.returncode}\n{p.stdout}{p.stderr}"


# --- beyond the Go suite ----------------------------------------------------


def test_the_action_yml_boolean_syntax_is_accepted(tmp_path: Path) -> None:
    """`action.yml` passe `--full-repo-scan=${{ inputs.full-repo-scan }}`, ce
    qui vaut `--full-repo-scan=false` à chaque exécution qui n'y adhère pas.

    Le paquet flag de Go accepte une valeur accolée à un booléen ; le
    `store_true` d'argparse non. Sans la forme à valeur optionnelle dans
    `build_parser`, l'Action publiée échouerait sur son propre défaut — ceci
    épingle donc l'écriture exacte que l'Action émet, dans les deux états.
    """
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        'resource "aws_vpc" "second" {\n  cidr_block = "10.1.0.0/16"\n}',
    )
    common = ["--repo-dir", str(repo), "--base-ref", "HEAD~1", "--head-ref", "HEAD"]

    off = _run_scanner(*common, "--full-repo-scan=false")
    assert off.returncode in (0, 1), off.stdout + off.stderr

    on = _run_scanner(*common, "--full-repo-scan=true")
    assert on.returncode in (0, 1), on.stdout + on.stderr


def test_single_dash_long_flags_are_accepted(tmp_path: Path) -> None:
    """Le paquet flag de Go traite `-repo-dir` et `--repo-dir` comme le même
    drapeau, et les deux écritures figurent dans des README et des workflows
    écrits à la main."""
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  '
        "enable_dns_hostnames = true\n}",
    )

    p = _run_scanner("-repo-dir", str(repo), "-base-ref", "HEAD~1", "-head-ref", "HEAD")
    out = p.stdout + p.stderr
    assert p.returncode == 0, f"{p.returncode}\n{out}"
    assert "No risk patterns detected" in out, out


def test_mutually_exclusive_modes_are_refused(tmp_path: Path) -> None:
    p = _run_scanner("--staged", "--uncommitted", "--repo-dir", str(tmp_path))
    assert p.returncode == 2
    assert "mutually exclusive" in p.stderr


def test_version_and_print_rules_short_circuit() -> None:
    v = _run_scanner("--version")
    assert v.returncode == 0
    assert v.stdout.startswith("tf-predeploy-firewall ")

    r = _run_scanner("--print-rules")
    assert r.returncode == 0
    assert "rules:" in r.stdout, "the built-in pack goes to stdout verbatim"


def test_write_baseline_records_and_exits_zero(tmp_path: Path) -> None:
    """Adopter le scanner sur un dépôt qui a déjà des découvertes ne doit pas
    faire échouer l'exécution qui les enregistre."""
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        'resource "aws_db_instance" "prod" {\n  identifier = "prod-db"\n'
        '  password   = "changeme"\n}',
    )
    out_path = tmp_path / "baseline.json"

    p = _run_scanner(
        "--repo-dir",
        str(repo),
        "--base-ref",
        "HEAD~1",
        "--head-ref",
        "HEAD",
        "--write-baseline",
        str(out_path),
    )
    assert p.returncode == 0, p.stdout + p.stderr
    assert out_path.exists()

    # And the recorded findings no longer block.
    again = _run_scanner(
        "--repo-dir",
        str(repo),
        "--base-ref",
        "HEAD~1",
        "--head-ref",
        "HEAD",
        "--baseline",
        str(out_path),
    )
    out = again.stdout + again.stderr
    assert again.returncode == 0, f"a baselined finding must not block\n{out}"
    assert "accepted finding" in out


def test_staged_mode_never_tries_to_post_a_comment(tmp_path: Path) -> None:
    """Un hook pre-commit tourne dans le shell d'un développeur, où
    GITHUB_TOKEN est souvent exporté. Laisser le défaut de --post-comment en
    place ferait tenter au hook de poster sur la première PR que le jeton peut
    atteindre."""
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  enable_dns_support = true\n}',
    )
    (repo / "staged.tf").write_text(
        'resource "aws_db_instance" "x" {\n  password = "changeme"\n}\n'
    )
    _git(repo, "add", "staged.tf")

    p = _run_scanner(
        "--repo-dir",
        str(repo),
        "--staged",
        env={"GITHUB_TOKEN": "not-a-real-token", "GITHUB_REPOSITORY": "acme/infra"},
    )
    out = p.stdout + p.stderr
    assert p.returncode == 1, out
    assert "hardcoded string literal" in out
    assert "failed to post PR comment" not in out, "it must not have tried"


@pytest.mark.parametrize("threshold", ["hgih", "HIGH"])
def test_an_unrecognised_threshold_is_said_out_loud(tmp_path: Path, threshold: str) -> None:
    """Go classe un seuil inconnu à 0, si bien qu'une faute de frappe
    transforme silencieusement le scanner en « bloquer sur la moindre
    découverte ». La comparaison est laissée exactement telle que Go la fait —
    une découverte de faible sévérité bloque toujours — mais le CLI dit
    désormais pourquoi.

    « HIGH » est là aussi : les valeurs sont en minuscules, donc la
    capitalisation évidente est l'une des fautes de frappe que ceci attrape.
    """
    repo = _init_git_repo_with_commits(
        tmp_path,
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}',
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "my-test-bucket"\n}',
    )

    p = _run_scanner(
        "--repo-dir",
        str(repo),
        "--base-ref",
        "HEAD~1",
        "--head-ref",
        "HEAD",
        env={"SCANNER_BLOCK_THRESHOLD": threshold},
    )
    assert "is not one of low/medium/high/critical" in p.stderr, p.stderr
