"""Exercise the installed CLI against real temporary Git repositories to test how scan components
work together.
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
    """Create base and head commits with the supplied Terraform contents and return the repository."""
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
    """enable_dns_hostnames is a known, in-place-updatable aws_vpc attribute."""
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
    """Accept the exact --full-repo-scan=true/false syntax emitted by action.yml."""
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
    """Preserve Go-style single-dash long options used by existing workflows."""
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
    """Recording existing findings for adoption must exit successfully."""
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
    """A local hook must not post comments merely because the developer exports GITHUB_TOKEN."""
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
    """Preserve legacy blocking for unknown thresholds while warning about typos, including
    uppercase HIGH.
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
