"""Verify repository identity for hosted scan reporting, including local Git-remote fallback and a
visible warning when no identity is available.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from httpstub import Request, Response, StubServer
from tfpdf.cli.forges import _repo_path_from_remote_url, repo_full_name
from tfpdf.cli.orgpolicy import report_usage
from tfpdf.report.finding import Category, Finding, Severity

# Clear CI identity variables so tests actually exercise the Git-remote fallback.
_CI_VARS = ("GITHUB_REPOSITORY", "CI_PROJECT_PATH", "TFPDF_REPO_NAME")


@pytest.fixture(autouse=True)
def _no_ci_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _CI_VARS:
        monkeypatch.delenv(name, raising=False)


def _git(directory: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=directory, capture_output=True, check=True)


def _repo(tmp_path: Path, origin: str | None = "git@github.com:acme/infra.git") -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    (tmp_path / "main.tf").write_text(
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}'
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    if origin is not None:
        _git(tmp_path, "remote", "add", "origin", origin)
    return tmp_path


# Parse Git remote URLs.


@pytest.mark.parametrize(
    ("url", "want"),
    [
        # HTTPS and SSH remote forms must resolve to the same hosted repository identity.
        ("git@github.com:acme/infra.git", "acme/infra"),
        ("https://github.com/acme/infra.git", "acme/infra"),
        ("ssh://git@github.com/acme/infra.git", "acme/infra"),
        ("https://github.com/acme/infra", "acme/infra"),
        # Strip credentials embedded in CI clone URLs.
        ("https://x-token:ghp_secret@github.com/acme/infra.git", "acme/infra"),
        # Preserve GitLab subgroup paths, matching CI_PROJECT_PATH.
        ("git@gitlab.com:acme/platform/infra.git", "acme/platform/infra"),
        # Local folder remotes have no hosted identity; do not invent one.
        ("/home/me/infra", ""),
        ("../sibling.git", ""),
        ("C:/repos/infra", ""),
        ("https://github.com/acme", ""),
        ("", ""),
    ],
)
def test_the_repo_path_is_read_out_of_a_remote_url(url: str, want: str) -> None:
    assert _repo_path_from_remote_url(url) == want


# Identity source precedence.


def test_a_local_scan_is_named_after_its_origin_remote(tmp_path: Path) -> None:
    """Local scans inherit the origin remote's repository identity."""
    assert repo_full_name(str(_repo(tmp_path))) == "acme/infra"


def test_the_ci_variable_still_wins_over_the_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CI identity takes precedence so existing scan history keeps the same repository name."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/canonical")
    assert repo_full_name(str(_repo(tmp_path))) == "acme/canonical"


def test_an_explicit_name_wins_over_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/canonical")
    assert repo_full_name(str(_repo(tmp_path)), "acme/chosen") == "acme/chosen"


def test_a_repo_without_a_remote_has_no_name(tmp_path: Path) -> None:
    assert repo_full_name(str(_repo(tmp_path, origin=None))) == ""


def test_a_directory_that_is_not_a_repo_has_no_name(tmp_path: Path) -> None:
    """A nonrepository directory has no identity but does not fail merely because naming is
    unavailable.
    """
    assert repo_full_name(str(tmp_path)) == ""


# Hosted scan reporting.


def _finding() -> Finding:
    return Finding(
        file="main.tf",
        line=1,
        category=Category.MISSING_LIFECYCLE,
        severity=Severity.HIGH,
        resource="aws_db_instance.prod",
        message="x",
    )


def test_a_named_scan_is_reported_and_counted() -> None:
    received: list[Request] = []

    def handler(request: Request) -> Response:
        received.append(request)
        return Response(body={"allowed": True})

    with StubServer(handler) as server:
        assert report_usage("test-key", server.url, [_finding()], False, "acme/infra") is False

    assert [r.path for r in received] == ["/v1/usage/scan"]
    assert received[0].body["repo_full_name"] == "acme/infra"
    assert received[0].body["finding_count"] == 1


def test_a_nameless_scan_reports_nothing_and_says_so(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Warn explicitly when a scan cannot be recorded without repository identity."""
    assert report_usage("test-key", "http://127.0.0.1:1", [_finding()], False, "") is False
    warning = capsys.readouterr().err
    assert "will NOT be counted" in warning
    assert "--repo-name" in warning


# End-to-end CLI integration.


def test_a_local_scan_with_a_license_key_records_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run the real CLI to verify licensed local scans actually send usage with the resolved
    repository identity.
    """
    from tfpdf.cli.main import main

    repo = _repo(tmp_path)
    received: list[Request] = []

    def handler(request: Request) -> Response:
        received.append(request)
        if request.path == "/v1/usage/scan":
            return Response(body={"allowed": True})
        # Optional waivers and packs fail open; a 404 preserves the local scan.
        return Response(status=404, body={})

    with StubServer(handler) as server:
        code = main(
            [
                "--repo-dir",
                str(repo),
                "--full-repo-scan",
                "--license-key",
                "test-key",
                "--license-api-base",
                server.url,
                "--post-comment=false",
            ]
        )

    capsys.readouterr()
    scans = [r for r in received if r.path == "/v1/usage/scan"]
    assert len(scans) == 1, f"the scan must be reported once: {[r.path for r in received]}"
    assert scans[0].body["repo_full_name"] == "acme/infra"
    assert code in (0, 1)


def test_a_refused_quota_never_fails_the_build_or_hides_the_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Quota refusal skips recording without hiding reports or changing the scan verdict."""
    from tfpdf.cli.main import main

    repo = _repo(tmp_path)

    def handler(request: Request) -> Response:
        if request.path == "/v1/usage/scan":
            return Response(
                body={
                    "allowed": False,
                    "reason": 'plan "Trial" includes 50 scans and this org has used all of them',
                }
            )
        return Response(status=404, body={})

    with StubServer(handler) as server:
        code = main(
            [
                "--repo-dir",
                str(repo),
                "--full-repo-scan",
                "--license-key",
                "test-key",
                "--license-api-base",
                server.url,
                "--post-comment=false",
            ]
        )

    captured = capsys.readouterr()
    assert code != 3, "quota refusal must not fail the build"
    assert code in (0, 1), "the exit code depends only on findings"
    assert captured.out.strip(), "quota refusal must not hide the report"
    assert "not recorded" in captured.err, "quota refusal must produce a warning"
