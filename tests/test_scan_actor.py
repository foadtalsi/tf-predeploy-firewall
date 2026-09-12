"""CI attribution reaches the usage API without inventing legacy identities."""

from __future__ import annotations

import json

import pytest

from tfpdf._httpjson import RawResponse
from tfpdf.cli.orgpolicy import report_usage, scan_actor

ACTOR_VARIABLES = (
    "TFPDF_SCAN_ACTOR",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_ACTOR",
    "GITLAB_USER_LOGIN",
)


@pytest.fixture(autouse=True)
def clean_actor_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ACTOR_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def test_no_identity_is_invented() -> None:
    assert scan_actor() == ""


def test_ci_precedence_and_explicit_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_USER_LOGIN", "gitlab-user")
    assert scan_actor() == "gitlab-user"
    monkeypatch.setenv("GITHUB_ACTOR", "initial-user")
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", "rerun-user")
    assert scan_actor() == "rerun-user"
    monkeypatch.setenv("TFPDF_SCAN_ACTOR", "  local-user  ")
    assert scan_actor() == "local-user"


def test_usage_reporting_transmits_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_ACTOR", "alice")
    payloads = []

    def request(*args, **kwargs):
        payloads.append(json.loads(kwargs["body"]))
        return RawResponse(status=200, body=b'{"allowed":true}', headers={})

    monkeypatch.setattr("tfpdf.licensing.client.request_raw", request)
    assert report_usage("test-key", "https://api.test", [], False, "acme/infra") is False
    assert payloads[0]["scan_actor"] == "alice"
