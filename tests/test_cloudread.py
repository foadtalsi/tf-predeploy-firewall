"""Test read-only AWS enforcement, default opt-out behavior, and graceful failure handling."""

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from tfpdf.cloudread import Access, WriteAttempted, open_access, permission_summary


@pytest.fixture
def granted(monkeypatch: pytest.MonkeyPatch) -> Access:
    """Open access through the real setup path so tests verify guard installation as well as its
    behavior.
    """
    monkeypatch.setenv("AWS_REGION", "eu-west-3")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "clé-de-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-de-test")
    monkeypatch.setattr(
        "botocore.client.BaseClient._make_api_call",
        lambda self, *a, **k: {"Account": "123456789012"},
    )
    access, _ = open_access(True)
    assert access is not None
    # Remove the STS stub after opening access; later clients still use the real guard.
    monkeypatch.undo()
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "clé-de-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-de-test")
    return access


# Read-only operation guard.


def test_a_write_call_is_refused_before_it_leaves_the_process(granted: Access) -> None:
    """Use real botocore to verify writes are rejected before a socket opens."""
    import boto3

    with pytest.raises(WriteAttempted, match="s3:PutObject"):
        boto3.client("s3").put_object(Bucket="peu-importe", Key="k", Body=b"x")


def test_a_delete_call_is_refused_too(granted: Access) -> None:
    """Reject delete operations through the same guard."""
    import boto3

    with pytest.raises(WriteAttempted, match="s3:DeleteBucket"):
        boto3.client("s3").delete_bucket(Bucket="peu-importe")


def test_a_read_that_is_not_on_the_list_is_refused(granted: Access) -> None:
    """GetObject is a read but remains forbidden: the allowlist excludes object contents."""
    import boto3

    with pytest.raises(WriteAttempted, match="s3:GetObject"):
        boto3.client("s3").get_object(Bucket="peu-importe", Key="k")


def test_the_guard_covers_a_client_the_severity_check_makes_itself(
    granted: Access,
) -> None:
    """Guard clients created through boto3's default session, including the severity checker."""
    import boto3
    import botocore.client

    from tfpdf.ruledef import severitycheck

    # Mock only GetCallerIdentity after the guard runs; keep the rest of botocore's request path
    # real.
    real_call = botocore.client.BaseClient._make_api_call

    def only_identity_succeeds(self: Any, name: str, params: Any) -> Any:
        if name == "GetCallerIdentity":
            return {"Account": "123456789012"}
        return real_call(self, name, params)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", only_identity_succeeds)
    try:
        assert severitycheck.available_context() is True
    finally:
        monkeypatch.undo()
    assert severitycheck.s3 is not None

    with pytest.raises(WriteAttempted, match="s3:DeleteObject"):
        severitycheck.s3.delete_object(Bucket="peu-importe", Key="k")

    # Also check the module's own client on the same session.
    with pytest.raises(WriteAttempted, match="s3:CreateBucket"):
        boto3.client("s3").create_bucket(Bucket="peu-importe")


def test_the_call_the_severity_check_actually_makes_is_allowed(granted: Access) -> None:
    """The guard must still allow the calls needed by actual severity checks."""
    import boto3
    from botocore.stub import Stubber

    client = boto3.client("s3")
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", {"KeyCount": 0})
        client.list_objects_v2(Bucket="b", MaxKeys=1)


# --- open_access ------------------------------------------------------------


def test_not_asking_for_it_builds_nothing_and_says_nothing() -> None:
    """Default opt-out must read no credentials, make no request, and emit no note."""
    assert open_access(False) == (None, "")


def test_asking_without_a_region_explains_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    access, note = open_access(True)
    assert access is None
    assert "no region is set" in note


def test_aws_region_alone_is_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept AWS_REGION even though botocore normally reads AWS_DEFAULT_REGION."""
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-west-3")
    monkeypatch.setattr(
        "botocore.client.BaseClient._make_api_call",
        lambda self, *a, **k: {"Account": "123456789012"},
    )
    access, note = open_access(True)
    assert access == Access(account_id="123456789012", region="eu-west-3")
    assert "eu-west-3" in note


def test_credentials_that_do_not_work_do_not_fail_the_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired or invalid credentials must not fail the static scan."""
    monkeypatch.setenv("AWS_REGION", "eu-west-3")

    def refused(self: Any, *args: Any, **kwargs: Any) -> None:
        raise ClientError({"Error": {"Code": "ExpiredToken"}}, "GetCallerIdentity")

    monkeypatch.setattr("botocore.client.BaseClient._make_api_call", refused)
    access, note = open_access(True)
    assert access is None
    assert "no usable credentials" in note


def test_the_note_lists_what_the_scan_may_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Derive the displayed permissions from the enforced allowlist."""
    monkeypatch.setenv("AWS_REGION", "eu-west-3")
    monkeypatch.setattr(
        "botocore.client.BaseClient._make_api_call",
        lambda self, *a, **k: {"Account": "1"},
    )
    _, note = open_access(True)
    assert permission_summary() in note
    for expected in ("sts:GetCallerIdentity", "s3:ListObjectsV2"):
        assert expected in note
