"""Test the skip_final_snapshot severity check against the error shapes real botocore returns."""

from __future__ import annotations

from collections.abc import Iterator

import boto3
import pytest
from botocore.stub import Stubber

from tfpdf.ruledef import severitycheck


@pytest.fixture
def rds(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stubber]:
    """Give the check a stubbed RDS client, as if the scan's probe had succeeded."""
    client = boto3.client(
        "rds",
        region_name="eu-west-3",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    monkeypatch.setattr(severitycheck, "rds", client)
    monkeypatch.setattr(severitycheck, "AWS_OK", True)
    with Stubber(client) as stub:
        yield stub


def test_a_db_instance_this_pr_creates_is_low(rds: Stubber) -> None:
    """Nothing exists yet, so a destroy has nothing to lose."""
    rds.add_client_error(
        "describe_db_instances",
        service_error_code="DBInstanceNotFound",
        expected_params={"DBInstanceIdentifier": "prod-db"},
    )

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_db_instance", "prod-db"
    )

    assert severity == "low"


def test_an_existing_db_instance_is_high(rds: Stubber) -> None:
    """A live database destroyed without a final snapshot is gone for good."""
    rds.add_response(
        "describe_db_instances",
        {"DBInstances": [{"DBInstanceIdentifier": "prod-db"}]},
        expected_params={"DBInstanceIdentifier": "prod-db"},
    )

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_db_instance", "prod-db"
    )

    assert severity == "high"


def test_a_cluster_this_pr_creates_is_low(rds: Stubber) -> None:
    """Clusters use their own call and their own not-found code."""
    rds.add_client_error(
        "describe_db_clusters",
        service_error_code="DBClusterNotFoundFault",
        expected_params={"DBClusterIdentifier": "prod-cluster"},
    )

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_rds_cluster", "prod-cluster"
    )

    assert severity == "low"


def test_an_existing_cluster_is_high(rds: Stubber) -> None:
    rds.add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": "prod-cluster"}]},
        expected_params={"DBClusterIdentifier": "prod-cluster"},
    )

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_rds_cluster", "prod-cluster"
    )

    assert severity == "high"


def test_a_refused_lookup_keeps_the_static_severity(rds: Stubber) -> None:
    """A role without the RDS permissions proves nothing about the database."""
    rds.add_client_error("describe_db_instances", service_error_code="AccessDenied")

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_db_instance", "prod-db"
    )

    assert severity == "medium"


def test_a_type_the_check_does_not_cover_asks_nothing(rds: Stubber) -> None:
    """The stub has no queued response, so any call would fail the test."""
    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_docdb_cluster", "docs-cluster"
    )

    assert severity == "medium"


def test_without_access_the_check_asks_nothing(
    rds: Stubber, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(severitycheck, "AWS_OK", False)

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_db_instance", "prod-db"
    )

    assert severity == "medium"
