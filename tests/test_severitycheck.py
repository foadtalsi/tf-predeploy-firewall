"""Test the cloud severity checks against the response and error shapes real botocore returns."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError
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
        "medium", "aws_elasticache_cluster", "cache-cluster"
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


def test_a_documentdb_cluster_is_described_through_rds(rds: Stubber) -> None:
    """DocumentDB and Neptune share the RDS control plane, so the same call answers."""
    rds.add_response(
        "describe_db_clusters",
        {"DBClusters": [{"DBClusterIdentifier": "docs-cluster"}]},
        expected_params={"DBClusterIdentifier": "docs-cluster"},
    )

    severity = severitycheck.skip_final_snapshot_severity_check(
        "medium", "aws_docdb_cluster", "docs-cluster"
    )

    assert severity == "high"


# Stubbed clients for the other services.


def _client(service: str) -> Any:
    return boto3.client(
        service,
        region_name="eu-west-3",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


@pytest.fixture
def s3(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stubber]:
    client = _client("s3")
    monkeypatch.setattr(severitycheck, "s3", client)
    monkeypatch.setattr(severitycheck, "AWS_OK", True)
    with Stubber(client) as stub:
        yield stub


@pytest.fixture
def dynamodb(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stubber]:
    client = _client("dynamodb")
    monkeypatch.setattr(severitycheck, "dynamodb", client)
    monkeypatch.setattr(severitycheck, "AWS_OK", True)
    with Stubber(client) as stub:
        yield stub


@pytest.fixture
def ecr(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stubber]:
    client = _client("ecr")
    monkeypatch.setattr(severitycheck, "ecr", client)
    monkeypatch.setattr(severitycheck, "AWS_OK", True)
    with Stubber(client) as stub:
        yield stub


@pytest.fixture
def redshift(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stubber]:
    client = _client("redshift")
    monkeypatch.setattr(severitycheck, "redshift", client)
    monkeypatch.setattr(severitycheck, "AWS_OK", True)
    with Stubber(client) as stub:
        yield stub


# S3 buckets.


def test_a_bucket_with_objects_is_critical(s3: Stubber) -> None:
    s3.add_response(
        "list_objects_v2",
        {"KeyCount": 1, "Contents": [{"Key": "backup.tar"}]},
        expected_params={"Bucket": "prod-backups", "MaxKeys": 1},
    )

    assert severitycheck.s3_force_destroy_severity_check("medium", "prod-backups") == "critical"


def test_a_bucket_with_only_noncurrent_versions_is_not_empty(s3: Stubber) -> None:
    """force_destroy deletes every version, so versions alone are data to lose."""
    s3.add_response("list_objects_v2", {"KeyCount": 0})
    s3.add_response(
        "list_object_versions",
        {"Versions": [{"Key": "backup.tar", "VersionId": "v1", "IsLatest": False}]},
        expected_params={"Bucket": "prod-backups"},
    )

    assert severitycheck.s3_force_destroy_severity_check("medium", "prod-backups") == "critical"


def test_a_bucket_with_no_object_and_no_version_is_low(s3: Stubber) -> None:
    s3.add_response("list_objects_v2", {"KeyCount": 0})
    s3.add_response("list_object_versions", {"IsTruncated": False})

    assert severitycheck.s3_force_destroy_severity_check("medium", "prod-backups") == "low"


def test_a_bucket_that_does_not_exist_is_low(s3: Stubber) -> None:
    s3.add_client_error("list_objects_v2", service_error_code="NoSuchBucket")

    assert severitycheck.s3_force_destroy_severity_check("medium", "new-bucket") == "low"


def test_a_page_of_delete_markers_proves_nothing(s3: Stubber) -> None:
    """Versions may follow on the next page, so the bucket is not known to be empty."""
    s3.add_response("list_objects_v2", {"KeyCount": 0})
    s3.add_response(
        "list_object_versions",
        {"DeleteMarkers": [{"Key": "a", "VersionId": "m1"}], "IsTruncated": True},
    )

    assert severitycheck.s3_force_destroy_severity_check("medium", "prod-backups") == "medium"


def test_a_refused_version_listing_keeps_the_static_severity(s3: Stubber) -> None:
    """A role granted s3:ListBucket but not s3:ListBucketVersions cannot prove a bucket empty."""
    s3.add_response("list_objects_v2", {"KeyCount": 0})
    s3.add_client_error("list_object_versions", service_error_code="AccessDenied")

    assert severitycheck.s3_force_destroy_severity_check("medium", "prod-backups") == "medium"


def test_a_network_failure_keeps_the_static_severity(s3: Stubber) -> None:
    """A failure that is not an AWS answer must not fail the scan."""
    with patch.object(
        severitycheck.s3,
        "list_objects_v2",
        side_effect=EndpointConnectionError(endpoint_url="https://s3.eu-west-3.amazonaws.com"),
    ):
        severity = severitycheck.s3_force_destroy_severity_check("medium", "prod-backups")

    assert severity == "medium"


# Destroys and replacements.


def test_replacing_a_bucket_that_holds_objects_is_critical(s3: Stubber) -> None:
    s3.add_response("list_objects_v2", {"KeyCount": 1, "Contents": [{"Key": "a"}]})

    assert (
        severitycheck.destruction_severity_check("high", "aws_s3_bucket", "prod-backups")
        == "critical"
    )


def test_replacing_a_bucket_that_does_not_exist_is_low(s3: Stubber) -> None:
    """Bucket names are global: NoSuchBucket is true in every region and account."""
    s3.add_client_error("list_objects_v2", service_error_code="NoSuchBucket")

    assert severitycheck.destruction_severity_check("critical", "aws_s3_bucket", "gone") == "low"


def test_replacing_a_table_that_holds_items_is_critical(dynamodb: Stubber) -> None:
    dynamodb.add_response(
        "describe_table",
        {"Table": {"TableName": "orders", "ItemCount": 1200, "TableSizeBytes": 98304}},
        expected_params={"TableName": "orders"},
    )

    assert (
        severitycheck.destruction_severity_check("high", "aws_dynamodb_table", "orders")
        == "critical"
    )


def test_a_table_count_of_zero_does_not_lower_the_severity(dynamodb: Stubber) -> None:
    """DynamoDB refreshes its counts every six hours, so zero does not prove empty."""
    dynamodb.add_response(
        "describe_table", {"Table": {"TableName": "orders", "ItemCount": 0, "TableSizeBytes": 0}}
    )

    assert (
        severitycheck.destruction_severity_check("critical", "aws_dynamodb_table", "orders")
        == "critical"
    )


def test_a_table_absent_from_this_region_does_not_lower_the_severity(
    dynamodb: Stubber,
) -> None:
    """Tables are regional: absent here may mean it lives in another region."""
    dynamodb.add_client_error("describe_table", service_error_code="ResourceNotFoundException")

    assert (
        severitycheck.destruction_severity_check("critical", "aws_dynamodb_table", "orders")
        == "critical"
    )


def test_replacing_an_empty_repository_is_low(ecr: Stubber) -> None:
    # ECR omits imageIds for an empty repository; the response model forbids an empty list.
    ecr.add_response(
        "list_images",
        {},
        expected_params={"repositoryName": "api", "maxResults": 1},
    )

    assert severitycheck.destruction_severity_check("high", "aws_ecr_repository", "api") == "low"


def test_replacing_a_repository_that_holds_images_is_critical(ecr: Stubber) -> None:
    ecr.add_response("list_images", {"imageIds": [{"imageDigest": "sha256:" + "0" * 64}]})

    assert (
        severitycheck.destruction_severity_check("high", "aws_ecr_repository", "api") == "critical"
    )


def test_replacing_an_existing_database_keeps_the_static_severity(rds: Stubber) -> None:
    """RDS says a database exists, not what it holds."""
    rds.add_response("describe_db_instances", {"DBInstances": [{"DBInstanceIdentifier": "db"}]})

    assert severitycheck.destruction_severity_check("critical", "aws_db_instance", "db") == (
        "critical"
    )


def test_an_existing_redshift_cluster_without_final_snapshot_is_high(redshift: Stubber) -> None:
    redshift.add_response(
        "describe_clusters",
        {"Clusters": [{"ClusterIdentifier": "warehouse"}]},
        expected_params={"ClusterIdentifier": "warehouse"},
    )

    assert (
        severitycheck.skip_final_snapshot_severity_check(
            "medium", "aws_redshift_cluster", "warehouse"
        )
        == "high"
    )


def test_a_redshift_cluster_this_pr_creates_is_low(redshift: Stubber) -> None:
    redshift.add_client_error("describe_clusters", service_error_code="ClusterNotFound")

    assert (
        severitycheck.skip_final_snapshot_severity_check(
            "medium", "aws_redshift_cluster", "warehouse"
        )
        == "low"
    )


def test_a_destroy_of_a_type_with_no_lookup_asks_nothing(s3: Stubber) -> None:
    """The stub has no queued response, so any call would fail the test."""
    assert severitycheck.destruction_severity_check("high", "aws_instance", "web") == "high"
