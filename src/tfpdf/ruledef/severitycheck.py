from enum import StrEnum

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Optional cloud observations used to adjust finding severity.
s3 = None
rds = None
dynamodb = None
ecr = None
redshift = None
AWS_OK = None


class Contents(StrEnum):
    """What AWS says about the resource a finding is about."""

    #: AWS answered that nothing by this name exists.
    ABSENT = "absent"
    #: The resource exists and AWS confirms it holds nothing.
    EMPTY = "empty"
    #: The resource exists and AWS confirms it holds data.
    HOLDS_DATA = "holds_data"
    #: The resource exists, but AWS does not say whether it holds data.
    EXISTS = "exists"
    #: No lookup was possible, or its answer could not be interpreted.
    UNKNOWN = "unknown"


# S3 bucket names are global: NoSuchBucket is true in every region and every account. Every other
# type below is looked up in the runner's account and region only, so "absent" there may just mean
# "somewhere else", and it is never used to lower a destruction finding.
GLOBALLY_NAMED_TYPES = frozenset({"aws_s3_bucket"})

# Every type observe_contents can look up.
OBSERVABLE_TYPES = frozenset(
    {
        "aws_s3_bucket",
        "aws_dynamodb_table",
        "aws_ecr_repository",
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_docdb_cluster",
        "aws_neptune_cluster",
        "aws_redshift_cluster",
    }
)

# DocumentDB and Neptune clusters are served by the RDS control plane, so DescribeDBClusters
# answers for all three.
_RDS_CLUSTER_TYPES = frozenset({"aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster"})


# Probe once per scan and cache AWS_OK. Before a probe, checks preserve the static severity.
def available_context() -> bool:
    """Probe AWS once and cache the service clients; return whether access is available"""
    global s3, rds, dynamodb, ecr, redshift, AWS_OK
    try:
        boto3.client("sts").get_caller_identity()
        s3 = boto3.client("s3")
        rds = boto3.client("rds")
        dynamodb = boto3.client("dynamodb")
        ecr = boto3.client("ecr")
        redshift = boto3.client("redshift")
        AWS_OK = True
    except Exception:
        AWS_OK = False
    return AWS_OK


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", ""))


def observe_contents(resource_type: str, name: str) -> Contents:
    """Ask AWS whether the named resource exists and whether it holds data"""
    if not AWS_OK or not name:
        return Contents.UNKNOWN
    try:
        if resource_type == "aws_s3_bucket":
            return _observe_bucket(name)
        if resource_type == "aws_dynamodb_table":
            return _observe_table(name)
        if resource_type == "aws_ecr_repository":
            return _observe_repository(name)
        if resource_type == "aws_db_instance":
            return _observe_db_instance(name)
        if resource_type in _RDS_CLUSTER_TYPES:
            return _observe_db_cluster(name)
        if resource_type == "aws_redshift_cluster":
            return _observe_redshift_cluster(name)
    except BotoCoreError:
        # A network or endpoint failure proves nothing about the resource.
        return Contents.UNKNOWN
    return Contents.UNKNOWN


def _observe_bucket(bucket: str) -> Contents:
    if s3 is None:
        return Contents.UNKNOWN
    try:
        listing = s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
    except ClientError as error:
        if _error_code(error) == "NoSuchBucket":
            return Contents.ABSENT
        return Contents.UNKNOWN
    if listing.get("KeyCount", 0) > 0 or listing.get("Contents"):
        return Contents.HOLDS_DATA

    # No current object is not the same as empty: a versioned bucket can hold only noncurrent
    # versions, and force_destroy deletes those too.
    try:
        versions = s3.list_object_versions(Bucket=bucket)
    except ClientError as error:
        if _error_code(error) == "NoSuchBucket":
            return Contents.ABSENT
        return Contents.UNKNOWN
    if versions.get("Versions"):
        return Contents.HOLDS_DATA
    if versions.get("IsTruncated"):
        # A full page of delete markers: versions may follow on the next page.
        return Contents.UNKNOWN
    return Contents.EMPTY


def _observe_table(table: str) -> Contents:
    if dynamodb is None:
        return Contents.UNKNOWN
    try:
        description = dynamodb.describe_table(TableName=table)["Table"]
    except ClientError as error:
        if _error_code(error) == "ResourceNotFoundException":
            return Contents.ABSENT
        return Contents.UNKNOWN
    if description.get("ItemCount", 0) > 0 or description.get("TableSizeBytes", 0) > 0:
        return Contents.HOLDS_DATA
    # DynamoDB refreshes these counts about every six hours, so zero does not prove empty.
    return Contents.EXISTS


def _observe_repository(repository: str) -> Contents:
    if ecr is None:
        return Contents.UNKNOWN
    try:
        listing = ecr.list_images(repositoryName=repository, maxResults=1)
    except ClientError as error:
        if _error_code(error) == "RepositoryNotFoundException":
            return Contents.ABSENT
        return Contents.UNKNOWN
    if listing.get("imageIds"):
        return Contents.HOLDS_DATA
    return Contents.EMPTY


def _observe_db_instance(identifier: str) -> Contents:
    if rds is None:
        return Contents.UNKNOWN
    try:
        rds.describe_db_instances(DBInstanceIdentifier=identifier)
    except ClientError as error:
        if _error_code(error) == "DBInstanceNotFound":
            return Contents.ABSENT
        return Contents.UNKNOWN
    return Contents.EXISTS


def _observe_db_cluster(identifier: str) -> Contents:
    if rds is None:
        return Contents.UNKNOWN
    try:
        rds.describe_db_clusters(DBClusterIdentifier=identifier)
    except ClientError as error:
        if _error_code(error) == "DBClusterNotFoundFault":
            return Contents.ABSENT
        return Contents.UNKNOWN
    return Contents.EXISTS


def _observe_redshift_cluster(identifier: str) -> Contents:
    if redshift is None:
        return Contents.UNKNOWN
    try:
        redshift.describe_clusters(ClusterIdentifier=identifier)
    except ClientError as error:
        if _error_code(error) == "ClusterNotFound":
            return Contents.ABSENT
        return Contents.UNKNOWN
    return Contents.EXISTS


def s3_force_destroy_severity_check(severity: str, bucket: str) -> str:
    """Return low for an absent/empty bucket, critical for objects, or the original severity"""
    contents = observe_contents("aws_s3_bucket", bucket)
    if contents in (Contents.ABSENT, Contents.EMPTY):
        return "low"
    if contents is Contents.HOLDS_DATA:
        return "critical"
    return severity


def skip_final_snapshot_severity_check(severity: str, resource_type: str, identifier: str) -> str:
    """Return low for a missing database, high for an existing one, or the original severity"""
    if resource_type not in ("aws_db_instance", "aws_redshift_cluster", *_RDS_CLUSTER_TYPES):
        return severity
    contents = observe_contents(resource_type, identifier)
    if contents is Contents.ABSENT:
        # This PR creates the database, so a destroy has nothing to lose yet.
        return "low"
    if contents in (Contents.EXISTS, Contents.HOLDS_DATA):
        # The database exists: destroying it without a final snapshot loses its data for good.
        return "high"
    return severity


def destruction_severity_check(severity: str, resource_type: str, name: str) -> str:
    """Rate a destroy or replace by what it would actually destroy: critical when the resource
    holds data, low when it is confirmed empty or (for globally named types) does not exist, the
    original severity otherwise"""
    if resource_type not in OBSERVABLE_TYPES:
        return severity
    contents = observe_contents(resource_type, name)
    if contents is Contents.HOLDS_DATA:
        return "critical"
    if contents is Contents.EMPTY:
        return "low"
    if contents is Contents.ABSENT and resource_type in GLOBALLY_NAMED_TYPES:
        return "low"
    return severity
