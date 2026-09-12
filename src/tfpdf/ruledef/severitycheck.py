import boto3
from botocore.exceptions import ClientError

# Optional cloud observations used to adjust finding severity.
s3 = None
AWS_OK = None


# Probe once per scan and cache AWS_OK. Before a probe, checks preserve the static severity.
def available_context() -> bool:
    """Probe AWS once and cache the S3 client; return whether access is available."""
    global s3, AWS_OK
    try:
        boto3.client("sts").get_caller_identity()
        s3 = boto3.client("s3")
        AWS_OK = True
    except Exception:
        AWS_OK = False
    return AWS_OK


def s3_force_destroy_severity_check(severity: str, bucket: str) -> str:
    """Return low for an absent/empty bucket, critical for objects, or the original severity."""
    # A missing client must preserve severity, including when a check runs without a prior
    # probe.
    if not AWS_OK or s3 is None:
        return severity

    objects_counts = 0
    try:
        info = s3.list_objects_v2(Bucket=bucket)
    except ClientError as error:
        code = error.response["Error"]["Code"]
        if code == "NoSuchBucket":
            severity = "low"
            return severity
        return severity

    for objects in info.get("Contents", []):
        if objects["Key"]:
            objects_counts += 1

    if info.get("Contents", []) == []:
        severity = "low"
        return severity
    if objects_counts >= 1:
        return "critical"

    return severity
