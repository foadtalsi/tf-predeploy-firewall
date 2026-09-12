"""Optional AWS access limited to sts:GetCallerIdentity and s3:ListObjectsV2; never read object
contents.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


# Allowed AWS operations. Any addition must be read-only and documented in
# docs/cloud-read-access.md and its IAM example.
_READ_ONLY_OPERATIONS: dict[str, frozenset[str]] = {
    "sts": frozenset({"GetCallerIdentity"}),
    "s3": frozenset({"ListObjectsV2"}),
}


class WriteAttempted(RuntimeError):
    """An operation outside the read-only allowlist. Propagate this programming error instead of
    hiding it.
    """


@dataclass(frozen=True, slots=True)
class Access:
    """A successfully opened read-only cloud access session."""

    account_id: str
    region: str


def _refuse_anything_but_reads(model: Any = None, **_kwargs: Any) -> None:
    """Reject disallowed operations before botocore builds request parameters."""
    if model is None:  # pragma: no cover - botocore always supplies the model
        return
    service = model.service_model.service_name
    if model.name not in _READ_ONLY_OPERATIONS.get(service, frozenset()):
        raise WriteAttempted(
            f"{service}:{model.name} is not an allowed read-only operation "
            f"— see _READ_ONLY_OPERATIONS in tfpdf/cloudread.py"
        )


def open_access(enabled: bool) -> tuple[Access | None, str]:
    """Open read-only access or explain why it is unavailable."""
    if not enabled:
        return None, ""

    try:
        import boto3
    except ImportError:
        return None, (
            "cloud read access requested but boto3 is not installed — "
            "install the extra with "
            '`pip install "tf-predeploy-firewall[aws] @ '
            'git+https://github.com/foadtalsi/tf-predeploy-firewall@v1"` '
            "(the published Action image already has it)"
        )

    # Accept AWS_REGION as well as botocore's AWS_DEFAULT_REGION.
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or ""
    if not region:
        return None, (
            "cloud read access requested but no region is set — "
            "set AWS_REGION (or AWS_DEFAULT_REGION) in the workflow"
        )

    # Guard the default session before the first request so every operation is checked.
    boto3.setup_default_session(region_name=region)
    boto3.DEFAULT_SESSION.events.register("before-parameter-build", _refuse_anything_but_reads)

    from botocore.exceptions import BotoCoreError, ClientError

    try:
        identity = boto3.client("sts").get_caller_identity()
    except (ClientError, BotoCoreError) as error:
        return None, (
            f"cloud read access requested but no usable credentials were found "
            f"({type(error).__name__}) — the scan continues without it"
        )

    account_id = str(identity.get("Account", ""))
    return Access(account_id=account_id, region=region), (
        f"cloud read access active on account {account_id} in {region} "
        f"(read-only: {permission_summary()})"
    )


def permission_summary() -> str:
    """Describe the API calls this scan may make."""
    return ", ".join(sorted(_operation_names()))


def _operation_names() -> Iterator[str]:
    for service, operations in _READ_ONLY_OPERATIONS.items():
        for operation in operations:
            yield f"{service}:{operation}"
