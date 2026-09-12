"""Accès cloud optionnel, limité à sts:GetCallerIdentity et s3:ListObjectsV2. Aucun contenu de
bucket n'est lu."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


#: Les seules opérations que ce processus a le droit d'émettre, par service.
#: Toute autre est refusée avant l'envoi. Ajouter une entrée est une décision :
#: elle doit être en lecture seule, la politique IAM de
#: docs/cloud-read-access.md doit gagner l'action correspondante, et la page
#: d'accueil énumère cette liste au client.
_READ_ONLY_OPERATIONS: dict[str, frozenset[str]] = {
    "sts": frozenset({"GetCallerIdentity"}),
    "s3": frozenset({"ListObjectsV2"}),
}


class WriteAttempted(RuntimeError):
    """Une opération hors de `_READ_ONLY_OPERATIONS` a été tentée.

    Un défaut de programmation, donc la seule exception de ce module qui
    remonte au lieu d'être avalée.
    """


@dataclass(frozen=True, slots=True)
class Access:
    """La preuve qu'un accès en lecture a été ouvert."""

    account_id: str
    region: str


def _refuse_anything_but_reads(model: Any = None, **_kwargs: Any) -> None:
    """Gestionnaire `before-parameter-build` : la garde."""
    if model is None:  # pragma: no cover - botocore le fournit toujours
        return
    service = model.service_model.service_name
    if model.name not in _READ_ONLY_OPERATIONS.get(service, frozenset()):
        raise WriteAttempted(
            f"{service}:{model.name} n'est pas dans les opérations de lecture "
            f"autorisées — voir _READ_ONLY_OPERATIONS dans tfpdf/cloudread.py"
        )


def open_access(enabled: bool) -> tuple[Access | None, str]:
    """Ouvre l'accès en lecture, ou explique pourquoi il n'y en a pas."""
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

    # botocore ne lit que AWS_DEFAULT_REGION. AWS_REGION est celle que la
    # plupart des gens écrivent, et l'oublier fait partir les requêtes vers
    # us-east-1 sans rien dire — donc les deux sont acceptées ici.
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or ""
    if not region:
        return None, (
            "cloud read access requested but no region is set — "
            "set AWS_REGION (or AWS_DEFAULT_REGION) in the workflow"
        )

    # La session par défaut est posée et gardée avant le premier appel, pour
    # qu'aucune requête du processus — celle-ci comprise — ne parte non gardée.
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
    """La liste des appels que ce scan peut émettre, pour l'imprimer."""
    return ", ".join(sorted(_operation_names()))


def _operation_names() -> Iterator[str]:
    for service, operations in _READ_ONLY_OPERATIONS.items():
        for operation in operations:
            yield f"{service}:{operation}"
