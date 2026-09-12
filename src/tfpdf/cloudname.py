"""Le nom qu'une ressource portera réellement chez le fournisseur."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .parser import Kind

if TYPE_CHECKING:
    from .parser import Resource


#: type de ressource -> attribut qui porte le nom réel chez le fournisseur.
NAME_ATTRIBUTE_BY_TYPE: dict[str, str] = {
    "aws_s3_bucket": "bucket",
    "aws_db_instance": "identifier",
    "aws_rds_cluster": "cluster_identifier",
    "aws_elasticache_cluster": "cluster_id",
    "aws_dynamodb_table": "name",
    "aws_lambda_function": "function_name",
    "aws_sqs_queue": "name",
    "aws_sns_topic": "name",
    "aws_ecr_repository": "name",
    "aws_secretsmanager_secret": "name",
    "aws_cloudwatch_log_group": "name",
    "aws_iam_role": "name",
    "azurerm_storage_account": "name",
    "azurerm_resource_group": "name",
}


def of(resource: Resource) -> str:
    """Le nom réel de `resource`, ou "" si on ne peut pas l'affirmer."""
    if resource.kind is not Kind.RESOURCE:
        return ""

    attribute_name = NAME_ATTRIBUTE_BY_TYPE.get(resource.type)
    if attribute_name is None:
        return ""

    attribute = resource.attributes.get(attribute_name)
    if attribute is None or not attribute.is_literal or not attribute.raw_value:
        return ""
    return attribute.raw_value
