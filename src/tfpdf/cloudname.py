"""Le nom qu'une ressource portera réellement chez le fournisseur.

`Resource.address()` rend `aws_s3_bucket.backups` : l'identifiant *logique*,
celui qu'emploie Terraform. Aucune API cloud ne le connaît. Ce qu'une API
connaît est `prod-backups`, la valeur de l'attribut qui nomme la ressource — et
cet attribut ne s'appelle pas pareil selon le type : `bucket` pour un
compartiment S3, `identifier` pour une base RDS, `function_name` pour une
lambda.

D'où cette table. Elle est explicite et **sans valeur par défaut**, ce qui est
le point délicat : se rabattre sur `name` paraît raisonnable jusqu'à
`aws_db_instance`, où `name` désigne la base de données créée à l'intérieur de
l'instance et non l'instance elle-même. Une vérification qui interrogerait le
cloud avec cette valeur recevrait « cet objet n'existe pas », et le code qui
s'en sert baisserait la sévérité — exactement le sens dangereux de l'erreur.
Un type absent de la table rend une chaîne vide, que l'appelant doit traiter
comme « je ne sais pas ».

La table est courte volontairement : ce sont les types pour lesquels
l'affirmation a été vérifiée. L'allonger est une ligne, mais chaque ligne est
une affirmation sur le schéma d'un fournisseur.
"""

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
    """Le nom réel de `resource`, ou "" si on ne peut pas l'affirmer.

    Trois façons de ne pas savoir, toutes rendues de la même manière parce que
    l'appelant doit en faire la même chose :

    - le type n'est pas dans la table ;
    - l'attribut n'est pas écrit ;
    - sa valeur n'est pas littérale — elle peut venir d'un `var.x` ou d'un
      `local.y` que le moteur a déjà résolu, mais un nom construit à
      l'exécution (`"${var.env}-backups"` sans portée) ne se demande à
      personne.

    Seuls les blocs `resource` en ont un : un `data` lit une ressource qui
    existe déjà et un `module` n'est pas une ressource.
    """
    if resource.kind is not Kind.RESOURCE:
        return ""

    attribute_name = NAME_ATTRIBUTE_BY_TYPE.get(resource.type)
    if attribute_name is None:
        return ""

    attribute = resource.attributes.get(attribute_name)
    if attribute is None or not attribute.is_literal or not attribute.raw_value:
        return ""
    return attribute.raw_value
