"""L'accès en lecture seule au compte cloud, quand le client en accorde un.

Le scanner par défaut ne s'authentifie à rien : il lit les fichiers .tf du
dépôt contre un schéma qu'il embarque déjà. Cette propriété reste vraie, et
c'est le chemin qu'emprunte quiconque n'active pas `--cloud-read-access`.

Ce module ne juge rien et n'interroge rien lui-même. Il fait trois choses, et
c'est tout ce qui sépare « on a le droit de regarder » de « on regarde » :

1. **Décider si l'accès existe.** Identifiants utilisables ou non, région
   connue ou non. Sans accès, `tfpdf.rules.engine` ne demande rien à personne.
2. **Poser la garde de lecture seule.** Un gestionnaire botocore sur la session
   *par défaut* de boto3 refuse toute opération absente de
   `_READ_ONLY_OPERATIONS` avant que la requête soit construite. La session par
   défaut est celle qu'utilise n'importe quel `boto3.client(...)` du
   processus — y compris ceux que crée `ruledef.severitycheck`, qui est le
   code qui interroge réellement AWS. C'est ce qui fait que « lecture seule »
   est une propriété du programme et non une phrase de documentation.
3. **Le dire.** Une ligne sur stderr nommant le compte atteint et les appels
   permis, dérivée de la table elle-même, pour que la personne qui a activé
   l'option sache ce que son scan a le droit de faire.

Rien ici ne lève dans un scan : identifiants absents, permission refusée,
boto3 pas installé, tout cela rend « pas d'accès », et le scan continue comme
si l'option n'avait jamais été demandée. La seule exception est
`WriteAttempted`, qui signale un défaut du scanner et non une condition
d'exécution — confondre les deux ferait passer « ce code appelle une
écriture » pour « le client n'a pas donné assez de droits ».
"""

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
    """La preuve qu'un accès en lecture a été ouvert.

    Ne porte aucune méthode d'interrogation : ce qui interroge le cloud est
    `ruledef.severitycheck`, et cet objet dit seulement qu'il a le droit de le
    faire. Le moteur le traite comme un jeton — présent ou absent.
    """

    account_id: str
    region: str


def _refuse_anything_but_reads(model: Any = None, **_kwargs: Any) -> None:
    """Gestionnaire `before-parameter-build` : la garde.

    Voit toutes les requêtes de tous les clients issus de la session sur
    laquelle il est posé, y compris ceux qu'un code futur créerait sans avoir
    lu ce fichier. C'est ce qui fait que la garantie survit aux modifications.
    """
    if model is None:  # pragma: no cover - botocore le fournit toujours
        return
    service = model.service_model.service_name
    if model.name not in _READ_ONLY_OPERATIONS.get(service, frozenset()):
        raise WriteAttempted(
            f"{service}:{model.name} n'est pas dans les opérations de lecture "
            f"autorisées — voir _READ_ONLY_OPERATIONS dans tfpdf/cloudread.py"
        )


def open_access(enabled: bool) -> tuple[Access | None, str]:
    """Ouvre l'accès en lecture, ou explique pourquoi il n'y en a pas.

    Rend `(None, raison)` dans tous les cas d'échec. La raison est faite pour
    être imprimée : quelqu'un qui a activé l'option et ne voit rien changer
    doit apprendre pourquoi sans lire ce fichier.
    """
    if not enabled:
        return None, ""

    try:
        import boto3
    except ImportError:
        return None, (
            "cloud read access requested but boto3 is not installed — "
            'install the extra with `pip install "tf-predeploy-firewall[aws]"` '
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
    """La liste des appels que ce scan peut émettre, pour l'imprimer.

    Dérivée de `_READ_ONLY_OPERATIONS` plutôt que réécrite à la main : une
    opération ajoutée sans mettre le message à jour dirait au client moins que
    ce que le scanner fait réellement.
    """
    return ", ".join(sorted(_operation_names()))


def _operation_names() -> Iterator[str]:
    for service, operations in _READ_ONLY_OPERATIONS.items():
        for operation in operations:
            yield f"{service}:{operation}"
