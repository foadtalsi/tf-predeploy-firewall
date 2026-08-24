"""L'accès en lecture seule au compte cloud.

Sans équivalent Go : la fonctionnalité n'existe que dans le port. Ce qui est
épinglé ici est ce sur quoi repose la phrase vendue au client — la garde
refuse vraiment une écriture, elle s'applique au code qui interroge réellement
AWS, et rien de ce qui peut mal tourner dehors ne fait rougir un scan.
"""

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from tfpdf.cloudread import Access, WriteAttempted, open_access, permission_summary


@pytest.fixture
def granted(monkeypatch: pytest.MonkeyPatch) -> Access:
    """Un accès ouvert par le vrai `open_access`, garde comprise.

    Les tests de la garde passent par ici plutôt que de monter leur propre
    session : sinon ils prouveraient que le gestionnaire fonctionne sans rien
    prouver de son installation, et retirer le `register` d'`open_access` les
    laisserait tous verts.
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
    # Le double de STS a servi à ouvrir l'accès ; le retirer rend aux clients
    # suivants leur comportement normal, garde comprise.
    monkeypatch.undo()
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "clé-de-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-de-test")
    return access


# --- la garde ---------------------------------------------------------------


def test_a_write_call_is_refused_before_it_leaves_the_process(granted: Access) -> None:
    """Le test qui donne son sens à la phrase « lecture seule ».

    Ni un stub ni un client hors ligne : le vrai botocore, et l'appel meurt
    avant qu'une socket s'ouvre. Sans la garde, cette requête part réellement
    — la saboter fait échouer ce test avec une erreur venue d'AWS.
    """
    import boto3

    with pytest.raises(WriteAttempted, match="s3:PutObject"):
        boto3.client("s3").put_object(Bucket="peu-importe", Key="k", Body=b"x")


def test_a_delete_call_is_refused_too(granted: Access) -> None:
    """Le cas qui coûte cher si la garde ne couvre que ce à quoi on a pensé."""
    import boto3

    with pytest.raises(WriteAttempted, match="s3:DeleteBucket"):
        boto3.client("s3").delete_bucket(Bucket="peu-importe")


def test_a_read_that_is_not_on_the_list_is_refused(granted: Access) -> None:
    """`GetObject` lit, et reste refusé : la garde autorise les opérations dont
    le scanner a besoin, pas la catégorie « lecture ». C'est ce qui permet de
    dire au client que le scan ne peut pas lire le contenu de ses
    compartiments, et pas seulement qu'il ne le fait pas."""
    import boto3

    with pytest.raises(WriteAttempted, match="s3:GetObject"):
        boto3.client("s3").get_object(Bucket="peu-importe", Key="k")


def test_the_guard_covers_a_client_the_severity_check_makes_itself(
    granted: Access,
) -> None:
    """Le test qui compte le plus.

    `ruledef.severitycheck` est le code qui interroge réellement AWS, et il
    construit son propre client avec `boto3.client("s3")` — il ne passe par
    aucun objet de ce module. La garde n'aurait donc rien protégé si elle
    n'était posée que sur une session à nous. Elle est posée sur la session
    *par défaut* de boto3, qui est celle que ce `boto3.client` utilise.
    """
    import boto3
    import botocore.client

    from tfpdf.ruledef import severitycheck

    # `GetCallerIdentity` seul est simulé, et au niveau où la garde est déjà
    # passée : tout le reste emprunte le vrai chemin botocore, sans quoi ce
    # test contournerait précisément ce qu'il vérifie.
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

    # Et le client du module lui-même, sur la même session.
    with pytest.raises(WriteAttempted, match="s3:CreateBucket"):
        boto3.client("s3").create_bucket(Bucket="peu-importe")


def test_the_call_the_severity_check_actually_makes_is_allowed(granted: Access) -> None:
    """La contrepartie : une garde qui refuse tout serait verte aux tests
    ci-dessus et casserait la fonctionnalité."""
    import boto3
    from botocore.stub import Stubber

    client = boto3.client("s3")
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", {"KeyCount": 0})
        client.list_objects_v2(Bucket="b", MaxKeys=1)


# --- open_access ------------------------------------------------------------


def test_not_asking_for_it_builds_nothing_and_says_nothing() -> None:
    """Le chemin par défaut, celui de tous ceux qui n'activent pas l'option :
    aucun identifiant lu, aucune requête, et rien à imprimer."""
    assert open_access(False) == (None, "")


def test_asking_without_a_region_explains_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    access, note = open_access(True)
    assert access is None
    assert "no region is set" in note


def test_aws_region_alone_is_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    """botocore ne lit que `AWS_DEFAULT_REGION`. `AWS_REGION` est celle que la
    plupart des gens écrivent, et ne pas la reconnaître envoie chaque requête
    vers us-east-1 sans le dire."""
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
    """Le principe qui rend l'option adoptable : un rôle expiré dégrade le
    scan, il ne le casse pas."""
    monkeypatch.setenv("AWS_REGION", "eu-west-3")

    def refused(self: Any, *args: Any, **kwargs: Any) -> None:
        raise ClientError({"Error": {"Code": "ExpiredToken"}}, "GetCallerIdentity")

    monkeypatch.setattr("botocore.client.BaseClient._make_api_call", refused)
    access, note = open_access(True)
    assert access is None
    assert "no usable credentials" in note


def test_the_note_lists_what_the_scan_may_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ce que le client lit dans son journal de CI doit être la liste réelle,
    dérivée de la table qui fait foi — pas une phrase écrite à côté qui
    vieillit dès qu'une opération s'ajoute."""
    monkeypatch.setenv("AWS_REGION", "eu-west-3")
    monkeypatch.setattr(
        "botocore.client.BaseClient._make_api_call",
        lambda self, *a, **k: {"Account": "1"},
    )
    _, note = open_access(True)
    assert permission_summary() in note
    for expected in ("sts:GetCallerIdentity", "s3:ListObjectsV2"):
        assert expected in note
