"""Sous quel nom un scan est rapporté — et pourquoi il doit toujours en avoir un.

Le plan de contrôle exige `repo_full_name` : sans lui, `/v1/usage/scan` répond
400 et le CLI n'appelle même pas. Or ce nom ne venait que de `GITHUB_REPOSITORY`
ou `CI_PROJECT_PATH`, deux variables qu'un poste de travail n'a pas. Un scan
lancé à la main avec une clé de licence n'était donc **pas décompté du quota**,
et n'apparaissait dans aucun tableau de bord — sans le moindre message. Ces
tests tiennent le repli qui bouche ce trou, et le seul cas qui reste non
rapporté doit désormais le dire.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from httpstub import Request, Response, StubServer
from tfpdf.cli.forges import _repo_path_from_remote_url, repo_full_name
from tfpdf.cli.orgpolicy import report_usage
from tfpdf.report.finding import Category, Finding, Severity

#: Les variables qui nommeraient le dépôt à la place du repli. Effacées dans
#: chaque test : la suite tourne elle-même en CI, où elles sont posées, et un
#: test du repli qui lit `GITHUB_REPOSITORY` ne teste pas le repli.
_CI_VARS = ("GITHUB_REPOSITORY", "CI_PROJECT_PATH", "TFPDF_REPO_NAME")


@pytest.fixture(autouse=True)
def _no_ci_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _CI_VARS:
        monkeypatch.delenv(name, raising=False)


def _git(directory: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=directory, capture_output=True, check=True)


def _repo(tmp_path: Path, origin: str | None = "git@github.com:acme/infra.git") -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    (tmp_path / "main.tf").write_text(
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}'
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    if origin is not None:
        _git(tmp_path, "remote", "add", "origin", origin)
    return tmp_path


# --- lire l'URL d'un distant -------------------------------------------------


@pytest.mark.parametrize(
    ("url", "want"),
    [
        # Les trois formes que `git remote get-url` rend réellement, et le même
        # résultat pour les trois : c'est le point. Un dépôt cloné en SSH et le
        # même dépôt scanné par GitHub Actions doivent porter le MÊME nom, sans
        # quoi ils compteraient pour deux dépôts dans la limite du plan.
        ("git@github.com:acme/infra.git", "acme/infra"),
        ("https://github.com/acme/infra.git", "acme/infra"),
        ("ssh://git@github.com/acme/infra.git", "acme/infra"),
        ("https://github.com/acme/infra", "acme/infra"),
        # Un jeton dans l'URL — ce que pose un `git clone` de CI — ne doit pas
        # se retrouver dans le nom du dépôt.
        ("https://x-token:ghp_secret@github.com/acme/infra.git", "acme/infra"),
        # GitLab : le chemin est gardé entier, sous-groupes compris, parce que
        # c'est entier que `CI_PROJECT_PATH` le donne.
        ("git@gitlab.com:acme/platform/infra.git", "acme/platform/infra"),
        # Rien d'exploitable : un dépôt cloné depuis un dossier n'a aucune
        # identité que le plan de contrôle reconnaîtrait, et lui en inventer
        # une créerait un dépôt fantôme facturé au client.
        ("/home/me/infra", ""),
        ("../sibling.git", ""),
        ("C:/repos/infra", ""),
        ("https://github.com/acme", ""),
        ("", ""),
    ],
)
def test_the_repo_path_is_read_out_of_a_remote_url(url: str, want: str) -> None:
    assert _repo_path_from_remote_url(url) == want


# --- l'ordre des sources -----------------------------------------------------


def test_a_local_scan_is_named_after_its_origin_remote(tmp_path: Path) -> None:
    """Le trou lui-même : hors CI, ceci rendait "" et le scan n'était pas
    compté."""
    assert repo_full_name(str(_repo(tmp_path))) == "acme/infra"


def test_the_ci_variable_still_wins_over_the_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Là où la CI nomme le dépôt, elle reste l'autorité — le repli ne doit pas
    renommer les scans déjà rapportés et scinder l'historique d'un dépôt en
    deux."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/canonical")
    assert repo_full_name(str(_repo(tmp_path))) == "acme/canonical"


def test_an_explicit_name_wins_over_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/canonical")
    assert repo_full_name(str(_repo(tmp_path)), "acme/chosen") == "acme/chosen"


def test_a_repo_without_a_remote_has_no_name(tmp_path: Path) -> None:
    assert repo_full_name(str(_repo(tmp_path, origin=None))) == ""


def test_a_directory_that_is_not_a_repo_has_no_name(tmp_path: Path) -> None:
    """git échoue, et cela vaut « pas de nom » et non une erreur : un scan ne
    dépend pas de savoir se nommer."""
    assert repo_full_name(str(tmp_path)) == ""


# --- ce que le scan rapporte -------------------------------------------------


def _finding() -> Finding:
    return Finding(
        file="main.tf",
        line=1,
        category=Category.MISSING_LIFECYCLE,
        severity=Severity.HIGH,
        resource="aws_db_instance.prod",
        message="x",
    )


def test_a_named_scan_is_reported_and_counted() -> None:
    received: list[Request] = []

    def handler(request: Request) -> Response:
        received.append(request)
        return Response(body={"allowed": True})

    with StubServer(handler) as server:
        assert report_usage("test-key", server.url, [_finding()], False, "acme/infra") is False

    assert [r.path for r in received] == ["/v1/usage/scan"]
    assert received[0].body["repo_full_name"] == "acme/infra"
    assert received[0].body["finding_count"] == 1


def test_a_nameless_scan_reports_nothing_and_says_so(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Le seul chemin qui laisse encore un scan hors quota. Il doit être bruyant :
    un écart silencieux entre ce qu'une organisation consomme et ce que son
    tableau de bord montre est exactement le bug qu'on vient de corriger."""
    assert report_usage("test-key", "http://127.0.0.1:1", [_finding()], False, "") is False
    warning = capsys.readouterr().err
    assert "will NOT be counted" in warning
    assert "--repo-name" in warning


# --- le câblage, de bout en bout ---------------------------------------------


def test_a_local_scan_with_a_license_key_records_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Le scan que le trou laissait passer : un dépôt sur un poste, une clé de
    licence, aucune variable de CI.

    Les tests unitaires ci-dessus tiendraient tous alors même que `main` ne
    demanderait jamais le nom du dépôt. Celui-ci pilote la vraie ligne de
    commande et regarde ce qui part sur le fil.
    """
    from tfpdf.cli.main import main

    repo = _repo(tmp_path)
    received: list[Request] = []

    def handler(request: Request) -> Response:
        received.append(request)
        if request.path == "/v1/usage/scan":
            return Response(body={"allowed": True})
        # Politique, dérogations, packs de règles : tout échoue ouvert, donc un
        # 404 laisse le scan tourner sur sa configuration locale.
        return Response(status=404, body={})

    with StubServer(handler) as server:
        code = main(
            [
                "--repo-dir",
                str(repo),
                "--full-repo-scan",
                "--license-key",
                "test-key",
                "--license-api-base",
                server.url,
                "--post-comment=false",
            ]
        )

    capsys.readouterr()
    scans = [r for r in received if r.path == "/v1/usage/scan"]
    assert len(scans) == 1, f"le scan doit être rapporté une fois : {[r.path for r in received]}"
    assert scans[0].body["repo_full_name"] == "acme/infra"
    assert code in (0, 1)
