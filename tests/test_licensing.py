"""Port des quatre fichiers de test de internal/licensing, cas pour cas :
client_test.go, policy_test.go, waivers_test.go et rulepacks_test.go.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from httpstub import Request, Response, StubServer
from tfpdf import licensing
from tfpdf.licensing import (
    PACK_CACHE_TTL_SECONDS,
    FindingSummary,
    LicensingError,
    ScanResult,
    cache_fresh,
    new_client,
    pack_file_name,
)

# --- client.go ---------------------------------------------------------------


def test_record_scan_allowed() -> None:
    def handler(r: Request) -> Response:
        assert r.headers["Authorization"] == "Bearer test-key"
        assert r.body is not None
        assert r.body["repo_full_name"] == "acme/infra"
        return Response(body={"allowed": True})

    with StubServer(handler) as srv:
        client = new_client("test-key", srv.url)
        allowed, _ = client.record_scan(
            ScanResult(repo_full_name="acme/infra", finding_count=3, blocked=False)
        )
    assert allowed is True


def test_record_scan_sends_finding_detail() -> None:
    """Empêche le tableau de bord de revenir en silence à n'afficher qu'un
    décompte nu : ScanResult ne portait autrefois que finding_count, si bien
    qu'un administrateur qui descendait dans un scan n'avait aucun moyen de voir
    ce qui avait réellement été trouvé."""
    captured: dict[str, object] = {}

    def handler(r: Request) -> Response:
        captured["body"] = r.body
        return Response(body={"allowed": True})

    with StubServer(handler) as srv:
        new_client("test-key", srv.url).record_scan(
            ScanResult(
                repo_full_name="acme/infra",
                finding_count=1,
                blocked=True,
                findings=[
                    FindingSummary(
                        category="missing_lifecycle",
                        severity="critical",
                        resource="aws_db_instance.primary",
                        file_path="database.tf",
                        line=3,
                        message="missing prevent_destroy",
                    )
                ],
            )
        )

    body = captured["body"]
    assert isinstance(body, dict)
    assert len(body["findings"]) == 1
    assert body["findings"][0] == {
        "category": "missing_lifecycle",
        "severity": "critical",
        "resource": "aws_db_instance.primary",
        "file": "database.tf",
        "line": 3,
        "message": "missing prevent_destroy",
    }


def test_record_scan_omits_findings_when_there_are_none() -> None:
    """`omitempty` du côté Go. Envoyer `"findings": []` au lieu d'omettre la
    clé est un document différent, et le plan de contrôle est celui de la
    version Go."""
    captured: dict[str, object] = {}

    def handler(r: Request) -> Response:
        captured["body"] = r.body
        return Response(body={"allowed": True})

    with StubServer(handler) as srv:
        new_client("test-key", srv.url).record_scan(ScanResult(repo_full_name="acme/infra"))

    body = captured["body"]
    assert isinstance(body, dict)
    assert "findings" not in body


def test_record_scan_quota_exceeded() -> None:
    handler = lambda r: Response(  # noqa: E731
        body={"allowed": False, "reason": "plan quota exceeded"}
    )
    with StubServer(handler) as srv:
        allowed, reason = new_client("test-key", srv.url).record_scan(
            ScanResult(repo_full_name="acme/infra")
        )
    assert allowed is False
    assert reason == "plan quota exceeded"


def test_record_scan_unauthorized() -> None:
    with (
        StubServer(lambda r: Response(status=401, body={})) as srv,
        pytest.raises(LicensingError, match="invalid or revoked API key"),
    ):
        new_client("bad-key", srv.url).record_scan(ScanResult(repo_full_name="acme/infra"))


def test_record_scan_server_error() -> None:
    with (
        StubServer(lambda r: Response(status=500, body="internal error")) as srv,
        pytest.raises(LicensingError, match="500"),
    ):
        new_client("test-key", srv.url).record_scan(ScanResult(repo_full_name="acme/infra"))


# --- policy.go ---------------------------------------------------------------


def test_get_policy_no_policy_set() -> None:
    """Le plan de contrôle rend un objet vide quand aucune politique
    n'existe."""
    with StubServer(lambda r: Response(body={})) as srv:
        assert new_client("test-key", srv.url).get_policy("") is None


def test_get_policy_with_overrides() -> None:
    custom_rules = (
        "custom_rules:\n  - id: no-iam-users\n    resource_type: aws_iam_user\n"
        "    severity: medium\n    message: x\n"
    )

    def handler(r: Request) -> Response:
        assert r.headers["Authorization"] == "Bearer test-key"
        return Response(
            body={
                "block_threshold": "critical",
                "ignore_rules": ["tutorial_pattern"],
                "plan_blast_radius_threshold": 5,
                "custom_rules_yaml": custom_rules,
            }
        )

    with StubServer(handler) as srv:
        policy = new_client("test-key", srv.url).get_policy("")

    assert policy is not None
    assert policy.block_threshold == "critical"
    assert policy.ignore_rules == ["tutorial_pattern"]
    assert policy.plan_blast_radius_threshold == 5
    assert policy.custom_rules_yaml is not None
    assert "no-iam-users" in policy.custom_rules_yaml


def test_get_policy_sends_repo_query_param() -> None:
    """Protège la capacité du plan de contrôle à fusionner une surcharge propre
    à un dépôt par-dessus la politique de l'organisation : il ne peut le faire
    que si le CLI lui dit réellement quel dépôt scanne."""
    with StubServer(lambda r: Response(body={})) as srv:
        new_client("test-key", srv.url).get_policy("acme/infra")
        assert srv.requests[0].query["repo"] == ["acme/infra"]


def test_get_policy_unauthorized() -> None:
    with StubServer(lambda r: Response(status=401, body={})) as srv, pytest.raises(LicensingError):
        new_client("bad-key", srv.url).get_policy("")


def test_an_explicitly_empty_override_is_not_the_same_as_no_override() -> None:
    """`ignore_rules: []` est une instruction — « remplace la liste locale par
    rien ». Une clé absente n'en est pas une. Go les distingue par une tranche
    nulle ; le port doit garder cela, sinon une politique qui vide délibérément
    la liste d'ignorés locale se lirait comme aucune politique du tout et la
    laisserait en place."""
    with StubServer(lambda r: Response(body={"ignore_rules": []})) as srv:
        policy = new_client("k", srv.url).get_policy("")
    assert policy is not None, "an explicit empty list is still a policy"
    assert policy.ignore_rules == []


# --- waivers.go --------------------------------------------------------------


def test_get_waivers_sends_repo_query_param_and_parses_response() -> None:
    def handler(r: Request) -> Response:
        assert r.headers["Authorization"] == "Bearer test-key"
        return Response(
            body=[
                {
                    "category": "missing_lifecycle",
                    "resource": "aws_db_instance.legacy",
                    "file": "main.tf",
                    "justification": "ticketed in INFRA-42",
                }
            ]
        )

    with StubServer(handler) as srv:
        waivers = new_client("test-key", srv.url).get_waivers("acme/infra")
        assert srv.requests[0].query["repo"] == ["acme/infra"]

    assert len(waivers) == 1
    assert waivers[0].justification == "ticketed in INFRA-42"
    assert waivers[0].file_path == "main.tf", 'the wire field is "file"'


def test_get_waivers_empty_when_none_configured() -> None:
    with StubServer(lambda r: Response(body=[])) as srv:
        assert new_client("test-key", srv.url).get_waivers("acme/infra") == []


def test_get_waivers_unauthorized() -> None:
    with StubServer(lambda r: Response(status=401, body={})) as srv, pytest.raises(LicensingError):
        new_client("bad-key", srv.url).get_waivers("acme/infra")


# --- rulepacks.go ------------------------------------------------------------


@pytest.fixture
def isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isole le cache de packs dans un répertoire temporaire, pour que les tests
    ne touchent jamais celui du développeur."""
    monkeypatch.setenv("TFPDF_CACHE_DIR", str(tmp_path))
    return tmp_path / "rulepacks"


def _seed_cache(dir_: Path, provider: str, body: str, etag: str, age_seconds: float) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    pack_path = dir_ / pack_file_name(provider, ".pack.gz")
    pack_path.write_bytes(body.encode())
    (dir_ / pack_file_name(provider, ".etag")).write_text(etag)
    when = time.time() - age_seconds
    os.utime(pack_path, (when, when))


def test_fetch_rule_pack_downloads_and_caches(isolated_cache: Path) -> None:
    def handler(r: Request) -> Response:
        assert r.headers["Authorization"] == "Bearer test-key"
        return Response(raw=b"PACKBODY", headers={"ETag": '"v1"'})

    with StubServer(handler) as srv:
        client = new_client("test-key", srv.url)

        pack, exception = client.fetch_rule_pack("aws")
        assert exception is None
        assert pack is not None
        assert pack.data == b"PACKBODY"
        assert pack.etag == '"v1"'
        assert not pack.from_cache, "the first fetch is not cached"

        assert (isolated_cache / "aws.pack.gz").read_bytes() == b"PACKBODY"

        # A second call inside the TTL must not hit the network at all.
        again, err2 = client.fetch_rule_pack("aws")
        assert err2 is None
        assert again is not None and again.from_cache
        assert srv.calls == 1, "the cache must serve the second call"


def test_fetch_rule_pack_revalidates_with_etag_after_ttl(isolated_cache: Path) -> None:
    seen: dict[str, str] = {}

    def handler(r: Request) -> Response:
        seen["if_none_match"] = r.headers.get("If-None-Match", "")
        return Response(status=304)

    _seed_cache(isolated_cache, "aws", "CACHEDBODY", '"v1"', 2 * PACK_CACHE_TTL_SECONDS)

    with StubServer(handler) as srv:
        pack, exception = new_client("test-key", srv.url).fetch_rule_pack("aws")

    assert exception is None
    assert seen["if_none_match"] == '"v1"'
    assert pack is not None
    assert pack.data == b"CACHEDBODY", "a 304 reuses the cached body"
    assert pack.from_cache
    # The 304 refreshed the timestamp, so the next call skips the network.
    assert cache_fresh(isolated_cache, "aws")


def test_fetch_rule_pack_falls_back_to_cache_when_service_is_down(
    isolated_cache: Path,
) -> None:
    """La promesse centrale de ce chemin : une panne coûte de la couverture,
    jamais une coche rouge."""
    _seed_cache(isolated_cache, "aws", "CACHEDBODY", '"v1"', 2 * PACK_CACHE_TTL_SECONDS)

    with StubServer(lambda r: Response(status=500, raw=b"boom")) as srv:
        pack, exception = new_client("test-key", srv.url).fetch_rule_pack("aws")

    assert pack is not None, "the cached pack must be used despite the outage"
    assert pack.data == b"CACHEDBODY"
    assert pack.from_cache
    assert exception is not None, "the fallback is still reported, so the scan can warn"


def test_fetch_rule_pack_no_cache_and_service_down_returns_error(
    isolated_cache: Path,
) -> None:
    with StubServer(lambda r: Response(status=500, raw=b"boom")) as srv:
        pack, exception = new_client("test-key", srv.url).fetch_rule_pack("aws")
    assert pack is None
    assert exception is not None, "the caller turns this into a warning"


def test_fetch_rule_pack_unauthorized_is_reported_clearly(isolated_cache: Path) -> None:
    with StubServer(lambda r: Response(status=403, body={})) as srv:
        _, exception = new_client("test-key", srv.url).fetch_rule_pack("aws")
    assert exception is not None
    assert "plan" in str(exception), "the error should point at the plan"


def test_fetch_rule_pack_empty_body_is_rejected(isolated_cache: Path) -> None:
    with StubServer(lambda r: Response(status=200, raw=b"")) as srv:
        pack, exception = new_client("test-key", srv.url).fetch_rule_pack("aws")
    assert pack is None, "an empty body must not be cached as a valid pack"
    assert exception is not None


def test_fetch_rule_pack_synthesises_etag_when_absent(isolated_cache: Path) -> None:
    """Un corps de pack sans en-tête ETag reçoit quand même une identité
    stable, pour que le scan suivant puisse revalider au lieu de retélécharger
    indéfiniment."""
    with StubServer(lambda r: Response(raw=b"PACKBODY")) as srv:
        pack, exception = new_client("test-key", srv.url).fetch_rule_pack("aws")
    assert exception is None
    assert pack is not None and pack.etag


@pytest.mark.parametrize("provider", ["../../etc/passwd", "aws/../..", "", "AWS"])
def test_pack_file_name_rejects_path_traversal(provider: str) -> None:
    """Le nom de fournisseur atteint ce code depuis la configuration : il ne
    doit donc pas pouvoir choisir où nous écrivons."""
    got = pack_file_name(provider, ".pack.gz")
    assert Path(got).name == got, f"{provider!r} -> {got!r} escapes its directory"
    assert "/" not in got and ".." not in got


def test_the_cache_directory_matches_the_go_builds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un travail d'intégration continue qui met ce chemin en cache d'une
    exécution à l'autre continue de fonctionner à travers la bascule au lieu de
    repartir froid en silence : le chemin est donc celui que résout
    os.UserCacheDir de Go."""
    monkeypatch.delenv("TFPDF_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/xdg-example")
    monkeypatch.setattr("sys.platform", "linux")

    from tfpdf.licensing.rulepacks import _user_cache_dir

    assert str(_user_cache_dir()) == "/tmp/xdg-example"

    monkeypatch.delenv("XDG_CACHE_HOME")
    monkeypatch.setenv("HOME", "/home/someone")
    assert str(_user_cache_dir()) == "/home/someone/.cache"


def test_the_module_surface_is_reachable_from_the_package() -> None:
    assert licensing.DEFAULT_API_BASE.startswith("https://")
    assert new_client("k").api_base == licensing.DEFAULT_API_BASE
    assert new_client("k", "https://self.hosted").api_base == "https://self.hosted"
