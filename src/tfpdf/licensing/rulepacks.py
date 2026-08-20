"""Récupère le pack de règles étendu d'une organisation sous licence et le
superpose au pack de base embarqué.

Port de internal/licensing/rulepacks.go.

Trois propriétés à tenir, par ordre de priorité :

1. **Un scan n'échoue jamais à cause de nous.** Plan de contrôle tombé, lent ou
   incohérent : le scan tourne sur la dernière copie en cache, ou à défaut sur
   le pack de base embarqué.
2. **Aucune découverte n'apparaît ni ne disparaît en silence.** Le pack
   réellement utilisé est indiqué dans la sortie du scan.
3. **Pas de retéléchargement de 560 Ko à chaque scan.** Cache disque revalidé
   par ETag ; le régime permanent est un 304.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .._httpjson import RawResponse, request_raw

#: How long a cached pack is used without revalidating. Packs change only when
#: the provider ships a release, so revalidating each scan would spend a round
#: trip to be told "unchanged" almost every time.
PACK_CACHE_TTL_SECONDS = 24 * 60 * 60

#: Deliberately shorter than the client's default: a slow pack fetch delays
#: every PR check, and falling back to the base pack is a perfectly good
#: outcome.
PACK_FETCH_TIMEOUT = 15.0

#: A pack is ~0.6 MB. The cap is generous but finite.
_MAX_PACK_BYTES = 64 << 20


class NoPackAvailableError(RuntimeError):
    """Ni le réseau ni le cache n'ont pu fournir de pack étendu.

    Ce n'est pas un échec du scan : l'appelant se rabat sur le pack de base
    embarqué.
    """


@dataclass(slots=True)
class RulePack:
    """Un pack récupéré ou mis en cache, prêt à être passé à
    `schema.load_with`."""

    #: The provider the pack describes ("aws").
    provider: str
    #: The gzipped pack body.
    data: bytes
    #: Whether this came from disk rather than the network.
    from_cache: bool = False
    #: Identifies this pack version.
    etag: str = ""

    def reader(self) -> io.BytesIO:
        """Le corps du pack, sous forme de lecteur."""
        return io.BytesIO(self.data)


def fetch_rule_pack(
    api_base: str, api_key: str, provider: str
) -> tuple[RulePack | None, Exception | None]:
    """Rend le pack de règles étendu d'un fournisseur, en préférant une copie
    fraîche, puis une copie en cache, et en indiquant précisément laquelle a
    servi.

    L'erreur rendue est **consultative** : chaque fois qu'elle est non-None,
    l'appelant doit avertir et continuer sur le pack de base, jamais abandonner.
    Un résultat `(None, None)` est impossible — l'un des deux est toujours posé.
    Rendre une paire plutôt que lever est délibéré, à l'image du `(pack, err)`
    de Go : le cas intéressant ici est d'avoir *les deux* à la fois, un pack en
    cache utilisable accompagné de la raison pour laquelle il n'est pas frais.
    """
    cache_dir: Path | None
    try:
        cache_dir = pack_cache_dir()
    except OSError:
        cache_dir = None

    cached: RulePack | None = None
    if cache_dir is not None:
        cached = read_cached_pack(cache_dir, provider)
        # A recent cache entry is used as-is: the network round trip would
        # almost always just confirm it.
        if cached is not None and cache_fresh(cache_dir, provider):
            cached.from_cache = True
            return cached, None

    try:
        fetched = _download_rule_pack(api_base, api_key, provider, cached)
        err: Exception | None = None
    except Exception as exc:
        fetched, err = None, exc

    if err is None and fetched is not None:
        if cache_dir is not None:
            # A cache we cannot write is not worth failing over; the next scan
            # simply downloads again.
            with contextlib.suppress(OSError):
                write_cached_pack(cache_dir, provider, fetched)
        return fetched, None

    if err is None and fetched is None and cached is not None:
        # 304 Not Modified: the cache is still correct, just stale-dated.
        if cache_dir is not None:
            with contextlib.suppress(OSError):
                touch_cache(cache_dir, provider)
        cached.from_cache = True
        return cached, None

    if cached is not None:
        cached.from_cache = True
        return cached, RuntimeError(f"using cached rule pack: {err}")

    return None, err if err is not None else NoPackAvailableError("no extended rule pack available")


def _download_rule_pack(
    api_base: str, api_key: str, provider: str, cached: RulePack | None
) -> RulePack | None:
    """Rend None quand le serveur signale que la copie en cache est encore à
    jour."""
    headers = {"Authorization": "Bearer " + api_key}
    if cached is not None and cached.etag:
        headers["If-None-Match"] = cached.etag

    resp: RawResponse = request_raw(
        "GET",
        f"{api_base}/v1/rulepacks/{provider}",
        headers,
        timeout=PACK_FETCH_TIMEOUT,
        max_bytes=_MAX_PACK_BYTES,
    )

    if resp.status == 304:
        return None
    if resp.status in (401, 403):
        raise RuntimeError(f"rule pack refused ({resp.status}) — check the license key's plan")
    if resp.status == 404:
        raise RuntimeError(f'no rule pack published for provider "{provider}"')
    if resp.status != 200:
        raise RuntimeError(f"rule pack service returned {resp.status}")

    if not resp.body:
        raise RuntimeError("rule pack service returned an empty body")

    etag = resp.header("ETag")
    if not etag:
        etag = '"' + hashlib.sha256(resp.body).hexdigest() + '"'
    return RulePack(provider=provider, data=resp.body, etag=etag)


# ---------------------------------------------------------------------------
# On-disk cache
# ---------------------------------------------------------------------------


def _user_cache_dir() -> Path:
    """Le répertoire de cache par utilisateur de la plateforme, correspondant à
    l'`os.UserCacheDir` de Go.

    Écrit explicitement plutôt que pris dans une bibliothèque, parce que le
    chemin doit être celui qu'utilisait la version Go : un job de CI qui met en
    cache `~/.cache/tf-predeploy-firewall` continue de fonctionner à travers la
    bascule au lieu de repartir silencieusement d'un cache froid.
    """
    # Read into a local first. `sys.platform` compared inline is special-cased
    # by type checkers, which then declare every branch but this machine's
    # unreachable — and all three branches have to stay checked.
    platform = sys.platform

    if platform == "darwin":
        home = os.environ.get("HOME")
        if not home:
            raise OSError("neither $HOME nor $XDG_CACHE_HOME is set")
        return Path(home) / "Library" / "Caches"
    if platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise OSError("%LocalAppData% is not set")
        return Path(local)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg)
    home = os.environ.get("HOME")
    if not home:
        raise OSError("neither $HOME nor $XDG_CACHE_HOME is set")
    return Path(home) / ".cache"


def pack_cache_dir() -> Path:
    """Où les packs sont mis en cache.

    `TFPDF_CACHE_DIR` existe pour qu'un job de CI puisse le pointer sur un
    répertoire qu'il restaure déjà entre deux exécutions (actions/cache),
    ramenant le régime permanent à zéro appel réseau.
    """
    base = os.environ.get("TFPDF_CACHE_DIR")
    root = Path(base) if base else _user_cache_dir() / "tf-predeploy-firewall"
    dir_ = root / "rulepacks"
    dir_.mkdir(parents=True, exist_ok=True)
    return dir_


def pack_file_name(provider: str, ext: str) -> str:
    """Empêche le nom du fournisseur de s'échapper du répertoire de cache : il
    vient de la configuration, et une valeur comme « ../../etc » ne doit pas
    décider où l'on écrit."""
    safe = "".join(
        ch if ("a" <= ch <= "z" or "0" <= ch <= "9" or ch in "-_") else "-"
        for ch in provider.lower()
    )
    if not safe:
        safe = "unknown"
    return safe + ext


def read_cached_pack(dir_: Path, provider: str) -> RulePack | None:
    try:
        data = (dir_ / pack_file_name(provider, ".pack.gz")).read_bytes()
    except OSError:
        return None
    if not data:
        return None
    try:
        etag = (dir_ / pack_file_name(provider, ".etag")).read_text()
    except OSError:
        etag = ""
    return RulePack(provider=provider, data=data, etag=etag.strip())


def write_cached_pack(dir_: Path, provider: str, p: RulePack) -> None:
    pack_path = dir_ / pack_file_name(provider, ".pack.gz")
    # Write via a temp file and rename: two scans can run concurrently on the
    # same runner, and a half-written pack read by the other one would be a
    # corrupt-pack error rather than a clean miss.
    fd, tmp_name = tempfile.mkstemp(prefix="pack-", suffix=".tmp", dir=dir_)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(p.data)
        tmp.replace(pack_path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    (dir_ / pack_file_name(provider, ".etag")).write_text(p.etag)


def cache_fresh(dir_: Path, provider: str) -> bool:
    try:
        mtime = (dir_ / pack_file_name(provider, ".pack.gz")).stat().st_mtime
    except OSError:
        return False
    return (time.time() - mtime) < PACK_CACHE_TTL_SECONDS


def touch_cache(dir_: Path, provider: str) -> None:
    now = time.time()
    os.utime(dir_ / pack_file_name(provider, ".pack.gz"), (now, now))
