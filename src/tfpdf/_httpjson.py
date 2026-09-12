"""Le peu de HTTP que fait le scanner, avec la bibliothèque standard."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import Message
from typing import Any

#: Long enough for a slow forge, short enough that a hung connection cannot
#: hold a CI job open. Go leaves this at http.DefaultClient's no-timeout,
#: which is a hang waiting to happen in a pipeline.
DEFAULT_TIMEOUT = 30.0


class HTTPError(RuntimeError):
    """Une réponse hors 2xx, portant son corps."""


class TransportError(HTTPError):
    """La requête n'a jamais obtenu de réponse — DNS, connexion, TLS, délai."""


@dataclass(slots=True, frozen=True)
class RawResponse:
    """Une réponse avec son statut intact, pour les appelants dont la logique *est* le code de
    statut."""

    status: int
    body: bytes
    _headers: Message | None = None

    def header(self, name: str) -> str:
        """Un en-tête de réponse, sans distinction de casse, ou « »."""
        if self._headers is None:
            return ""
        return self._headers.get(name, "")


def request_raw(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int | None = None,
) -> RawResponse:
    """Exécute une requête et rend la réponse sans juger son statut."""
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(max_bytes) if max_bytes is not None else response.read()
            return RawResponse(status=response.status, body=raw, _headers=response.headers)
    except urllib.error.HTTPError as exc:
        # urllib raises for every non-2xx, 304 included. The status is the
        # answer here, so it is handed back rather than raised.
        return RawResponse(status=exc.code, body=exc.read(), _headers=exc.headers)
    except urllib.error.URLError as exc:
        raise TransportError(f"{method} {url} failed: {exc.reason}") from exc


def get_json(url: str, headers: dict[str, str], timeout: float = DEFAULT_TIMEOUT) -> Any:
    """GET, puis décodage d'une réponse JSON."""
    request = urllib.request.Request(url, method="GET", headers=headers)
    return _read_json(request, url, "GET", timeout)


def send_json(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: Any,
    timeout: float = DEFAULT_TIMEOUT,
    want_response: bool = False,
) -> Any:
    """Envoie un corps JSON et, éventuellement, décode la réponse."""
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={**headers, "Content-Type": "application/json"},
    )
    result = _read_json(request, url, method, timeout, decode=want_response)
    return result


def _read_json(
    request: urllib.request.Request,
    url: str,
    method: str,
    timeout: float,
    decode: bool = True,
) -> Any:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if not decode:
                response.read()
                return None
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise HTTPError(f"{method} {url} failed: {exc.code} {exc.reason}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise HTTPError(f"{method} {url} failed: {exc.reason}") from exc
