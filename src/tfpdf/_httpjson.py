"""Le peu de HTTP que fait le scanner, avec la bibliothèque standard.

`githubpr` et `gitlabmr` portent chacun leur propre paire `getJSON`/`doJSON` en
Go, ce qui y est raisonnable : ce sont des paquets séparés et la paire fait six
lignes de `net/http`. En Python l'équivalent est du passe-partout
`urllib.request`, et deux copies écrites à la main en feraient deux endroits où
la gestion d'erreurs peut diverger. Elles ne diffèrent que par leur en-tête
d'authentification, qui devient donc le paramètre.

Bibliothèque standard à dessein. Le scanner tourne dans la CI d'autres gens, et
`requests` serait une dépendance d'exécution que leur revue de chaîne
d'approvisionnement devrait valider pour un POST par pipeline.
"""

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
    """Une réponse hors 2xx, portant son corps.

    Le message d'erreur de la forge est généralement la seule chose qui
    explique l'échec (« Reviews may only be requested from collaborators »), il
    n'est donc jamais avalé.
    """


class TransportError(HTTPError):
    """La requête n'a jamais obtenu de réponse — DNS, connexion, TLS, délai.

    Distincte de `HTTPError` parce que `licensing` se branche sur des codes de
    statut et doit pouvoir distinguer « le service a dit 403 » de « le service
    était injoignable » ; sous-classe pour que chaque `except HTTPError`
    existant l'attrape encore.
    """


@dataclass(slots=True, frozen=True)
class RawResponse:
    """Une réponse avec son statut intact, pour les appelants dont la logique
    *est* le code de statut.

    `licensing.fetch_rule_pack` traite 304 comme « ton cache est encore bon »,
    403 comme « ton plan n'inclut pas ceci », 404 comme « aucun pack publié » et
    200 comme un corps à garder — quatre issues différentes, dont aucune n'est
    une exception. Lever sur un hors-2xx comme le fait `get_json` obligerait à
    reconstruire le statut depuis une chaîne d'erreur.
    """

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
    """Exécute une requête et rend la réponse sans juger son statut.

    Seul un service injoignable lève, puisque c'est le seul cas sans statut sur
    lequel se brancher. `max_bytes` plafonne la lecture : une lecture non bornée
    depuis un service que nous ne contrôlons pas n'est pas quelque chose qu'un
    runner de CI devrait offrir.
    """
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
