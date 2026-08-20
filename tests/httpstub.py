"""Un serveur HTTP local pour les tests des clients de forge — le substitut
du `httptest.NewServer` de Go.

Les clients de forge sont la seule partie du scanner qui parle à un réseau, et
ce qui mérite d'être testé chez eux est la requête qu'ils construisent : quelle
URL, quelle méthode, quel corps JSON. Simuler `urllib` testerait que la
simulation a été appelée. Un vrai serveur sur un port de loopback teste ce qui
part réellement sur le fil, ce que GitHub et GitLab refusent ou acceptent.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


@dataclass(slots=True)
class Request:
    """Une requête reçue, décodée."""

    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: Any = None


@dataclass(slots=True)
class Response:
    """Ce que le handler veut renvoyer.

    `body` est encodé en JSON. `raw` envoie des octets tels quels à la place —
    un pack de règles est un blob gzip, et l'envelopper en JSON testerait
    l'enveloppe. `headers` porte ceux que le client relit, ce qui pour la
    récupération de pack est l'ETag sur lequel repose tout le schéma de
    revalidation.
    """

    status: int = 200
    body: Any = field(default_factory=dict)
    raw: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)


class StubServer:
    """Sert `handler(request) -> Response` jusqu'à fermeture.

    À utiliser comme gestionnaire de contexte ; `url` est la base vers laquelle
    pointer un client, et `requests` est chaque requête reçue, dans l'ordre.
    """

    def __init__(self, handler: Callable[[Request], Response]) -> None:
        self._handler = handler
        self.requests: list[Request] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def calls(self) -> int:
        return len(self.requests)

    def __enter__(self) -> StubServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: object) -> None:
                pass  # the test output is not a request log

            def _dispatch(self) -> None:
                parsed = urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None

                request = Request(
                    method=self.command,
                    path=parsed.path,
                    query=parse_qs(parsed.query),
                    headers=dict(self.headers),
                    body=body,
                )
                server.requests.append(request)

                response = server._handler(request)

                # 304 carries no body by definition, and sending one makes the
                # client wait for bytes that never come.
                if response.status == 304:
                    self.send_response(304)
                    for k, v in response.headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                if response.raw is not None:
                    payload, content_type = response.raw, "application/octet-stream"
                else:
                    payload, content_type = json.dumps(response.body).encode(), "application/json"

                self.send_response(response.status)
                self.send_header("Content-Type", content_type)
                for k, v in response.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _dispatch
            do_POST = _dispatch
            do_PATCH = _dispatch
            do_PUT = _dispatch

        return Handler
