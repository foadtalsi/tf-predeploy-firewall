"""Standard-library HTTP helpers for the scanner's optional network features."""

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
    """An HTTP response outside the 2xx range, including its body."""


class TransportError(HTTPError):
    """A request that failed before receiving a response (DNS, connection, TLS, or timeout)."""


@dataclass(slots=True, frozen=True)
class RawResponse:
    """An HTTP response whose status code is left for the caller to interpret."""

    status: int
    body: bytes
    _headers: Message | None = None

    def header(self, name: str) -> str:
        """Return a response header case-insensitively, or an empty string if absent."""
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
    """Send a request and return its response without interpreting the status code."""
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
    """Send a GET request and decode its JSON response."""
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
    """Send a JSON body and optionally decode the response."""
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
