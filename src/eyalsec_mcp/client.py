"""A small, read-only client for the EyalSec API.

Only endpoints the EyalSec API reference documents as reads are called. The
client has no method that changes anything on the account, so even a
full-access key cannot be used to write through this server.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__

DEFAULT_URL = "https://eyalsec.com"
API_KEY_ENV = "EYALSEC_API_KEY"
URL_ENV = "EYALSEC_URL"

# The event row and machine row are arrays in a fixed order; new values are
# only ever appended. These names follow the API reference.
EVENT_ROW_FIELDS = (
    "created_at",
    "where",
    "str_repr",
    "count",
    "machine_name",
    "severity",
    "agent_kind",
    "id",
    "source_label",
    "context",
    "suppressed",
    "sanitize_reason",
    "impact",
    "labels",
    "has_comment",
    "extension",
    "taint_source",
)

MACHINE_ROW_FIELDS = (
    "created_at",
    "machine_name",
    "status",
    "public_id",
    "os_type",
    "installed_build",
    "current_build",
    "python_version",
    "socket_only",
    "clone_locked",
    "stalled",
    "stale_agent",
    "agent_kind",
)

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ConfigError(Exception):
    """The server is not configured well enough to call the API."""


class APIError(Exception):
    """The EyalSec API answered with an error status."""

    def __init__(self, status: int, message: str, retry_after: str | None = None, *, unavailable: bool = False):
        self.status = status
        self.message = message
        self.retry_after = retry_after
        # True when the address answered with its generic "no such page"
        # rather than an API error: the endpoint is not offered there (for
        # example an account on a domain still running an older release).
        self.unavailable = unavailable
        super().__init__(self.describe())

    def describe(self) -> str:
        if self.unavailable:
            return (
                f"EyalSec API answered {self.status}: this EyalSec address does not offer {self.message} yet. "
                "Other tools keep working."
            )
        hints = {
            401: "The API key was refused: it is missing, wrong, revoked or expired. "
            "Create a key on Settings > API access and set it as EYALSEC_API_KEY.",
            403: "This account or key is not allowed to read that.",
            404: "Something that belongs to another account is answered the same way as something that does not exist.",
            429: "Rate limit reached.",
        }
        text = f"EyalSec API answered {self.status}"
        if self.message:
            text += f": {self.message}"
        hint = hints.get(self.status)
        if hint:
            text += f". {hint}"
        if self.status == 429 and self.retry_after:
            text += f" Try again in {self.retry_after} seconds."
        if self.status >= 500:
            text += ". Something failed on the EyalSec side; try again, and contact support@eyalsec.com if it persists."
        return text


def normalize_base_url(url: str) -> str:
    """Return the API origin without a trailing slash, refusing plain HTTP
    to anything but this machine (the key would travel in clear text)."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return DEFAULT_URL
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError(f"{URL_ENV} must be an https:// address, got {url!r}")
    if parts.scheme == "http" and parts.hostname not in _LOCAL_HOSTS:
        raise ConfigError(f"{URL_ENV} must use https:// (the API key would be sent in clear text), got {url!r}")
    return url


def rows_to_objects(rows: list[Any], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Turn fixed-order arrays into objects. Values past the known fields are
    kept under ``extra`` so nothing the server adds later is lost."""
    out = []
    for row in rows or []:
        if isinstance(row, dict):
            out.append(row)
            continue
        obj = {name: row[i] for i, name in enumerate(fields) if i < len(row)}
        if len(row) > len(fields):
            obj["extra"] = list(row[len(fields) :])
        out.append(obj)
    return out


class EyalSecClient:
    """Async client for the read-only part of the EyalSec API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
    ):
        self.api_key = (api_key if api_key is not None else os.environ.get(API_KEY_ENV, "")).strip()
        self.base_url = normalize_base_url(base_url if base_url is not None else os.environ.get(URL_ENV, ""))
        self._transport = transport
        self._timeout = timeout
        self._http: httpx.AsyncClient | None = None

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                base_url=self.base_url,
                transport=self._transport,
                timeout=self._timeout,
                headers={"User-Agent": f"eyalsec-mcp/{__version__}", "Accept": "application/json"},
                follow_redirects=False,
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        public: bool = False,
    ) -> Any:
        headers = {}
        if not public:
            if not self.api_key:
                raise ConfigError(
                    f"{API_KEY_ENV} is not set. Create a key on your EyalSec dashboard "
                    "(Settings > API access; a read-only key is enough) and pass it to this server "
                    f"in the {API_KEY_ENV} environment variable."
                )
            headers["X-API-Key"] = self.api_key
        clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        try:
            resp = await self._client().request(method, path, params=clean, json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise APIError(0, f"could not reach {self.base_url} ({type(exc).__name__})") from exc
        if resp.is_redirect:
            # The API never redirects a key request; a redirect means the path
            # or the address is wrong (for example a sign-in page).
            raise APIError(resp.status_code, f"unexpected redirect to {resp.headers.get('location', '?')}")
        if resp.status_code == 404 and "json" not in resp.headers.get("content-type", ""):
            raise APIError(404, path, unavailable=True)
        if resp.status_code >= 400:
            raise APIError(resp.status_code, _error_text(resp), resp.headers.get("Retry-After"))
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError as exc:
            raise APIError(resp.status_code, "the answer was not JSON") from exc

    async def get(self, path: str, params: dict[str, Any] | None = None, *, public: bool = False) -> Any:
        return await self._request("GET", path, params=params, public=public)

    async def post_read(self, path: str, body: dict[str, Any], params: dict[str, Any] | None = None) -> Any:
        """POST for the two documented read endpoints whose filters travel in
        a JSON body (the events query and the events map)."""
        if path not in _READ_POSTS:
            raise ValueError(f"{path} is not a documented read endpoint")
        return await self._request("POST", path, params=params, json=body)


_READ_POSTS = frozenset({"/api/get_all_events_with_count/", "/api/event_map/"})


def _error_text(resp: httpx.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict) and data.get("error"):
            return str(data["error"])[:500]
    except ValueError:
        pass
    text = resp.text.strip()
    if text.startswith("<"):
        return ""
    return text[:500]
