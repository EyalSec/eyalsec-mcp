import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from eyalsec_mcp.client import EyalSecClient

KEY = "es2_TESTKEYdoNotUse000000000000000000000000000"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeAPI:
    """Answers EyalSec API paths from a dict and records every request."""

    def __init__(self, routes: dict[tuple[str, str], Callable[[httpx.Request], httpx.Response] | Any]):
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"error": "not found"})
        if callable(route):
            return route(request)
        return httpx.Response(200, json=route)

    def bodies(self, path: str) -> list[dict]:
        return [json.loads(r.content or b"{}") for r in self.requests if r.url.path == path]


@pytest.fixture
def fake():
    def make(routes, key: str | None = KEY):
        api = FakeAPI(routes)
        client = EyalSecClient(api_key=key, base_url="https://eyalsec.example", transport=httpx.MockTransport(api))
        return api, client

    return make
