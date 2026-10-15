import httpx
import pytest

from eyalsec_mcp.client import (
    EVENT_ROW_FIELDS,
    APIError,
    ConfigError,
    EyalSecClient,
    normalize_base_url,
    rows_to_objects,
)

from .conftest import KEY

pytestmark = pytest.mark.anyio


def test_base_url_defaults_and_trailing_slash():
    assert normalize_base_url("") == "https://eyalsec.com"
    assert normalize_base_url("https://eyalsec.com/") == "https://eyalsec.com"
    assert normalize_base_url("http://localhost:8080") == "http://localhost:8080"


@pytest.mark.parametrize("url", ["http://eyalsec.com", "ftp://eyalsec.com", "eyalsec.com", "https://"])
def test_base_url_refuses_cleartext_and_junk(url):
    with pytest.raises(ConfigError):
        normalize_base_url(url)


def test_rows_to_objects_keeps_unknown_trailing_values():
    row = list(range(len(EVENT_ROW_FIELDS))) + ["future"]
    [obj] = rows_to_objects([row], EVENT_ROW_FIELDS)
    assert obj["created_at"] == 0
    assert obj["taint_source"] == len(EVENT_ROW_FIELDS) - 1
    assert obj["extra"] == ["future"]


def test_rows_to_objects_tolerates_short_rows():
    [obj] = rows_to_objects([["2026-01-01T00:00:00Z", "os system"]], EVENT_ROW_FIELDS)
    assert obj == {"created_at": "2026-01-01T00:00:00Z", "where": "os system"}


async def test_key_is_sent_in_header(fake):
    api, client = fake({("GET", "/api/account/"): {"username": "alice"}})
    assert await client.get("/api/account/") == {"username": "alice"}
    assert api.requests[0].headers["X-API-Key"] == KEY
    assert api.requests[0].headers["User-Agent"].startswith("eyalsec-mcp/")


async def test_public_endpoint_sends_no_key(fake):
    api, client = fake({("GET", "/api/supported_os_types/"): {"distros": []}}, key="")
    await client.get("/api/supported_os_types/", public=True)
    assert "X-API-Key" not in api.requests[0].headers


async def test_missing_key_is_a_clear_error(fake):
    api, client = fake({}, key="")
    with pytest.raises(ConfigError, match="EYALSEC_API_KEY"):
        await client.get("/api/account/")
    assert api.requests == []


async def test_empty_params_are_dropped(fake):
    api, client = fake({("GET", "/api/runs/"): {"runs": []}})
    await client.get("/api/runs/", {"machine": None, "q": "", "limit": 5})
    assert str(api.requests[0].url.query, "ascii") == "limit=5"


async def test_401_explains_where_to_get_a_key(fake):
    api, client = fake(
        {("GET", "/api/account/"): lambda r: httpx.Response(401, json={"error": "invalid or expired API key"})}
    )
    with pytest.raises(APIError) as exc:
        await client.get("/api/account/")
    assert exc.value.status == 401
    assert "invalid or expired API key" in str(exc.value)
    assert "Settings > API access" in str(exc.value)


async def test_429_reports_retry_after(fake):
    api, client = fake(
        {("GET", "/api/account/"): lambda r: httpx.Response(429, text="slow down", headers={"Retry-After": "12"})}
    )
    with pytest.raises(APIError, match="12 seconds"):
        await client.get("/api/account/")


async def test_html_error_body_is_not_echoed(fake):
    api, client = fake({("GET", "/api/account/"): lambda r: httpx.Response(500, text="<html>oops</html>")})
    with pytest.raises(APIError) as exc:
        await client.get("/api/account/")
    assert "<html>" not in str(exc.value)


async def test_redirect_is_an_error_not_followed(fake):
    api, client = fake({("GET", "/api/account/"): lambda r: httpx.Response(302, headers={"Location": "/login/"})})
    with pytest.raises(APIError, match="redirect"):
        await client.get("/api/account/")
    assert len(api.requests) == 1


async def test_post_is_limited_to_documented_reads(fake):
    api, client = fake({})
    with pytest.raises(ValueError):
        await client.post_read("/api/delete_machine/", {})
    assert api.requests == []


def test_client_reads_environment(monkeypatch):
    monkeypatch.setenv("EYALSEC_API_KEY", "  es2_fromenv  ")
    monkeypatch.setenv("EYALSEC_URL", "https://test.example/")
    client = EyalSecClient()
    assert client.api_key == "es2_fromenv"
    assert client.base_url == "https://test.example"


async def test_generic_404_page_means_endpoint_not_offered(fake):
    api, client = fake(
        {
            ("GET", "/api/ci/findings/"): lambda r: httpx.Response(
                404, text="<html>404</html>", headers={"content-type": "text/html"}
            )
        }
    )
    with pytest.raises(APIError) as exc:
        await client.get("/api/ci/findings/")
    assert exc.value.unavailable
    assert "does not offer /api/ci/findings/" in str(exc.value)


async def test_json_404_is_an_ordinary_not_found(fake):
    api, client = fake({("GET", "/api/event/5"): lambda r: httpx.Response(404, json={"error": "not found"})})
    with pytest.raises(APIError) as exc:
        await client.get("/api/event/5")
    assert not exc.value.unavailable
    assert "another account" in str(exc.value)
