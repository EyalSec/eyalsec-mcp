import json

import httpx
import pytest
from mcp import Client

from eyalsec_mcp.server import create_server

pytestmark = pytest.mark.anyio

EVENTS_PATH = "/api/get_all_events_with_count/"


def event_row(i, where="os system"):
    return [
        "2026-07-05T12:00:00Z",
        where,
        "'x'" * 300,
        1,
        "web-01",
        "high",
        "python",
        i,
        "",
        "",
        False,
        "This value was not sanitized.",
        [{"label": "command injection", "sev": "critical"}],
        [],
        False,
        "",
        "socket",
    ]


def text(result):
    assert result.content, result
    return result.content[0].text


async def call(client, name, args=None):
    result = await client.call_tool(name, args or {})
    return result, text(result)


async def test_every_tool_is_marked_read_only(fake):
    _, api = fake({})
    async with Client(create_server(api)) as client:
        tools = (await client.list_tools()).tools
    assert len(tools) >= 15
    for tool in tools:
        assert tool.annotations is not None and tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name
        assert tool.description, tool.name


async def test_search_events_maps_filters_and_rows(fake):
    calls, api = fake(
        {("POST", EVENTS_PATH): {"events": [event_row(7)], "next_cursor": "", "exhausted": True, "scanned": 1}}
    )
    async with Client(create_server(api)) as client:
        result, body = await call(
            client,
            "search_events",
            {
                "view": "python",
                "severity": ["critical", "high"],
                "date_from": "2026-06-01",
                "sink_include": "sql",
                "sink_exclude": "^healthcheck$",
                "machine": "web-01",
                "value_chars": 10,
            },
        )
    assert not result.is_error, body
    sent = calls.bodies(EVENTS_PATH)[0]
    assert sent == {
        "view": "python",
        "severity": ["critical", "high"],
        "from": "2026-06-01",
        "whitelist_repr": "sql",
        "blacklist_repr": "^healthcheck$",
        "machine": "web-01",
    }
    data = json.loads(body)
    [ev] = data["events"]
    assert ev["id"] == 7 and ev["where"] == "os system" and ev["taint_source"] == "socket"
    assert len(ev["str_repr"]) == 10 and ev["str_repr_truncated"] is True
    assert data["more_may_exist"] is False


async def test_search_events_follows_cursor_past_empty_pages(fake):
    pages = iter(
        [
            {"events": [], "next_cursor": "c1", "exhausted": False},
            {"events": [], "next_cursor": "c2", "exhausted": False},
            {"events": [event_row(3)], "next_cursor": "", "exhausted": True},
        ]
    )
    calls, api = fake({("POST", EVENTS_PATH): lambda r: httpx.Response(200, json=next(pages))})
    async with Client(create_server(api)) as client:
        _, body = await call(client, "search_events", {"severity": ["critical"]})
    data = json.loads(body)
    assert [e["id"] for e in data["events"]] == [3]
    assert data["pages_read"] == 3
    sent = calls.bodies(EVENTS_PATH)
    assert "cursor" not in sent[0] and sent[1]["cursor"] == "c1" and sent[2]["cursor"] == "c2"
    assert all(b["severity"] == ["critical"] for b in sent)


async def test_search_events_stops_at_limit_and_hands_back_cursor(fake):
    calls, api = fake(
        {
            ("POST", EVENTS_PATH): lambda r: httpx.Response(
                200, json={"events": [event_row(i) for i in range(100)], "next_cursor": "more"}
            )
        }
    )
    async with Client(create_server(api)) as client:
        _, body = await call(client, "search_events", {"limit": 150})
    data = json.loads(body)
    assert data["returned"] == 200 and data["pages_read"] == 2
    assert data["next_cursor"] == "more" and data["more_may_exist"] is True


async def test_search_events_reports_hide_all_rule(fake):
    calls, api = fake(
        {
            ("POST", EVENTS_PATH): {
                "events": [],
                "next_cursor": "",
                "exhausted": True,
                "hidden_by": {"id": 4, "label": "all"},
            }
        }
    )
    async with Client(create_server(api)) as client:
        _, body = await call(client, "search_events")
    data = json.loads(body)
    assert data["hidden_by"] == {"id": 4, "label": "all"}
    assert "Hide rule" in data["note"]


async def test_run_uid_becomes_a_run_condition(fake):
    calls, api = fake({("POST", EVENTS_PATH): {"events": [], "next_cursor": ""}})
    async with Client(create_server(api)) as client:
        await call(
            client,
            "search_events",
            {
                "run_uid": "9f2c1d4ab8e0472c93ad5f6178be20c4",
                "advanced": {"match": "all", "conditions": [{"field": "sink", "op": "contains", "value": "sql"}]},
            },
        )
    sent = calls.bodies(EVENTS_PATH)[0]
    assert sent["view"] == "python"
    assert sent["advanced"]["conditions"][-1] == {
        "field": "run",
        "op": "is",
        "value": "9f2c1d4ab8e0472c93ad5f6178be20c4",
    }
    assert len(sent["advanced"]["conditions"]) == 2


async def test_run_uid_refuses_any_match(fake):
    calls, api = fake({("POST", EVENTS_PATH): {"events": []}})
    async with Client(create_server(api)) as client:
        result, body = await call(
            client, "search_events", {"run_uid": "abc", "advanced": {"match": "any", "conditions": []}}
        )
    assert result.is_error and "match" in body
    assert calls.requests == []


async def test_get_event(fake):
    calls, api = fake({("GET", "/api/event/42"): {"trace": "Traceback", "runs": []}})
    async with Client(create_server(api)) as client:
        _, body = await call(client, "get_event", {"event_id": 42})
    assert json.loads(body) == {"trace": "Traceback", "runs": [], "id": 42}


async def test_api_error_becomes_tool_error(fake):
    calls, api = fake({})
    async with Client(create_server(api)) as client:
        result, body = await call(client, "get_event", {"event_id": 99})
    assert result.is_error
    assert "404" in body


async def test_list_machines_names_fields_and_flags_updates(fake):
    row = [
        "2026-07-01T00:00:00Z",
        "web-01",
        "installed",
        "pid-1",
        "ubuntu_24_04_x86_64",
        "b1",
        "b2",
        "3.13",
        False,
        False,
        False,
        False,
        "python",
    ]
    calls, api = fake({("GET", "/api/get_all_machines/"): {"machines": [row]}})
    async with Client(create_server(api)) as client:
        _, body = await call(client, "list_machines")
    data = json.loads(body)
    assert data["count"] == 1
    m = data["machines"][0]
    assert m["machine_name"] == "web-01" and m["public_id"] == "pid-1" and m["agent_kind"] == "python"
    assert m["update_available"] is True


async def test_event_map_is_python_only_and_maps_focus_rows(fake):
    calls, api = fake(
        {
            ("POST", "/api/event_map/"): {
                "events": 1,
                "sinks": [],
                "focus": {"events": [event_row(5)], "truncated": False},
            }
        }
    )
    async with Client(create_server(api)) as client:
        _, body = await call(client, "event_map", {"focus_sink": "os system", "date_from": "2026-07-01"})
    req = calls.requests[0]
    assert req.url.params["sink"] == "os system"
    assert json.loads(req.content) == {"view": "python", "from": "2026-07-01"}
    assert json.loads(body)["focus"]["events"][0]["id"] == 5


async def test_rules_scope_defaults_to_global(fake):
    calls, api = fake({("GET", "/api/machine_rules/"): {"rules": []}})
    async with Client(create_server(api)) as client:
        await call(client, "list_rules")
        await call(client, "list_rules", {"machine": "pid-1"})
    assert calls.requests[0].url.params.get("machine") is None
    assert calls.requests[1].url.params["machine"] == "pid-1"


async def test_get_account_never_needs_a_write(fake):
    calls, api = fake(
        {
            ("GET", "/api/account/"): {"username": "alice"},
            ("GET", "/api/account/apikey"): {"exists": True, "scope": "read_only"},
            ("GET", "/api/onboarding_state/"): {"next_step": "done"},
        }
    )
    async with Client(create_server(api)) as client:
        _, body = await call(client, "get_account")
    data = json.loads(body)
    assert data["profile"]["username"] == "alice" and data["api_key"]["scope"] == "read_only"
    assert {r.method for r in calls.requests} == {"GET"}


async def test_no_tool_issues_a_write(fake):
    """Call every tool once with minimal arguments and check the only POSTs are the two documented reads."""
    calls, api = fake(
        {
            ("POST", EVENTS_PATH): {"events": [], "next_cursor": ""},
            ("POST", "/api/event_map/"): {"events": 0},
        }
    )
    required = {"get_event": {"event_id": 1}, "ci_findings": {"machine": "ci", "since": "2026-10-07T12:00:00Z"}}
    async with Client(create_server(api)) as client:
        for tool in (await client.list_tools()).tools:
            await client.call_tool(tool.name, required.get(tool.name, {}))
    assert calls.requests, "no request was made"
    for r in calls.requests:
        assert r.method == "GET" or r.url.path in (EVENTS_PATH, "/api/event_map/"), (r.method, r.url.path)


async def test_get_account_works_where_setup_progress_is_not_offered(fake):
    calls, api = fake(
        {
            ("GET", "/api/account/"): {"username": "alice"},
            ("GET", "/api/account/apikey"): {"exists": True},
            ("GET", "/api/onboarding_state/"): lambda r: httpx.Response(
                404, text="<html></html>", headers={"content-type": "text/html"}
            ),
        }
    )
    async with Client(create_server(api)) as client:
        result, body = await call(client, "get_account")
    assert not result.is_error, body
    assert json.loads(body)["setup"] is None
