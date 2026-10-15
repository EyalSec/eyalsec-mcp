"""Optional checks against a real EyalSec account.

Skipped unless EYALSEC_LIVE=1 and EYALSEC_API_KEY are set (EYALSEC_URL picks
the address). Every call is a read.
"""

import json
import os

import pytest
from mcp import Client

from eyalsec_mcp.server import create_server

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        os.environ.get("EYALSEC_LIVE") != "1" or not os.environ.get("EYALSEC_API_KEY"),
        reason="set EYALSEC_LIVE=1 and EYALSEC_API_KEY to run against a real account",
    ),
]


async def test_live_every_tool_answers():
    async with Client(create_server()) as client:
        tools = (await client.list_tools()).tools
        account = json.loads((await client.call_tool("get_account", {})).content[0].text)
        assert account["profile"]["username"]

        events = json.loads((await client.call_tool("search_events", {"limit": 5})).content[0].text)
        assert "events" in events
        if events["events"]:
            ev = events["events"][0]
            detail = await client.call_tool("get_event", {"event_id": ev["id"]})
            assert not detail.is_error

        machines = json.loads((await client.call_tool("list_machines", {})).content[0].text)
        required = {"get_event": {"event_id": events["events"][0]["id"]} if events["events"] else None}
        if machines["machines"]:
            required["ci_findings"] = {
                "machine": machines["machines"][0]["machine_name"],
                "since": "2026-01-01T00:00:00Z",
            }
        for tool in tools:
            args = required.get(tool.name, {})
            if args is None:
                continue
            if tool.name == "ci_findings" and "ci_findings" not in required:
                continue
            result = await client.call_tool(tool.name, args)
            assert not result.is_error, (tool.name, result.content[0].text if result.content else "")
