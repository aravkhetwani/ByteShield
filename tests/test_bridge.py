"""The stdio MCP bridge lets an unmodified MCP client use the gateway (real uvicorn + real MCP SDK client)."""
from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time

import httpx
import pytest
import uvicorn
from mcp import Client, StdioServerParameters

from byteshield.app import create_app
from byteshield.config import ROOT, Settings


@pytest.fixture()
def live_gateway(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    settings = Settings(data_dir=tmp_path, admin_token=None, mode_override=None)
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{url}/api/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.2)
    else:
        pytest.fail("gateway did not start")
    yield url
    server.should_exit = True
    thread.join(timeout=15)


def test_mcp_client_through_bridge(live_gateway):
    async def scenario():
        params = StdioServerParameters(command=sys.executable, cwd=str(ROOT),
                                       args=["-m", "byteshield.mcp_bridge", "--gateway", live_gateway, "--agent", "bridge-test"])
        async with Client(params) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            assert "weather__get_weather" in names and "poisoned__add" not in names
            ok = await client.call_tool("weather__get_weather", {"city": "Tokyo"})
            assert not ok.is_error and "Tokyo" in ok.content[0].text
            blocked = await client.call_tool("poisoned__add", {"a": 1, "b": 2})
            assert blocked.is_error and "BLOCKED" in blocked.content[0].text
            gated = await client.call_tool("office__send_email", {"to": "a@corp.example", "subject": "s", "body": "b"})
            assert gated.is_error and "approval" in gated.content[0].text.lower()

    asyncio.run(scenario())
