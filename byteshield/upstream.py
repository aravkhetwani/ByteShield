"""Connections from the gateway to upstream MCP servers, via the official MCP Python SDK client."""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import Client, StdioServerParameters

from .config import UpstreamConfig

log = logging.getLogger("byteshield.upstream")

CALL_TIMEOUT_S = 30.0
LIST_TIMEOUT_S = 15.0
MAX_PAGES = 20


@dataclass
class Upstream:
    config: UpstreamConfig
    client: Client | None = None
    status: str = "disconnected"          # connected | error | disconnected
    error: str | None = None
    tool_names: set[str] = field(default_factory=set)
    last_refresh: float | None = None

    @property
    def name(self) -> str:
        return self.config.name


class UpstreamManager:
    """Owns one MCP client session per upstream server.

    Sessions are opened and closed from the same task (the app lifespan), which anyio requires.
    """

    def __init__(self, configs: list[UpstreamConfig]):
        self.servers: dict[str, Upstream] = {c.name: Upstream(c) for c in configs}
        self._stack = AsyncExitStack()

    async def start(self) -> None:
        await self._stack.__aenter__()
        for up in self.servers.values():
            params = StdioServerParameters(command=up.config.command, args=up.config.args, env=up.config.env)
            try:
                # cache=None: never trust a cached tools/list - fingerprints must reflect the live definition
                up.client = await self._stack.enter_async_context(Client(params, cache=None))
                up.status, up.error = "connected", None
                log.info("connected to upstream %s", up.name)
            except Exception as exc:  # noqa: BLE001 - a dead upstream must not take the gateway down
                up.status, up.error = "error", f"{type(exc).__name__}: {exc}"
                log.error("failed to connect to upstream %s: %s", up.name, up.error)

    async def stop(self) -> None:
        try:
            await self._stack.aclose()
        except Exception as exc:  # noqa: BLE001
            log.warning("error while closing upstream sessions: %s", exc)
        for up in self.servers.values():
            up.client, up.status = None, "disconnected"

    def is_connected(self, name: str) -> bool:
        up = self.servers.get(name)
        return bool(up and up.client is not None and up.status == "connected")

    async def list_tools(self, name: str) -> list[dict[str, Any]]:
        up = self.servers[name]
        if up.client is None:
            raise ConnectionError(up.error or "not connected")
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        try:
            for _ in range(MAX_PAGES):
                page = await asyncio.wait_for(up.client.list_tools(cursor=cursor, cache_mode="bypass"), LIST_TIMEOUT_S)
                for t in page.tools:
                    dumped = t.model_dump(by_alias=True, exclude_none=True)
                    tools.append({"name": dumped["name"], "description": dumped.get("description", ""),
                                  "inputSchema": dumped.get("inputSchema", {}),
                                  "title": dumped.get("title"), "annotations": dumped.get("annotations")})
                cursor = page.next_cursor
                if not cursor:
                    break
        except Exception as exc:  # noqa: BLE001
            up.status, up.error = "error", f"{type(exc).__name__}: {exc}"
            raise
        up.status, up.error = "connected", None
        up.tool_names = {t["name"] for t in tools}
        up.last_refresh = time.time()
        return tools

    async def call_tool(self, name: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        up = self.servers[name]
        if up.client is None:
            raise ConnectionError(up.error or "not connected")
        res = await asyncio.wait_for(up.client.call_tool(tool, arguments), CALL_TIMEOUT_S)
        content = [c.model_dump(by_alias=True, exclude_none=True) for c in res.content]
        out: dict[str, Any] = {"content": content, "isError": bool(res.is_error)}
        if res.structured_content is not None:
            out["structuredContent"] = res.structured_content
        return out
