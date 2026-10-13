"""stdio MCP server that fronts a running ByteShield gateway.

Point any MCP client (Claude Desktop, an agent framework, the MCP Inspector) at this process and
every tool discovery / tool call is routed through the gateway's policy engine:

    python -m byteshield.mcp_bridge --gateway http://127.0.0.1:8080 --agent claude-desktop

Claude Desktop config example:
    {"mcpServers": {"byteshield": {"command": "python", "args": ["-m", "byteshield.mcp_bridge"]}}}
"""
from __future__ import annotations

import argparse
import uuid
from typing import Any

import anyio
import httpx
import mcp_types as types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server


def build_server(gateway_url: str, agent: str, session: str) -> Server:
    headers = {"x-agent-id": agent, "x-session-id": session}
    http = httpx.AsyncClient(base_url=gateway_url, headers=headers, timeout=60)

    async def on_list_tools(ctx: ServerRequestContext, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        resp = await http.get("/v1/tools")
        resp.raise_for_status()
        return types.ListToolsResult(tools=[
            types.Tool(name=t["name"], description=t.get("description", ""),
                       input_schema=t.get("inputSchema") or {"type": "object"})
            for t in resp.json()["tools"]
        ])

    async def on_call_tool(ctx: ServerRequestContext, params: types.CallToolRequestParams) -> types.CallToolResult:
        resp = await http.post("/v1/call", json={"tool": params.name, "arguments": params.arguments or {}})
        if resp.status_code >= 500 or resp.status_code in (400, 404):
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"ByteShield gateway error: {resp.text}")],
                                        is_error=True)
        body: dict[str, Any] = resp.json()
        result = body.get("result", {})
        content = [types.TextContent(type="text", text=c.get("text", "")) for c in result.get("content", [])
                   if c.get("type") == "text"]
        return types.CallToolResult(content=content or [types.TextContent(type="text", text=body.get("reason", ""))],
                                    is_error=bool(result.get("isError")) or body.get("status") != "ok")

    return Server("byteshield-bridge", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def amain(gateway_url: str, agent: str, session: str) -> None:
    server = build_server(gateway_url, agent, session)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description="stdio MCP bridge to a ByteShield gateway")
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument("--agent", default="mcp-client")
    parser.add_argument("--session", default=f"bridge-{uuid.uuid4().hex[:8]}")
    args = parser.parse_args()
    anyio.run(amain, args.gateway, args.agent, args.session)


if __name__ == "__main__":
    main()
