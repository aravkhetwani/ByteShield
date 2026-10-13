"""FastAPI application: agent-facing proxy endpoints, dashboard API, demo controls."""
from __future__ import annotations

import hmac
import logging
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import ROOT, Settings
from .gateway import Gateway, split_name

log = logging.getLogger("byteshield.app")
VERSION = "1.0.0"


class CallRequest(BaseModel):
    tool: str = Field(..., description="Exposed tool name '<server>__<tool>'")
    arguments: dict[str, Any] = Field(default_factory=dict)


class RugPullRequest(BaseModel):
    enabled: bool = True


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        gateway = Gateway(settings)
        app.state.gateway = gateway
        await gateway.start()
        try:
            yield
        finally:
            await gateway.stop()

    app = FastAPI(title="ByteShield", version=VERSION, lifespan=lifespan,
                  description="Runtime security gateway for MCP AI agents")
    app.state.settings = settings

    def gw(request: Request) -> Gateway:
        return request.app.state.gateway

    async def admin(request: Request) -> None:
        token = settings.admin_token
        if token and not hmac.compare_digest(request.headers.get("x-admin-token", ""), token):
            raise HTTPException(401, "admin token required (X-Admin-Token header)")

    def identity(request: Request) -> tuple[str, str]:
        agent = request.headers.get("x-agent-id", "agent")[:80]
        session = request.headers.get("x-session-id", f"{agent}-default")[:120]
        return agent, session

    # ---------------------------------------------------------------- health
    @app.get("/api/health")
    async def health(request: Request):
        g = gw(request)
        return {"status": "ok", "version": VERSION, "mode": g.policy.mode, "demo_mode": settings.demo_mode,
                "servers": {n: u.status for n, u in g.upstream.servers.items()}}

    # ---------------------------------------------------------------- agent-facing
    @app.get("/v1/tools")
    async def agent_list_tools(request: Request):
        agent, session = identity(request)
        tools = await gw(request).list_agent_tools(agent, session)
        return {"tools": tools}

    @app.post("/v1/call")
    async def agent_call(body: CallRequest, request: Request):
        agent, session = identity(request)
        try:
            server, tool = split_name(body.tool)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        out = await gw(request).call_tool(server, tool, body.arguments, agent, session)
        status = out.pop("http_status")
        return JSONResponse(out, status_code=status)

    @app.post("/mcp")
    async def mcp_jsonrpc(request: Request):
        """Minimal MCP-over-HTTP (JSON-RPC 2.0) endpoint: initialize, ping, tools/list, tools/call."""
        agent, session = identity(request)
        g = gw(request)
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})

        async def handle(msg: dict[str, Any]) -> dict[str, Any] | None:
            mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
            if mid is None:
                return None  # notification
            try:
                if method == "initialize":
                    result: dict[str, Any] = {
                        "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "byteshield-gateway", "version": VERSION}}
                elif method == "ping":
                    result = {}
                elif method == "tools/list":
                    tools = await g.list_agent_tools(agent, session)
                    result = {"tools": [{k: v for k, v in t.items() if k != "_byteshield"} for t in tools]}
                elif method == "tools/call":
                    server, tool = split_name(str(params.get("name", "")))
                    out = await g.call_tool(server, tool, params.get("arguments") or {}, agent, session)
                    result = {k: v for k, v in out["result"].items() if k != "_byteshield"}
                    result["_meta"] = {"byteshield": {k: out[k] for k in ("decision", "risk_level", "risk_score", "reason")}}
                else:
                    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
            except ValueError as exc:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(exc)}}
            return {"jsonrpc": "2.0", "id": mid, "result": result}

        if isinstance(payload, list):
            replies = [r for r in [await handle(m) for m in payload if isinstance(m, dict)] if r is not None]
            return JSONResponse(replies) if replies else Response(status_code=202)
        if not isinstance(payload, dict):
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
        reply = await handle(payload)
        return Response(status_code=202) if reply is None else JSONResponse(reply)

    # ---------------------------------------------------------------- dashboard / admin API
    @app.get("/api/overview", dependencies=[Depends(admin)])
    async def overview(request: Request):
        return gw(request).overview()

    @app.get("/api/servers", dependencies=[Depends(admin)])
    async def servers(request: Request):
        return gw(request).servers_view()

    @app.get("/api/tools", dependencies=[Depends(admin)])
    async def tools(request: Request):
        return gw(request).tools_view()

    @app.post("/api/tools/refresh", dependencies=[Depends(admin)])
    async def refresh(request: Request):
        g = gw(request)
        await g.refresh_tools("dashboard")
        return g.tools_view()

    @app.post("/api/tools/{server}/{tool}/trust", dependencies=[Depends(admin)])
    async def trust_tool(server: str, tool: str, request: Request):
        rec = gw(request).registry.trust(server, tool)
        if rec is None:
            raise HTTPException(404, "unknown tool")
        return {"server": server, "tool": tool, "status": rec["status"]}

    @app.get("/api/audit", dependencies=[Depends(admin)])
    async def audit(request: Request, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                    decision: str | None = None, since_id: int | None = None):
        return gw(request).store.list_audit(limit, offset, decision.upper() if decision else None, since_id)

    @app.get("/api/alerts", dependencies=[Depends(admin)])
    async def alerts(request: Request, limit: int = Query(100, ge=1, le=1000)):
        return gw(request).store.list_alerts(limit)

    @app.get("/api/stats", dependencies=[Depends(admin)])
    async def stats(request: Request):
        return gw(request).store.stats()

    @app.get("/api/policy", dependencies=[Depends(admin)])
    async def policy(request: Request):
        return gw(request).policy_cfg

    @app.get("/api/approvals", dependencies=[Depends(admin)])
    async def approvals(request: Request, status: str | None = None):
        return gw(request).store.list_approvals(status)

    @app.get("/api/approvals/{approval_id}")
    async def approval_status(approval_id: str, request: Request):
        """Agents may poll their own approval by its unguessable id."""
        rec = gw(request).get_approval(approval_id)
        if rec is None:
            raise HTTPException(404, "unknown approval id")
        return {"id": rec["id"], "status": rec["status"], "result": rec["result"]}

    @app.post("/api/approvals/{approval_id}/approve", dependencies=[Depends(admin)])
    async def approve(approval_id: str, request: Request):
        out = await gw(request).approve(approval_id)
        return JSONResponse(out, status_code=out.pop("http_status"))

    @app.post("/api/approvals/{approval_id}/deny", dependencies=[Depends(admin)])
    async def deny(approval_id: str, request: Request):
        out = gw(request).deny(approval_id)
        return JSONResponse(out, status_code=out.pop("http_status"))

    @app.post("/api/sessions/{session}/reset", dependencies=[Depends(admin)])
    async def reset_session(session: str, request: Request):
        gw(request).tracker.reset(session)
        return {"session": session, "tainted": False}

    @app.get("/api/anomaly", dependencies=[Depends(admin)])
    async def anomaly_info(request: Request):
        return gw(request).anomaly.info()

    @app.post("/api/anomaly/retrain", dependencies=[Depends(admin)])
    async def anomaly_retrain(request: Request):
        return await run_in_threadpool(gw(request).retrain_anomaly)

    # ---------------------------------------------------------------- demo controls
    def require_demo() -> None:
        if not settings.demo_mode:
            raise HTTPException(404, "demo mode is disabled (set BYTESHIELD_DEMO=1)")

    @app.post("/api/demo/rugpull", dependencies=[Depends(admin), Depends(require_demo)])
    async def demo_rugpull(body: RugPullRequest):
        flag = settings.data_dir / "rugpull.flag"
        if body.enabled:
            flag.write_text("1", encoding="utf-8")
        else:
            flag.unlink(missing_ok=True)
        return {"rugpull_active": flag.exists()}

    @app.post("/api/demo/reset", dependencies=[Depends(admin), Depends(require_demo)])
    async def demo_reset(request: Request, wipe: bool = False):
        g = gw(request)
        (settings.data_dir / "rugpull.flag").unlink(missing_ok=True)
        (settings.data_dir / "outbox.jsonl").unlink(missing_ok=True)
        g.tracker.reset()
        g.anomaly.reset_sessions()
        if wipe:
            g.store.wipe()
        await g.refresh_tools("demo-reset")
        return {"reset": True, "wiped": wipe}

    @app.get("/api/demo/scenarios", dependencies=[Depends(admin), Depends(require_demo)])
    async def demo_scenarios():
        _ensure_root_on_path()
        from demo.scenarios import SCENARIOS
        return [{"id": k, "title": v["title"], "description": v["description"]} for k, v in SCENARIOS.items()]

    @app.post("/api/demo/run/{scenario}", dependencies=[Depends(admin), Depends(require_demo)])
    async def demo_run(scenario: str, request: Request):
        _ensure_root_on_path()
        import httpx
        from demo.scenarios import SCENARIOS, run_scenario
        if scenario not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario; choose from {sorted(SCENARIOS)}")
        headers = {"x-admin-token": settings.admin_token} if settings.admin_token else {}

        def work() -> dict[str, Any]:
            with httpx.Client(base_url=str(request.base_url), timeout=60, headers=headers) as client:
                return run_scenario(scenario, client, settings.data_dir)

        return await run_in_threadpool(work)

    # ---------------------------------------------------------------- dashboard static files
    dist = settings.dashboard_dir
    if dist.is_dir() and (dist / "index.html").is_file():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    else:
        @app.get("/", response_class=HTMLResponse)
        async def no_dashboard():
            return ("<h1>ByteShield gateway is running</h1><p>The dashboard has not been built yet. "
                    "Run <code>cd dashboard &amp;&amp; npm install &amp;&amp; npm run build</code>, or use "
                    "<code>npm run dev</code> (port 5173). API docs: <a href='/docs'>/docs</a></p>")

    return app


def _ensure_root_on_path() -> None:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
