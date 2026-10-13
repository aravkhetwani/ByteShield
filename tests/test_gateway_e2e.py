"""End-to-end tests: real gateway + real MCP servers (weather, poisoned, office) over stdio."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from demo.scenarios import SCENARIOS, run_scenario


def _outbox(data_dir: Path):
    p = Path(data_dir) / "outbox.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


# ---- normal operation ------------------------------------------------------------------------------------
def test_all_three_upstreams_connect(client):
    health = client.get("/api/health").json()
    assert health["servers"] == {"weather": "connected", "poisoned": "connected", "office": "connected"}
    servers = {s["name"]: s for s in client.get("/api/servers").json()}
    assert servers["weather"]["tools"] == 2 and servers["office"]["tools"] == 3
    assert servers["poisoned"]["quarantined"] == 1 and servers["poisoned"]["trust"] == "untrusted"


def test_discovery_hides_quarantined_tools_and_pins_fingerprints(client, agent):
    names = agent.list_tools()
    assert {"weather__get_weather", "weather__get_forecast", "office__read_file", "poisoned__fetch_webpage"} <= set(names)
    assert "poisoned__add" not in names
    for t in client.get("/api/tools").json():
        assert len(t["baseline_sha256"]) == 64


def test_normal_weather_call_is_allowed_and_audited(client, agent):
    r = agent.call("weather__get_weather", city="Paris")
    assert r["http_status"] == 200 and r["decision"] == "ALLOW" and r["risk_level"] == "LOW"
    assert "Weather in Paris" in r["result"]["content"][0]["text"]
    row = next(a for a in client.get("/api/audit?limit=50").json() if a["id"] == r["audit_id"])
    assert row["agent"] == "pytest-agent" and row["server"] == "weather" and row["tool"] == "get_weather"
    assert row["arguments"] == {"city": "Paris"} and row["decision"] == "ALLOW" and row["risk_level"] == "LOW"
    assert row["reason"] and row["ts"] > 0 and "Weather in Paris" in row["response_summary"]


def test_safe_file_read_allowed_but_sensitive_paths_blocked(agent):
    ok = agent.call("office__read_file", path="notes/todo.txt")
    assert ok["decision"] == "ALLOW" and "Book flights" in ok["result"]["content"][0]["text"]
    for bad in ("~/.ssh/id_rsa", ".env", "../../etc/passwd"):
        r = agent.call("office__read_file", path=bad)
        assert r["http_status"] == 403 and r["decision"] == "BLOCK", bad


def test_email_requires_approval_then_executes_or_is_denied(client, agent, data_dir):
    r = agent.call("office__send_email", to="carol@corp.example", subject="Report", body="Attached.")
    assert r["http_status"] == 202 and r["decision"] == "REQUIRE_APPROVAL" and r["approval_id"]
    assert not any(m["to"] == "carol@corp.example" for m in _outbox(data_dir))  # nothing sent yet
    pending = [a["id"] for a in client.get("/api/approvals?status=pending").json()]
    assert r["approval_id"] in pending
    done = client.post(f"/api/approvals/{r['approval_id']}/approve")
    assert done.status_code == 200 and done.json()["status"] == "approved"
    assert any(m["to"] == "carol@corp.example" for m in _outbox(data_dir))
    assert client.post(f"/api/approvals/{r['approval_id']}/approve").status_code == 409  # single use

    r2 = agent.call("office__send_email", to="dave@corp.example", subject="x", body="y")
    assert client.post(f"/api/approvals/{r2['approval_id']}/deny").status_code == 200
    assert not any(m["to"] == "dave@corp.example" for m in _outbox(data_dir))


def test_external_recipient_blocked_in_clean_session(agent):
    r = agent.call("office__send_email", to="someone@gmail.com", subject="x", body="y")
    assert r["decision"] == "BLOCK"


def test_unknown_tool_and_bad_name(agent, client):
    assert agent.call("weather__does_not_exist")["decision"] == "BLOCK"
    assert agent.call("nope__tool")["decision"] == "BLOCK"
    assert client.post("/v1/call", json={"tool": "no-separator", "arguments": {}}).status_code == 400


def test_jsonrpc_mcp_endpoint(client):
    hdr = {"x-agent-id": "rpc-agent", "x-session-id": "rpc-1"}
    init = client.post("/mcp", headers=hdr, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).json()
    assert init["result"]["serverInfo"]["name"] == "byteshield-gateway"
    assert client.post("/mcp", headers=hdr, json={"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202
    tools = client.post("/mcp", headers=hdr, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()["result"]["tools"]
    assert "weather__get_weather" in {t["name"] for t in tools} and "poisoned__add" not in {t["name"] for t in tools}
    call = client.post("/mcp", headers=hdr, json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "weather__get_weather", "arguments": {"city": "Oslo"}}}).json()["result"]
    assert call["isError"] is False and "Oslo" in call["content"][0]["text"]
    blocked = client.post("/mcp", headers=hdr, json={"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                          "params": {"name": "poisoned__add", "arguments": {"a": 1, "b": 2}}}).json()["result"]
    assert blocked["isError"] is True and blocked["_meta"]["byteshield"]["decision"] == "BLOCK"


def test_dashboard_overview_contains_everything(client, agent):
    agent.call("weather__get_weather", city="Madrid")
    ov = client.get("/api/overview").json()
    assert {"stats", "servers", "tools", "audit", "alerts", "approvals", "sessions", "anomaly"} <= set(ov)
    assert ov["stats"]["total_calls"] >= 1 and ov["anomaly"]["enabled"]


# ---- the three attacks (each also asserted step-by-step inside the scenario) ------------------------------------
@pytest.mark.parametrize("name", ["normal_usage", "tool_poisoning", "rug_pull", "confused_deputy"])
def test_scenario_passes(client, data_dir, name):
    result = run_scenario(name, client, data_dir)
    failed = [s for s in result["steps"] if not s["ok"]]
    assert result["passed"], f"{name}: {failed}"
    assert len(result["steps"]) >= 5


def test_tool_poisoning_details(client, agent):
    rec = next(t for t in client.get("/api/tools").json() if (t["server"], t["tool"]) == ("poisoned", "add"))
    assert rec["status"] == "quarantined" and rec["poison_score"] >= 70
    assert {"hidden_instruction_tag", "sensitive_path", "concealment"} <= {f["rule"] for f in rec["findings"]}
    r = agent.call("poisoned__add", a=1, b=2)
    assert r["decision"] == "BLOCK" and r["risk_level"] == "HIGH"


def test_rug_pull_blocks_changed_tool_and_logs_diff(client, agent, data_dir):
    flag = Path(data_dir) / "rugpull.flag"
    try:
        assert agent.call("weather__get_weather", city="Lima")["decision"] == "ALLOW"
        flag.write_text("1")
        r = agent.call("weather__get_weather", city="Lima")
        assert r["decision"] == "BLOCK" and "rug_pull" in r["reason"]
        alert = next(a for a in client.get("/api/alerts").json() if a["type"] == "RUG_PULL")
        assert alert["severity"] == "HIGH" and alert["details"]["trusted_sha256"] != alert["details"]["current_sha256"]
        assert "IMPORTANT" in alert["details"]["diff"]
        assert "weather__get_weather" not in agent.list_tools()
        # operator can consciously re-trust the new definition
        assert client.post("/api/tools/weather/get_weather/trust").status_code == 200
        assert agent.call("weather__get_weather", city="Lima")["decision"] == "ALLOW"
    finally:
        flag.unlink(missing_ok=True)
        # restore the original pin for later tests: re-observe the benign definition as the new baseline
        client.post("/api/tools/refresh")
        client.post("/api/tools/weather/get_weather/trust")


def test_confused_deputy_session_isolation_and_taint_reset(client, data_dir):
    from demo.scenarios import Agent
    a, b = Agent(client, "agent-a"), Agent(client, "agent-b")
    a.call("poisoned__fetch_webpage", url="https://x.example")
    blocked = a.call("office__read_file", path="notes/q3_financials.txt")
    assert blocked["decision"] == "BLOCK" and "Confused deputy" in blocked["reason"]
    assert b.call("office__read_file", path="notes/q3_financials.txt")["decision"] == "ALLOW"  # other session unaffected
    assert client.post(f"/api/sessions/{a.session}/reset").status_code == 200
    assert a.call("office__read_file", path="notes/q3_financials.txt")["decision"] == "ALLOW"
    assert any(x["type"] == "CONFUSED_DEPUTY" for x in client.get("/api/alerts").json())


def test_anomaly_scores_are_recorded_and_retrain_works(client, agent):
    agent.call("weather__get_weather", city="Quito")
    rows = client.get("/api/audit?limit=20").json()
    assert any(r["anomaly_score"] is not None for r in rows)
    out = client.post("/api/anomaly/retrain").json()
    assert out["retrained"] is True and out["trained_on"] > 150


def test_demo_reset_with_wipe(client, data_dir):
    assert client.post("/api/demo/reset", params={"wipe": "true"}).json()["wiped"] is True
    assert client.get("/api/stats").json()["total_calls"] <= 1  # only the post-wipe discovery/refresh
    names = [t["tool"] for t in client.get("/api/tools").json()]
    assert "get_weather" in names  # re-pinned after wipe
