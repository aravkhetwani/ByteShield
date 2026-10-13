"""ByteShield gateway core: AI Agent -> [discovery / call / response interception] -> MCP servers."""
from __future__ import annotations

import logging
import time
from typing import Any

from .anomaly import AnomalyDetector, events_from_audit, synthetic_baseline
from .config import Settings
from .db import Store
from .fingerprint import QUARANTINED, FingerprintRegistry
from .policy import ALLOW, BLOCK, REQUIRE_APPROVAL, PolicyEngine, Verdict
from .poisoning import scan_response_text
from .taint import SessionTracker, TaintCheck, flatten_strings
from .upstream import UpstreamManager

log = logging.getLogger("byteshield.gateway")

SEP = "__"  # exposed tool name = "<server>__<tool>"
GATEWAY_SERVER = "gateway"


def exposed_name(server: str, tool: str) -> str:
    return f"{server}{SEP}{tool}"


def split_name(name: str) -> tuple[str, str]:
    server, sep, tool = name.partition(SEP)
    if not sep or not server or not tool:
        raise ValueError(f"tool name must look like '<server>{SEP}<tool>', got {name!r}")
    return server, tool


def result_text(result: dict[str, Any]) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def text_result(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class Gateway:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.policy_cfg = settings.load_policy()
        self.policy = PolicyEngine(self.policy_cfg)
        self.store = Store(settings.db_path)
        self.registry = FingerprintRegistry(self.store, self.policy.poison_block_score)
        deputy = self.policy_cfg.get("confused_deputy", {}) or {}
        self.tracker = SessionTracker(float(deputy.get("taint_ttl_seconds", 900)), int(deputy.get("min_overlap_len", 12)))
        anomaly_cfg = self.policy_cfg.get("anomaly", {}) or {}
        self.anomaly = AnomalyDetector(enabled=bool(anomaly_cfg.get("enabled", True)))
        self.upstream = UpstreamManager(settings.load_upstreams())
        self.started_at = time.time()

    # ---- lifecycle ---------------------------------------------------------------------------------
    async def start(self) -> None:
        await self.upstream.start()
        await self.refresh_tools(agent="gateway-startup")

    async def stop(self) -> None:
        await self.upstream.stop()
        self.store.close()

    # ---- discovery ---------------------------------------------------------------------------------
    async def refresh_server(self, server: str, agent: str = "gateway") -> list[dict[str, Any]]:
        try:
            tools = await self.upstream.list_tools(server)
        except Exception as exc:  # noqa: BLE001
            self.store.add_alert("SERVER_ERROR", "MEDIUM", f"Could not list tools from '{server}': {exc}", server,
                                 agent=agent)
            return []
        return [self.registry.observe(server, t["name"], t["description"], t["inputSchema"], agent) for t in tools]

    async def refresh_tools(self, agent: str = "gateway") -> None:
        for name in self.upstream.servers:
            if self.upstream.is_connected(name):
                await self.refresh_server(name, agent)

    async def list_agent_tools(self, agent: str, session: str) -> list[dict[str, Any]]:
        """Tool discovery as seen by the agent: fresh fingerprints, quarantined tools hidden."""
        await self.refresh_tools(agent)
        exposed, hidden = [], []
        current = {(r["server"], r["tool"]): r for r in self.store.list_fingerprints()}
        for name, up in self.upstream.servers.items():
            if not self.upstream.is_connected(name):
                continue
            for tool in sorted(up.tool_names):
                rec = current.get((name, tool))
                if rec is None:
                    continue
                if rec["status"] == QUARANTINED and self.policy.enforcing:
                    hidden.append(exposed_name(name, tool))
                    continue
                definition = rec["current_definition"]
                exposed.append({
                    "name": exposed_name(name, tool),
                    "description": definition.get("description", ""),
                    "inputSchema": definition.get("inputSchema", {}),
                    "_byteshield": {"server": name, "tool": tool, "sha256": rec["current_sha256"],
                                    "status": rec["status"]},
                })
        reason = f"Listed {len(exposed)} tools" + (f"; hid {len(hidden)} quarantined: {', '.join(hidden)}" if hidden else "")
        self.store.add_audit(agent=agent, session=session, server=GATEWAY_SERVER, tool="tools/list", arguments={},
                             risk_level="LOW" if not hidden else "MEDIUM", risk_score=0 if not hidden else 40,
                             decision=ALLOW, reason=reason, components={"hidden": hidden})
        return exposed

    # ---- tool calls ----------------------------------------------------------------------------------
    async def call_tool(self, server: str, tool: str, arguments: dict[str, Any] | None, agent: str,
                        session: str) -> dict[str, Any]:
        arguments = arguments or {}
        if server not in self.upstream.servers or not self.upstream.is_connected(server):
            verdict = Verdict(BLOCK, "HIGH", 90, [f"Unknown or unavailable MCP server '{server}'"], {})
            audit_id = self._audit(agent, session, server, tool, arguments, verdict, None)
            return self._outcome(verdict, audit_id, text_result(f"ByteShield: {verdict.reason}", True), enforced=True)

        if self.policy_cfg.get("verify_on_call", True):
            await self.refresh_server(server, agent)  # catches rug pulls that happen between list and call

        fingerprint = self.store.get_fingerprint(server, tool)
        if fingerprint is not None and tool not in self.upstream.servers[server].tool_names:
            fingerprint = None  # no longer advertised by its server
        tp = self.policy.tool_policy(server, tool)
        privileged = bool(tp.get("privileged", False))
        taint = self.tracker.check(session, arguments)
        arg_chars = sum(len(s) for s in flatten_strings(arguments))
        anomaly = self.anomaly.score(session, f"{server}.{tool}", len(arguments), arg_chars, privileged, taint.tainted)
        verdict = self.policy.evaluate(server, tool, arguments, fingerprint, taint, anomaly)
        if not self.policy.enforcing and verdict.decision != ALLOW:
            verdict.reasons.append("monitor mode: not enforced")
        audit_id = self._audit(agent, session, server, tool, arguments, verdict, anomaly)
        self._raise_alerts(verdict, taint, server, tool, agent, anomaly)

        effective = verdict.decision if self.policy.enforcing else ALLOW
        if effective == BLOCK:
            return self._outcome(verdict, audit_id, text_result(
                f"ByteShield BLOCKED this call to {server}.{tool}: {verdict.reason} "
                f"(risk {verdict.risk_level}, score {verdict.risk_score}).", True), enforced=True)
        if effective == REQUIRE_APPROVAL:
            approval_id = self.store.add_approval(audit_id=audit_id, agent=agent, session=session, server=server,
                                                  tool=tool, arguments=arguments, reason=verdict.reason,
                                                  risk_score=verdict.risk_score)
            out = self._outcome(verdict, audit_id, text_result(
                f"ByteShield: this call to {server}.{tool} needs human approval ({verdict.reason}). "
                f"Approval id: {approval_id}.", True), enforced=True)
            out["approval_id"] = approval_id
            return out

        result = await self._execute(server, tool, arguments, agent, session, audit_id)
        return self._outcome(verdict, audit_id, result, enforced=self.policy.enforcing)

    async def _execute(self, server: str, tool: str, arguments: dict[str, Any], agent: str, session: str,
                       audit_id: int) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            result = await self.upstream.call_tool(server, tool, arguments)
        except Exception as exc:  # noqa: BLE001
            result = text_result(f"Upstream error from {server}.{tool}: {type(exc).__name__}: {exc}", True)
        result = self._inspect_response(result, server, tool, agent, session)
        text = result_text(result)
        self.store.update_audit_response(audit_id, text[:300], (time.perf_counter() - started) * 1000)
        return result

    def _inspect_response(self, result: dict[str, Any], server: str, tool: str, agent: str,
                          session: str) -> dict[str, Any]:
        """Scan tool output for indirect prompt injection and taint the session if needed."""
        text = result_text(result)
        scan = scan_response_text(text)
        cfg = self.policy.poisoning
        flagged = scan["score"] >= int(cfg.get("response_flag_score", 40))
        untrusted = self.policy.server_trust(server) == "untrusted"
        if untrusted or flagged:
            reason = "prompt injection detected in output" if flagged else "output of untrusted server"
            self.tracker.mark_tainted(session, f"{server}.{tool}", text, reason)
        if flagged:
            withhold = (str(cfg.get("response_action", "FLAG")).upper() == "WITHHOLD"
                        and scan["score"] >= int(cfg.get("withhold_score", 70)) and self.policy.enforcing)
            self.store.add_alert(
                "INJECTION_IN_RESPONSE", "HIGH" if scan["score"] >= 70 else "MEDIUM",
                f"Output of {server}.{tool} contains likely prompt injection (score {scan['score']}); "
                f"session '{session}' is now tainted" + ("; output withheld" if withhold else ""),
                server, tool, agent, {"findings": scan["findings"]})
            if withhold:
                result = text_result("[ByteShield withheld this tool output: it contained prompt-injection "
                                     "instructions.]", True)
        result["_byteshield"] = {"response_scan": {"score": scan["score"], "rules": [f["rule"] for f in scan["findings"]]}}
        return result

    # ---- approvals ---------------------------------------------------------------------------------------
    async def approve(self, approval_id: str, approver: str = "operator") -> dict[str, Any]:
        rec = self.store.get_approval(approval_id)
        if rec is None:
            return {"error": "unknown approval id", "http_status": 404}
        if rec["status"] != "pending":
            return {"error": f"approval already {rec['status']}", "http_status": 409}
        server, tool, args = rec["server"], rec["tool"], rec["arguments"]
        if self.upstream.is_connected(server) and self.policy_cfg.get("verify_on_call", True):
            await self.refresh_server(server, "approval")
        fp = self.store.get_fingerprint(server, tool)
        if fp is None or fp["status"] != "trusted":
            self.store.decide_approval(approval_id, "denied", {"error": "tool quarantined before approval"})
            return {"error": "tool definition is quarantined; approval refused", "http_status": 409}
        if not self.store.decide_approval(approval_id, "approved"):
            return {"error": "approval already decided", "http_status": 409}
        verdict = Verdict(ALLOW, "MEDIUM", rec["risk_score"], [f"Approved by {approver} (approval {approval_id})"],
                          {"approval_id": approval_id})
        audit_id = self._audit(rec["agent"], rec["session"], server, tool, args, verdict, None)
        result = await self._execute(server, tool, args, rec["agent"], rec["session"], audit_id)
        self.store.set_approval_result(approval_id, result)
        return {"approval_id": approval_id, "status": "approved", "result": result, "audit_id": audit_id,
                "http_status": 200}

    def deny(self, approval_id: str, approver: str = "operator") -> dict[str, Any]:
        rec = self.store.get_approval(approval_id)
        if rec is None:
            return {"error": "unknown approval id", "http_status": 404}
        if not self.store.decide_approval(approval_id, "denied"):
            return {"error": f"approval already {rec['status']}", "http_status": 409}
        verdict = Verdict(BLOCK, "MEDIUM", rec["risk_score"], [f"Denied by {approver} (approval {approval_id})"], {})
        self._audit(rec["agent"], rec["session"], rec["server"], rec["tool"], rec["arguments"], verdict, None)
        return {"approval_id": approval_id, "status": "denied", "http_status": 200}

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        return self.store.get_approval(approval_id)

    # ---- helpers -------------------------------------------------------------------------------------------
    def _audit(self, agent: str, session: str, server: str, tool: str, arguments: Any, verdict: Verdict,
               anomaly: dict[str, Any] | None) -> int:
        return self.store.add_audit(
            agent=agent, session=session, server=server, tool=tool, arguments=arguments,
            risk_level=verdict.risk_level, risk_score=verdict.risk_score, decision=verdict.decision,
            reason=verdict.reason, components=verdict.components,
            anomaly_score=anomaly["score"] if anomaly and anomaly.get("enabled") else None)

    def _raise_alerts(self, verdict: Verdict, taint: TaintCheck, server: str, tool: str, agent: str,
                      anomaly: dict[str, Any]) -> None:
        comps = verdict.components
        details = {"reason": verdict.reason, "risk_score": verdict.risk_score}
        if "taint" in comps and verdict.decision != ALLOW:
            kind = "CONFUSED_DEPUTY"
            self.store.add_alert(kind, "HIGH" if verdict.decision == BLOCK else "MEDIUM",
                                 f"{verdict.decision} {server}.{tool}: {verdict.reason}", server, tool, agent,
                                 {**details, "taint": comps["taint"]})
        elif verdict.decision == BLOCK:
            kind = "QUARANTINED_TOOL_CALL" if "fingerprint_status" in comps else (
                "SENSITIVE_ARGUMENT" if "argument_rules" in comps else "POLICY_BLOCK")
            self.store.add_alert(kind, "HIGH", f"BLOCK {server}.{tool}: {verdict.reason}", server, tool, agent, details)
        if comps.get("anomaly_flagged"):
            self.store.add_alert("ANOMALY", "MEDIUM",
                                 f"Anomalous call sequence for {server}.{tool} (Isolation Forest score "
                                 f"{anomaly['score']:.2f} > {anomaly['threshold']:.2f})", server, tool, agent, anomaly)

    def _outcome(self, verdict: Verdict, audit_id: int, result: dict[str, Any], enforced: bool) -> dict[str, Any]:
        status = {BLOCK: "blocked", REQUIRE_APPROVAL: "approval_required", ALLOW: "ok"}[verdict.decision]
        if not enforced and verdict.decision != ALLOW:
            status = "ok"
        http = {"ok": 200, "blocked": 403, "approval_required": 202}[status]
        if status == "ok" and result.get("isError"):
            status, http = "error", 200
        return {"status": status, "http_status": http, "decision": verdict.decision, "enforced": enforced,
                "risk_level": verdict.risk_level, "risk_score": verdict.risk_score, "reason": verdict.reason,
                "audit_id": audit_id, "result": result}

    # ---- dashboard data ------------------------------------------------------------------------------------
    def servers_view(self) -> list[dict[str, Any]]:
        fps = self.store.list_fingerprints()
        out = []
        for name, up in self.upstream.servers.items():
            mine = [f for f in fps if f["server"] == name]
            out.append({
                "name": name, "trust": self.policy.server_trust(name), "status": up.status, "error": up.error,
                "command": f"{up.config.command} {' '.join(up.config.args)}".strip(),
                "tools": len(mine), "quarantined": sum(1 for f in mine if f["status"] == QUARANTINED),
                "last_refresh": up.last_refresh,
            })
        return out

    def tools_view(self) -> list[dict[str, Any]]:
        rows = []
        for f in self.store.list_fingerprints():
            tp = self.policy.tool_policy(f["server"], f["tool"])
            rows.append({
                "server": f["server"], "tool": f["tool"], "status": f["status"], "reason": f["reason"],
                "baseline_sha256": f["baseline_sha256"], "current_sha256": f["current_sha256"],
                "changed": f["baseline_sha256"] != f["current_sha256"], "poison_score": f["poison_score"],
                "findings": f["findings"], "description": f["description"], "privileged": bool(tp.get("privileged")),
                "base_risk": tp.get("base_risk"), "first_seen": f["first_seen"], "changed_at": f["changed_at"],
            })
        return rows

    def overview(self) -> dict[str, Any]:
        return {
            "now": time.time(), "mode": self.policy.mode,
            "stats": self.store.stats(), "servers": self.servers_view(), "tools": self.tools_view(),
            "audit": self.store.list_audit(150), "alerts": self.store.list_alerts(60),
            "approvals": self.store.list_approvals("pending"),
            "sessions": self.tracker.snapshot(), "anomaly": self.anomaly.info(),
        }

    def retrain_anomaly(self) -> dict[str, Any]:
        rows = [r for r in self.store.audit_for_training() if r["server"] != GATEWAY_SERVER]
        events = events_from_audit(rows)
        ok =self.anomaly.fit(events + synthetic_baseline(), source=f"audit log ({len(events)} calls) + synthetic baseline")
        return {"retrained": ok, **self.anomaly.info()}
