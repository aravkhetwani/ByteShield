"""SQLite persistence: audit log, alerts, trusted tool fingerprints, approvals."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    agent TEXT NOT NULL,
    session TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    arguments TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    components TEXT NOT NULL DEFAULT '{}',
    anomaly_score REAL,
    duration_ms REAL,
    response_summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    server TEXT,
    tool TEXT,
    agent TEXT,
    message TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS fingerprints (
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    baseline_sha256 TEXT NOT NULL,
    current_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    poison_score INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    baseline_definition TEXT NOT NULL DEFAULT '{}',
    current_definition TEXT NOT NULL DEFAULT '{}',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    changed_at REAL,
    PRIMARY KEY (server, tool)
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    status TEXT NOT NULL,
    audit_id INTEGER,
    agent TEXT NOT NULL,
    session TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    arguments TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    result TEXT,
    decided_at REAL
);
"""

_JSON_COLS = {"arguments", "components", "details", "findings", "baseline_definition", "current_definition", "result"}


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for key in _JSON_COLS & out.keys():
        if out[key] is not None:
            try:
                out[key] = json.loads(out[key])
            except (TypeError, ValueError):
                pass
    return out


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _exec(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [_row(r) for r in self._conn.execute(sql, params).fetchall()]  # type: ignore[misc]

    def _one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        with self._lock:
            return _row(self._conn.execute(sql, params).fetchone())

    # ---- audit -----------------------------------------------------------------
    def add_audit(self, *, agent: str, session: str, server: str, tool: str, arguments: Any, risk_level: str,
                  risk_score: int, decision: str, reason: str, components: dict | None = None,
                  anomaly_score: float | None = None, duration_ms: float | None = None,
                  response_summary: str | None = None) -> int:
        cur = self._exec(
            "INSERT INTO audit_log (ts, agent, session, server, tool, arguments, risk_level, risk_score, decision,"
            " reason, components, anomaly_score, duration_ms, response_summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), agent, session, server, tool, json.dumps(arguments, default=str), risk_level, int(risk_score),
             decision, reason, json.dumps(components or {}, default=str), anomaly_score, duration_ms, response_summary),
        )
        return int(cur.lastrowid)

    def update_audit_response(self, audit_id: int, summary: str, duration_ms: float) -> None:
        self._exec("UPDATE audit_log SET response_summary=?, duration_ms=? WHERE id=?", (summary, duration_ms, audit_id))

    def list_audit(self, limit: int = 100, offset: int = 0, decision: str | None = None,
                   since_id: int | None = None) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM audit_log", []
        clauses = []
        if decision:
            clauses.append("decision=?")
            params.append(decision)
        if since_id is not None:
            clauses.append("id>?")
            params.append(since_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return self._all(sql, params)

    def audit_for_training(self, limit: int = 5000) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM audit_log WHERE decision='ALLOW' ORDER BY id DESC LIMIT ?", (limit,))[::-1]

    def stats(self) -> dict[str, Any]:
        rows = self._all("SELECT decision, COUNT(*) AS n FROM audit_log GROUP BY decision")
        by_decision = {r["decision"]: r["n"] for r in rows}
        total = sum(by_decision.values())
        avg = self._one("SELECT AVG(risk_score) AS a, MAX(risk_score) AS m FROM audit_log") or {}
        alerts = self._one("SELECT COUNT(*) AS n FROM alerts") or {"n": 0}
        high = self._one("SELECT COUNT(*) AS n FROM alerts WHERE severity='HIGH'") or {"n": 0}
        return {
            "total_calls": total,
            "allowed": by_decision.get("ALLOW", 0),
            "approval_required": by_decision.get("REQUIRE_APPROVAL", 0),
            "blocked": by_decision.get("BLOCK", 0),
            "avg_risk": round(avg.get("a") or 0, 1),
            "max_risk": avg.get("m") or 0,
            "alerts": alerts["n"],
            "high_alerts": high["n"],
        }

    # ---- alerts ----------------------------------------------------------------
    def add_alert(self, type_: str, severity: str, message: str, server: str | None = None, tool: str | None = None,
                  agent: str | None = None, details: dict | None = None) -> int:
        cur = self._exec(
            "INSERT INTO alerts (ts, type, severity, server, tool, agent, message, details) VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), type_, severity, server, tool, agent, message, json.dumps(details or {}, default=str)),
        )
        return int(cur.lastrowid)

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    # ---- fingerprints ------------------------------------------------------------
    def get_fingerprint(self, server: str, tool: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM fingerprints WHERE server=? AND tool=?", (server, tool))

    def list_fingerprints(self) -> list[dict[str, Any]]:
        return self._all("SELECT * FROM fingerprints ORDER BY server, tool")

    def save_fingerprint(self, rec: dict[str, Any]) -> None:
        cols = ["server", "tool", "baseline_sha256", "current_sha256", "status", "reason", "poison_score", "findings",
                "description", "baseline_definition", "current_definition", "first_seen", "last_seen", "changed_at"]
        values = []
        for c in cols:
            v = rec.get(c)
            if c in _JSON_COLS and not isinstance(v, str):
                v = json.dumps(v if v is not None else ([] if c == "findings" else {}), default=str)
            values.append(v)
        self._exec(
            f"INSERT OR REPLACE INTO fingerprints ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", values
        )

    # ---- approvals ---------------------------------------------------------------
    def add_approval(self, *, audit_id: int, agent: str, session: str, server: str, tool: str, arguments: Any,
                     reason: str, risk_score: int) -> str:
        approval_id = uuid.uuid4().hex[:12]
        self._exec(
            "INSERT INTO approvals (id, ts, status, audit_id, agent, session, server, tool, arguments, reason, risk_score)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (approval_id, time.time(), "pending", audit_id, agent, session, server, tool,
             json.dumps(arguments, default=str), reason, int(risk_score)),
        )
        return approval_id

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM approvals WHERE id=?", (approval_id,))

    def list_approvals(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if status:
            return self._all("SELECT * FROM approvals WHERE status=? ORDER BY ts DESC LIMIT ?", (status, limit))
        return self._all("SELECT * FROM approvals ORDER BY ts DESC LIMIT ?", (limit,))

    def decide_approval(self, approval_id: str, status: str, result: Any = None) -> bool:
        """Atomically move a pending approval to approved/denied. False if it was no longer pending."""
        cur = self._exec(
            "UPDATE approvals SET status=?, decided_at=?, result=? WHERE id=? AND status='pending'",
            (status, time.time(), json.dumps(result, default=str) if result is not None else None, approval_id),
        )
        return cur.rowcount == 1

    def set_approval_result(self, approval_id: str, result: Any) -> None:
        self._exec("UPDATE approvals SET result=? WHERE id=?", (json.dumps(result, default=str), approval_id))

    # ---- maintenance ---------------------------------------------------------------
    def wipe(self) -> None:
        with self._lock:
            for table in ("audit_log", "alerts", "fingerprints", "approvals"):
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.commit()
