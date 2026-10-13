import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, getToken, setToken } from "./api.js";
import {
  Badge, DecisionBadge, Empty, Panel, RiskBar, Sparkline,
  compactArgs, fmtDateTime, fmtTime, severityKind, short, statusKind,
} from "./components.jsx";

const POLL_MS = 1500;

export default function App() {
  const [data, setData] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(null);
  const [needsToken, setNeedsToken] = useState(false);
  const busy = useRef(false);
  const [tab, setTabState] = useState(() => window.location.hash.slice(1) || "overview");
  const setTab = (t) => {
    setTabState(t);
    window.location.hash = t;
  };

  const load = useCallback(async () => {
    if (busy.current) return;
    busy.current = true;
    try {
      const [overview, hl] = await Promise.all([api("/api/overview"), api("/api/health")]);
      setData(overview);
      setHealth(hl);
      setError(null);
      setNeedsToken(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setNeedsToken(true);
      setError(e.message);
    } finally {
      busy.current = false;
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  if (needsToken) return <TokenGate onSaved={load} />;

  return (
    <div className="app">
      <Header data={data} error={error} />
      {!data ? (
        <p className="empty big">{error ? `Cannot reach the gateway: ${error}` : "Connecting to the gateway…"}</p>
      ) : (
        <>
          <Tabs tab={tab} setTab={setTab} data={data} demo={health?.demo_mode} />
          <main>
            <Approvals items={data.approvals} refresh={load} />
            {tab === "overview" && (
              <>
                <Stats data={data} />
                <div className="grid two">
                  <Servers servers={data.servers} sessions={data.sessions} anomaly={data.anomaly} refresh={load} />
                  <BlockedCalls audit={data.audit} />
                </div>
              </>
            )}
            {tab === "live" && <LiveFeed audit={data.audit} limit={40} />}
            {tab === "tools" && <Fingerprints tools={data.tools} refresh={load} />}
            {tab === "alerts" && <Alerts alerts={data.alerts} limit={60} />}
            {tab === "audit" && <AuditLog />}
            {tab === "demo" && health?.demo_mode && <DemoPanel refresh={load} />}
          </main>
        </>
      )}
    </div>
  );
}

function Tabs({ tab, setTab, data, demo }) {
  const tabs = [
    ["overview", "Overview", null],
    ["live", "Live traffic", null],
    ["tools", "Tools & fingerprints", data.tools.filter((t) => t.status === "quarantined").length || null],
    ["alerts", "Alerts", data.stats.high_alerts || null],
    ["audit", "Audit log", null],
    ...(demo ? [["demo", "Attack demos", null]] : []),
  ];
  return (
    <nav className="tabs" role="tablist">
      {tabs.map(([id, label, count]) => (
        <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>
          {label}
          {count ? <span className="count">{count}</span> : null}
        </button>
      ))}
    </nav>
  );
}

function TokenGate({ onSaved }) {
  const [value, setValue] = useState(getToken());
  return (
    <div className="gate">
      <h1>ByteShield</h1>
      <p>This gateway requires an admin token.</p>
      <input type="password" value={value} onChange={(e) => setValue(e.target.value)} placeholder="X-Admin-Token" />
      <button onClick={() => { setToken(value); onSaved(); }}>Unlock dashboard</button>
    </div>
  );
}

function Header({ data, error }) {
  const live = data && !error;
  return (
    <header className="top">
      <div className="brand">
        <svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true">
          <path fill="currentColor" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z" />
          <path fill="none" stroke="var(--bg)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="m8.5 12 2.5 2.5 4.5-5" />
        </svg>
        <div>
          <h1>ByteShield</h1>
          <span>Runtime security gateway for MCP agents</span>
        </div>
      </div>
      <div className="flow" aria-label="architecture">
        <span>AI Agent</span><i>→</i><b>ByteShield Gateway</b><i>→</i><span>MCP Servers</span>
      </div>
      <div className="status">
        {data && <Badge kind={data.mode === "enforce" ? "ok" : "warn"}>{data.mode.toUpperCase()} MODE</Badge>}
        <span className={`live ${live ? "on" : "off"}`}>{live ? "live" : "offline"}</span>
      </div>
    </header>
  );
}

function Stats({ data }) {
  const s = data.stats;
  const risks = useMemo(
    () => data.audit.filter((a) => a.server !== "gateway").slice(0, 60).reverse().map((a) => a.risk_score),
    [data.audit]
  );
  const tiles = [
    ["Tool calls", s.total_calls, ""],
    ["Allowed", s.allowed, "ok"],
    ["Needs approval", s.approval_required, "warn"],
    ["Blocked", s.blocked, "bad"],
    ["Alerts", s.alerts, s.high_alerts ? "bad" : ""],
    ["Avg risk", s.avg_risk, ""],
  ];
  return (
    <div className="stats">
      {tiles.map(([label, value, kind]) => (
        <div className={`tile ${kind}`} key={label}>
          <span className="v">{value}</span>
          <span className="l">{label}</span>
        </div>
      ))}
      <div className="tile wide">
        <Sparkline values={risks} />
        <span className="l">Risk score, last {risks.length} calls (line = HIGH threshold)</span>
      </div>
    </div>
  );
}

function Approvals({ items, refresh }) {
  const [err, setErr] = useState(null);
  if (!items.length) return null;
  const act = async (id, verb) => {
    try {
      await api(`/api/approvals/${id}/${verb}`, { method: "POST" });
      setErr(null);
    } catch (e) {
      setErr(e.message);
    }
    refresh();
  };
  return (
    <Panel title={`Pending approvals (${items.length})`} className="attention">
      {err && <p className="err">{err}</p>}
      {items.map((a) => (
        <div className="approval" key={a.id}>
          <div>
            <b>{a.server}.{a.tool}</b> <code>{compactArgs(a.arguments, 120)}</code>
            <div className="sub">{a.agent} · session {a.session} · {a.reason}</div>
          </div>
          <div className="btns">
            <button className="good" onClick={() => act(a.id, "approve")}>Approve & run</button>
            <button className="danger" onClick={() => act(a.id, "deny")}>Deny</button>
          </div>
        </div>
      ))}
    </Panel>
  );
}

function DemoPanel({ refresh }) {
  const [scenarios, setScenarios] = useState([]);
  const [running, setRunning] = useState(null);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    api("/api/demo/scenarios").then(setScenarios).catch((e) => setErr(e.message));
  }, []);

  const run = async (id) => {
    setRunning(id);
    setErr(null);
    try {
      setResult(await api(`/api/demo/run/${id}`, { method: "POST" }));
    } catch (e) {
      setErr(e.message);
    }
    setRunning(null);
    refresh();
  };
  const reset = async () => {
    setResult(null);
    try {
      await api("/api/demo/reset?wipe=true", { method: "POST" });
    } catch (e) {
      setErr(e.message);
    }
    refresh();
  };

  return (
    <Panel title="Attack demos" right={<button className="ghost" onClick={reset}>Reset demo data</button>}>
      <div className="scenarios">
        {scenarios.map((s) => (
          <button key={s.id} disabled={!!running} onClick={() => run(s.id)} title={s.description}>
            {running === s.id ? "Running…" : s.title}
          </button>
        ))}
      </div>
      {err && <p className="err">{err}</p>}
      {result && (
        <div className="report">
          <h3>
            {result.title} <Badge kind={result.passed ? "ok" : "bad"}>{result.passed ? "DEFENDED" : "FAILED"}</Badge>
          </h3>
          <ol>
            {result.steps.map((s, i) => (
              <li key={i} className={s.ok ? "ok" : "bad"}>
                <span>{s.title}</span>
                <small>expected {s.expected} · got <b>{s.actual}</b>{s.detail ? ` — ${s.detail}` : ""}</small>
              </li>
            ))}
          </ol>
          <p className="sub">{result.summary}</p>
        </div>
      )}
    </Panel>
  );
}

function LiveFeed({ audit, limit = 14 }) {
  const rows = audit.slice(0, limit);
  return (
    <Panel title="Live requests" right={<Badge kind="mute">auto-refresh {POLL_MS / 1000}s</Badge>}>
      {!rows.length && <Empty>No traffic yet. Run an attack demo or point an agent at /v1 or /mcp.</Empty>}
      <ul className="feed">
        {rows.map((a) => (
          <li key={a.id} className={`d-${a.decision}`}>
            <div className="l1">
              <time>{fmtTime(a.ts)}</time>
              <b>{a.server === "gateway" ? "tools/list" : `${a.server}.${a.tool}`}</b>
              <DecisionBadge decision={a.decision} />
              <RiskBar score={a.risk_score} level={a.risk_level} />
            </div>
            <div className="l2">
              <span className="agent">{a.agent}</span>
              {a.server !== "gateway" && <code>{compactArgs(a.arguments)}</code>}
            </div>
            <div className="l3">{a.reason}</div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Alerts({ alerts, limit = 14 }) {
  return (
    <Panel title={`Alerts (${alerts.length})`}>
      {!alerts.length && <Empty>No alerts. The gateway raises one for poisoning, rug pulls, injected output and blocked attacks.</Empty>}
      <ul className="alerts">
        {alerts.slice(0, limit).map((a) => (
          <li key={a.id}>
            <div className="l1">
              <Badge kind={severityKind(a.severity)}>{a.severity}</Badge>
              <b>{a.type.replaceAll("_", " ")}</b>
              <time>{fmtTime(a.ts)}</time>
            </div>
            <p>{a.message}</p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Servers({ servers, sessions, anomaly, refresh }) {
  const tainted = Object.entries(sessions || {});
  const refreshTools = async () => {
    await api("/api/tools/refresh", { method: "POST" });
    refresh();
  };
  return (
    <Panel title="Connected MCP servers" right={<button className="ghost" onClick={refreshTools}>Re-scan tools</button>}>
      <table>
        <thead><tr><th>Server</th><th>Trust</th><th>Status</th><th>Tools</th><th>Quarantined</th></tr></thead>
        <tbody>
          {servers.map((s) => (
            <tr key={s.name} title={s.error || s.command}>
              <td><b>{s.name}</b></td>
              <td><Badge kind={s.trust === "trusted" ? "ok" : "warn"}>{s.trust}</Badge></td>
              <td><Badge kind={statusKind(s.status)}>{s.status}</Badge></td>
              <td>{s.tools}</td>
              <td className={s.quarantined ? "bad-text" : ""}>{s.quarantined}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="meta">
        <div>
          <span className="l">Tainted sessions</span>
          {tainted.length ? tainted.map(([sid, src]) => (
            <div key={sid}><code>{sid}</code> <small>← {[...new Set(src.map((x) => x.origin))].join(", ")}</small></div>
          )) : <small> none</small>}
        </div>
        <div>
          <span className="l">Isolation Forest</span>
          <small>
            {anomaly.enabled
              ? ` trained on ${anomaly.trained_on} calls (${anomaly.source}); flag > ${anomaly.threshold}`
              : " disabled"}
          </small>
        </div>
      </div>
    </Panel>
  );
}

function BlockedCalls({ audit }) {
  const blocked = audit.filter((a) => a.decision === "BLOCK").slice(0, 8);
  return (
    <Panel title="Blocked calls">
      {!blocked.length && <Empty>Nothing blocked yet.</Empty>}
      <ul className="blocked">
        {blocked.map((a) => (
          <li key={a.id}>
            <div className="l1">
              <b>{a.server}.{a.tool}</b>
              <RiskBar score={a.risk_score} level={a.risk_level} />
              <time>{fmtTime(a.ts)}</time>
            </div>
            <p>{a.reason}</p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Fingerprints({ tools, refresh }) {
  const [open, setOpen] = useState(null);
  const trust = async (t) => {
    if (!window.confirm(`Accept the CURRENT definition of ${t.server}.${t.tool} as the new trusted baseline?`)) return;
    await api(`/api/tools/${t.server}/${t.tool}/trust`, { method: "POST" });
    refresh();
  };
  return (
    <Panel title="Tool fingerprints (SHA-256 of name + description + schema)">
      <div className="scroll">
        <table>
          <thead>
            <tr><th>Tool</th><th>Status</th><th>Trusted fingerprint</th><th>Current fingerprint</th><th>Poison score</th><th>Privileged</th><th /></tr>
          </thead>
          <tbody>
            {tools.map((t) => {
              const key = `${t.server}.${t.tool}`;
              return (
                <React.Fragment key={key}>
                  <tr className={`click ${t.status}`} onClick={() => setOpen(open === key ? null : key)}>
                    <td><b>{key}</b></td>
                    <td><Badge kind={statusKind(t.status)}>{t.status}</Badge></td>
                    <td><code title={t.baseline_sha256}>{short(t.baseline_sha256, 16)}…</code></td>
                    <td><code className={t.changed ? "bad-text" : ""} title={t.current_sha256}>{short(t.current_sha256, 16)}…</code>{t.changed && " ≠"}</td>
                    <td><RiskBar score={t.poison_score} level={t.poison_score >= 50 ? "HIGH" : t.poison_score >= 25 ? "MEDIUM" : "LOW"} /></td>
                    <td>{t.privileged ? <Badge kind="warn">privileged</Badge> : "—"}</td>
                    <td>{t.status === "quarantined" && <button className="ghost" onClick={(e) => { e.stopPropagation(); trust(t); }}>Re-trust</button>}</td>
                  </tr>
                  {open === key && (
                    <tr className="detail"><td colSpan="7">
                      <p><b>Reason:</b> {t.reason}</p>
                      <p><b>Description seen by the model:</b> <code className="block">{t.description || "(none)"}</code></p>
                      {t.findings.length > 0 && (
                        <ul>{t.findings.map((f, i) => (
                          <li key={i}><Badge kind="bad">{f.rule}</Badge> +{f.weight} {f.description} — <code>{f.excerpt}</code></li>
                        ))}</ul>
                      )}
                    </td></tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function AuditLog() {
  const [rows, setRows] = useState([]);
  const [decision, setDecision] = useState("");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(null);

  useEffect(() => {
    let alive = true;
    const pull = () =>
      api(`/api/audit?limit=300${decision ? `&decision=${decision}` : ""}`)
        .then((r) => alive && setRows(r))
        .catch(() => {});
    pull();
    const id = setInterval(pull, 3000);
    return () => { alive = false; clearInterval(id); };
  }, [decision]);

  const q = query.trim().toLowerCase();
  const shown = q
    ? rows.filter((r) => `${r.agent} ${r.server} ${r.tool} ${r.reason} ${JSON.stringify(r.arguments)}`.toLowerCase().includes(q))
    : rows;

  return (
    <Panel
      title={`Audit log (${shown.length})`}
      right={
        <div className="filters">
          <input placeholder="search agent / tool / args / reason" value={query} onChange={(e) => setQuery(e.target.value)} />
          <select value={decision} onChange={(e) => setDecision(e.target.value)}>
            <option value="">all decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>
      }
    >
      <div className="scroll tall">
        <table>
          <thead>
            <tr><th>Time</th><th>Agent</th><th>Server</th><th>Tool</th><th>Arguments</th><th>Risk</th><th>Decision</th><th>Reason</th></tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <React.Fragment key={r.id}>
                <tr className="click" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  <td title={fmtDateTime(r.ts)}>{fmtTime(r.ts)}</td>
                  <td>{r.agent}</td>
                  <td>{r.server}</td>
                  <td>{r.tool}</td>
                  <td><code>{compactArgs(r.arguments, 48)}</code></td>
                  <td><RiskBar score={r.risk_score} level={r.risk_level} /></td>
                  <td><DecisionBadge decision={r.decision} /></td>
                  <td className="reason">{r.reason}</td>
                </tr>
                {open === r.id && (
                  <tr className="detail"><td colSpan="8">
                    <pre>{JSON.stringify({ session: r.session, arguments: r.arguments, anomaly_score: r.anomaly_score, components: r.components, response: r.response_summary, duration_ms: r.duration_ms }, null, 2)}</pre>
                  </td></tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        {!shown.length && <Empty>No matching audit entries.</Empty>}
      </div>
    </Panel>
  );
}
