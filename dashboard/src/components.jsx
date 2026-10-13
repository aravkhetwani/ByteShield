import React from "react";

export const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : "-");
export const fmtDateTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { hour12: false }) : "-");
export const short = (s, n = 12) => (s ? s.slice(0, n) : "");
export const compactArgs = (args, n = 70) => {
  const text = typeof args === "string" ? args : JSON.stringify(args ?? {});
  return text.length > n ? text.slice(0, n - 1) + "…" : text;
};

const DECISION_CLASS = { ALLOW: "ok", REQUIRE_APPROVAL: "warn", BLOCK: "bad" };
const DECISION_LABEL = { ALLOW: "ALLOW", REQUIRE_APPROVAL: "APPROVAL", BLOCK: "BLOCK" };

export function Badge({ kind = "mute", children, title }) {
  return (
    <span className={`badge ${kind}`} title={title}>
      {children}
    </span>
  );
}

export function DecisionBadge({ decision }) {
  return <Badge kind={DECISION_CLASS[decision] || "mute"}>{DECISION_LABEL[decision] || decision}</Badge>;
}

export function statusKind(status) {
  return { trusted: "ok", connected: "ok", quarantined: "bad", error: "bad", disconnected: "mute", pending: "warn" }[status] || "mute";
}

export function severityKind(sev) {
  return { HIGH: "bad", MEDIUM: "warn", LOW: "mute" }[sev] || "mute";
}

export function RiskBar({ score, level }) {
  const cls = level === "HIGH" ? "bad" : level === "MEDIUM" ? "warn" : "ok";
  return (
    <div className="riskbar" title={`${level} - score ${score}`}>
      <div className="track">
        <div className={`fill ${cls}`} style={{ width: `${Math.min(100, score)}%` }} />
      </div>
      <span className={`num ${cls}`}>{score}</span>
    </div>
  );
}

export function Panel({ title, right, children, className = "" }) {
  return (
    <section className={`panel ${className}`}>
      <header>
        <h2>{title}</h2>
        {right}
      </header>
      {children}
    </section>
  );
}

export function Sparkline({ values }) {
  const w = 220;
  const h = 44;
  if (!values.length) return <svg className="spark" viewBox={`0 0 ${w} ${h}`} />;
  const step = values.length > 1 ? w / (values.length - 1) : 0;
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 3 - (Math.min(v, 100) / 100) * (h - 6)).toFixed(1)}`);
  const last = values[values.length - 1];
  const color = last >= 70 ? "var(--bad)" : last >= 35 ? "var(--warn)" : "var(--ok)";
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label="risk score trend">
      <line x1="0" x2={w} y1={h - 3 - 0.7 * (h - 6)} y2={h - 3 - 0.7 * (h - 6)} className="thr" />
      <polyline points={points.join(" ")} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

export function Empty({ children }) {
  return <p className="empty">{children}</p>;
}
