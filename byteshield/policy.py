"""Policy engine: combines every signal into a risk score, a LOW/MEDIUM/HIGH level and a decision."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from .taint import TaintCheck, flatten_strings

ALLOW, REQUIRE_APPROVAL, BLOCK = "ALLOW", "REQUIRE_APPROVAL", "BLOCK"
SEVERITY = {ALLOW: 0, REQUIRE_APPROVAL: 1, BLOCK: 2}
LEVELS = ("LOW", "MEDIUM", "HIGH")


@dataclass
class Verdict:
    decision: str
    risk_level: str
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    components: dict[str, Any] = field(default_factory=dict)

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else f"Within policy ({self.risk_level} risk)"


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]):
        self.policy = policy
        self.mode = str(policy.get("mode", "enforce")).lower()
        th = policy.get("level_thresholds", {})
        self.medium_at = int(th.get("medium", 35))
        self.high_at = int(th.get("high", 70))
        self.level_actions = {"LOW": ALLOW, "MEDIUM": ALLOW, "HIGH": BLOCK}
        self.level_actions.update({k.upper(): v.upper() for k, v in (policy.get("level_actions") or {}).items()})
        self.servers = policy.get("servers", {}) or {}
        self.default_server = policy.get("default_server", {"trust": "untrusted"})
        self.tools = policy.get("tools", {}) or {}
        self.default_tool = policy.get("default_tool", {"base_risk": 40, "privileged": False})
        self.poisoning = policy.get("poisoning", {}) or {}
        self.deputy = policy.get("confused_deputy", {}) or {}
        self.anomaly_cfg = policy.get("anomaly", {}) or {}
        self.rules = [
            {**r, "_re": re.compile(r["pattern"], re.IGNORECASE)} for r in (policy.get("argument_rules") or [])
        ]

    # ---- lookups -----------------------------------------------------------------------
    @property
    def enforcing(self) -> bool:
        return self.mode != "monitor"

    @property
    def poison_block_score(self) -> int:
        return int(self.poisoning.get("block_score", 50))

    def server_trust(self, server: str) -> str:
        return str((self.servers.get(server) or self.default_server).get("trust", "untrusted")).lower()

    def tool_policy(self, server: str, tool: str) -> dict[str, Any]:
        key = f"{server}.{tool}"
        if key in self.tools:
            return self.tools[key]
        for pattern, cfg in self.tools.items():
            if "*" in pattern and fnmatch.fnmatch(key, pattern):
                return cfg
        return self.default_tool

    def level_for(self, score: int) -> str:
        return "HIGH" if score >= self.high_at else "MEDIUM" if score >= self.medium_at else "LOW"

    # ---- evaluation ------------------------------------------------------------------------
    def evaluate(self, server: str, tool: str, arguments: Any, fingerprint: dict[str, Any] | None,
                 taint: TaintCheck, anomaly: dict[str, Any] | None = None) -> Verdict:
        tp = self.tool_policy(server, tool)
        privileged = bool(tp.get("privileged", False))
        score = int(tp.get("base_risk", 40))
        votes: list[tuple[str, str]] = []  # (decision, reason)
        parts: list[str] = [f"base {score}"]
        comps: dict[str, Any] = {"base_risk": score, "privileged": privileged, "tainted": taint.tainted,
                                 "server_trust": self.server_trust(server)}

        if self.server_trust(server) == "untrusted":
            bump = int(self.policy.get("untrusted_server_risk", 10))
            score += bump
            parts.append(f"untrusted server +{bump}")
            comps["untrusted_server"] = True

        # 1. Tool-definition integrity (poisoning / rug pull)
        if fingerprint is None:
            score = max(score, 90)
            parts.append("tool unknown -> 90")
            votes.append((BLOCK, "Tool is not in the fingerprint registry (never listed by its server)"))
        elif fingerprint["status"] != "trusted":
            score = max(score, 90)
            parts.append("quarantined tool -> 90")
            comps["fingerprint_status"] = fingerprint["status"]
            comps["poison_score"] = fingerprint.get("poison_score", 0)
            votes.append((BLOCK, f"Tool definition quarantined - {fingerprint['reason']}"))

        # 2. Confused deputy
        if self.deputy.get("enabled", True) and privileged and taint.tainted:
            src = ", ".join(taint.sources)
            if taint.entity_overlap:
                parts.append(f"untrusted-derived arguments +{int(self.deputy.get('entity_overlap_risk', 50))}")
                score += int(self.deputy.get("entity_overlap_risk", 50))
                votes.append((self.deputy.get("entity_overlap_action", BLOCK).upper(),
                              f"Confused deputy: privileged call uses {', '.join(taint.entity_overlap[:3])} "
                              f"taken from untrusted output ({src})"))
            elif taint.text_overlap:
                parts.append(f"copied untrusted text +{int(self.deputy.get('text_overlap_risk', 35))}")
                score += int(self.deputy.get("text_overlap_risk", 35))
                votes.append((self.deputy.get("text_overlap_action", REQUIRE_APPROVAL).upper(),
                              f"Privileged call copies untrusted content from {src}"))
            else:
                parts.append(f"tainted session +{int(self.deputy.get('tainted_session_risk', 30))}")
                score += int(self.deputy.get("tainted_session_risk", 30))
                votes.append((self.deputy.get("tainted_session_action", REQUIRE_APPROVAL).upper(),
                              f"Privileged call from a session holding untrusted data ({src})"))
            comps["taint"] = taint.to_dict()

        # 3. Argument rules
        strings = list(flatten_strings(arguments))
        for rule in self.rules:
            scope = rule.get("tools")
            if scope and not any(fnmatch.fnmatch(f"{server}.{tool}", p) for p in scope):
                continue
            hit = next((s for s in strings if rule["_re"].search(s)), None)
            if hit is not None:
                score += int(rule.get("risk_add", 30))
                parts.append(f"rule {rule['name']} +{int(rule.get('risk_add', 30))}")
                votes.append((str(rule.get("action", REQUIRE_APPROVAL)).upper(),
                              f"Argument rule '{rule['name']}' matched ({hit[:40]!r})"))
                comps.setdefault("argument_rules", []).append(rule["name"])

        allowed_domains = tp.get("allowed_recipient_domains")
        if allowed_domains is not None and isinstance(arguments, dict):
            allowed = {d.lower() for d in allowed_domains}
            recipients = [part for raw in flatten_strings(arguments.get("to", "")) for part in re.split(r"[,;\s]+", raw) if part]
            external = [r for r in recipients if r.rpartition("@")[2].lower() not in allowed]
            if external:
                score += int(tp.get("external_recipient_risk", 20))
                parts.append(f"external recipient +{int(tp.get('external_recipient_risk', 20))}")
                votes.append((REQUIRE_APPROVAL, f"Recipient outside allowed domains: {', '.join(external[:3])}"))
                comps["external_recipients"] = external

        # 4. Anomaly detection
        if anomaly and anomaly.get("enabled"):
            comps["anomaly_score"] = anomaly["score"]
            if anomaly["flagged"]:
                max_add = int(self.anomaly_cfg.get("max_risk_add", 30))
                span = max(1e-6, 1.0 - anomaly["threshold"])
                severity = min(1.0, 0.4 + 2 * (anomaly["score"] - anomaly["threshold"]) / span)
                score += int(round(max_add * severity))
                parts.append(f"anomaly +{int(round(max_add * severity))}")
                comps["anomaly_flagged"] = True
                if privileged:
                    votes.append((str(self.anomaly_cfg.get("privileged_action", REQUIRE_APPROVAL)).upper(),
                                  f"Anomalous call sequence (Isolation Forest score {anomaly['score']:.2f})"))
                else:
                    votes.append((ALLOW, f"Anomalous call sequence flagged (score {anomaly['score']:.2f})"))

        score = max(0, min(100, score))
        level = self.level_for(score)
        votes.append((self.level_actions.get(level, ALLOW),
                      f"{level} risk score {score} ({', '.join(parts)})" if level != "LOW" else ""))
        floor = str(tp.get("min_decision", ALLOW)).upper()
        if floor != ALLOW:
            votes.append((floor, f"Tool policy requires {floor.replace('_', ' ').lower()} for {server}.{tool}"))

        decision = max((d for d, _ in votes), key=lambda d: SEVERITY[d])
        reasons = [r for d, r in votes if r and SEVERITY[d] >= SEVERITY[decision]] or [r for _, r in votes if r]
        comps["score"] = score
        return Verdict(decision, level, score, reasons, comps)
