"""SHA-256 fingerprints of tool definitions + trust-on-first-use (TOFU) tracking.

The fingerprint covers exactly what an LLM sees about a tool: its name,
description and input schema, serialized canonically (sorted keys, no
whitespace) so semantically identical definitions always hash identically.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import time
from typing import Any

from .db import Store
from .poisoning import scan_tool_definition

TRUSTED = "trusted"
QUARANTINED = "quarantined"


def canonical_definition(name: str, description: str | None, input_schema: dict[str, Any] | None) -> dict[str, Any]:
    return {"name": name, "description": description or "", "inputSchema": input_schema or {}}


def fingerprint(name: str, description: str | None, input_schema: dict[str, Any] | None) -> str:
    blob = json.dumps(canonical_definition(name, description, input_schema), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _definition_diff(old: dict[str, Any], new: dict[str, Any]) -> str:
    a = json.dumps(old, sort_keys=True, indent=1, ensure_ascii=False).splitlines()
    b = json.dumps(new, sort_keys=True, indent=1, ensure_ascii=False).splitlines()
    diff = difflib.unified_diff(a, b, "trusted", "current", lineterm="", n=1)
    return "\n".join(list(diff)[:60])


class FingerprintRegistry:
    """Maintains the trusted baseline for every (server, tool) and flags drift."""

    def __init__(self, store: Store, poison_block_score: int = 50):
        self.store = store
        self.poison_block_score = poison_block_score

    def observe(self, server: str, name: str, description: str | None, input_schema: dict[str, Any] | None,
                agent: str | None = None) -> dict[str, Any]:
        """Record a tool definition seen from an upstream server and return its trust record."""
        now = time.time()
        definition = canonical_definition(name, description, input_schema)
        sha = fingerprint(name, description, input_schema)
        rec = self.store.get_fingerprint(server, name)
        scan = scan_tool_definition(name, description or "", input_schema)

        if rec is None:
            poisoned = scan["score"] >= self.poison_block_score
            rec = {
                "server": server, "tool": name, "baseline_sha256": sha, "current_sha256": sha,
                "status": QUARANTINED if poisoned else TRUSTED,
                "reason": f"tool_poisoning: score {scan['score']}" if poisoned else "trust-on-first-use",
                "poison_score": scan["score"], "findings": scan["findings"], "description": description or "",
                "baseline_definition": definition, "current_definition": definition,
                "first_seen": now, "last_seen": now, "changed_at": None,
            }
            self.store.save_fingerprint(rec)
            if poisoned:
                self.store.add_alert(
                    "TOOL_POISONING", "HIGH",
                    f"Tool {server}.{name} quarantined: definition contains hidden/malicious instructions "
                    f"(score {scan['score']}).", server, name, agent,
                    {"sha256": sha, "findings": scan["findings"]})
            return rec

        rec["last_seen"] = now
        if sha == rec["current_sha256"]:
            self.store.save_fingerprint(rec)
            return rec

        if sha == rec["baseline_sha256"]:
            # Definition went back to what was originally pinned: heal a rug-pull quarantine,
            # but never un-quarantine a tool that was poisoned from the very start.
            rec.update(current_sha256=sha, current_definition=definition, poison_score=scan["score"],
                       findings=scan["findings"], description=description or "")
            if rec["status"] == QUARANTINED and rec["reason"].startswith("rug_pull"):
                rec.update(status=TRUSTED, reason="definition restored to trusted baseline")
            self.store.save_fingerprint(rec)
            return rec

        # Definition differs from what was seen last -> rug pull
        diff = _definition_diff(rec["baseline_definition"], definition)
        rec.update(current_sha256=sha, current_definition=definition, poison_score=scan["score"],
                   findings=scan["findings"], description=description or "", changed_at=now)
        if rec["status"] != QUARANTINED or not rec["reason"].startswith("tool_poisoning"):
            rec.update(status=QUARANTINED,
                       reason=f"rug_pull: definition changed after trust was established "
                              f"({rec['baseline_sha256'][:12]} -> {sha[:12]})")
        self.store.save_fingerprint(rec)
        self.store.add_alert(
            "RUG_PULL", "HIGH",
            f"Tool {server}.{name} changed its definition after being trusted "
            f"({rec['baseline_sha256'][:12]} -> {sha[:12]}). Tool quarantined.", server, name, agent,
            {"trusted_sha256": rec["baseline_sha256"], "current_sha256": sha, "poison_score": scan["score"],
             "findings": scan["findings"], "diff": diff})
        return rec

    def trust(self, server: str, tool: str) -> dict[str, Any] | None:
        """Operator override: accept the current definition as the new trusted baseline."""
        rec = self.store.get_fingerprint(server, tool)
        if rec is None:
            return None
        rec.update(baseline_sha256=rec["current_sha256"], baseline_definition=rec["current_definition"],
                   status=TRUSTED, reason="re-trusted by operator", changed_at=time.time())
        self.store.save_fingerprint(rec)
        self.store.add_alert("TOOL_RETRUSTED", "LOW", f"Operator re-trusted {server}.{tool}.", server, tool)
        return rec
