"""Confused-deputy protection: track data provenance per agent session.

Once a session has received output from an *untrusted* source (an untrusted MCP server, or any
tool output in which prompt injection was detected) it is "tainted". A tainted session must not be
able to use its privileged tools on the strength of that data alone:

* an argument that carries a control-plane entity (e-mail address, URL, file path) taken from
  untrusted output -> strongest evidence of a confused deputy -> BLOCK
* an argument that copies a long span of untrusted text -> REQUIRE_APPROVAL
* any privileged call from a tainted session -> REQUIRE_APPROVAL
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

ENTITY_RE = re.compile(
    r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"            # e-mail addresses
    r"|https?://[^\s\"'<>)\]]+"                 # URLs
    r"|(?:~|\.{1,2})?/[\w.\-~]+(?:/[\w.\-~]+)*"   # absolute / home-relative paths
    r"|\b[\w\-]+(?:[/\\][\w.\-]+)+"             # relative paths with a separator
)
_TRAILING = ".,;:!?)]}>'\""


def extract_entities(text: str) -> set[str]:
    out = set()
    for m in ENTITY_RE.finditer(text):
        ent = m.group(0).rstrip(_TRAILING).lower()
        if len(ent) >= 4:
            out.add(ent)
    return out


def flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from flatten_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from flatten_strings(v)
    elif value is not None and not isinstance(value, bool):
        yield str(value)


@dataclass
class TaintSource:
    ts: float
    origin: str
    reason: str
    text: str
    entities: set[str]


@dataclass
class TaintCheck:
    tainted: bool = False
    entity_overlap: list[str] = field(default_factory=list)
    text_overlap: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"tainted": self.tainted, "entity_overlap": self.entity_overlap,
                "text_overlap": self.text_overlap, "sources": self.sources}


class SessionTracker:
    def __init__(self, ttl_seconds: float = 900, min_overlap_len: int = 12):
        self.ttl = ttl_seconds
        self.min_overlap_len = min_overlap_len
        self._sessions: dict[str, list[TaintSource]] = {}
        self._lock = threading.RLock()

    def _live(self, session: str, now: float) -> list[TaintSource]:
        sources = [s for s in self._sessions.get(session, []) if now - s.ts <= self.ttl]
        if sources:
            self._sessions[session] = sources
        else:
            self._sessions.pop(session, None)
        return sources

    def mark_tainted(self, session: str, origin: str, text: str, reason: str) -> None:
        with self._lock:
            self._sessions.setdefault(session, []).append(
                TaintSource(time.time(), origin, reason, text[:50_000].lower(), extract_entities(text)))

    def check(self, session: str, arguments: Any) -> TaintCheck:
        with self._lock:
            sources = self._live(session, time.time())
            if not sources:
                return TaintCheck()
            result = TaintCheck(tainted=True, sources=sorted({s.origin for s in sources}))
            for arg in flatten_strings(arguments):
                low = arg.strip().lower()
                if not low:
                    continue
                for src in sources:
                    for ent in src.entities:
                        if ent in low and ent not in result.entity_overlap:
                            result.entity_overlap.append(ent)
                    if len(low) >= self.min_overlap_len and low in src.text and arg not in result.text_overlap:
                        result.text_overlap.append(arg[:80])
            return result

    def reset(self, session: str | None = None) -> None:
        with self._lock:
            if session is None:
                self._sessions.clear()
            else:
                self._sessions.pop(session, None)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            return {
                sid: [{"origin": s.origin, "reason": s.reason, "age_s": round(now - s.ts, 1)}
                      for s in self._live(sid, now)]
                for sid in list(self._sessions)
            }
