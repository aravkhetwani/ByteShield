"""Optional anomaly detection on tool-call sequences using scikit-learn's Isolation Forest.

Every call is turned into a small numeric feature vector that captures both *what* is being called
and *where it sits in the session's sequence*:

  tool_freq        how common is this tool in the baseline
  transition_prob  P(tool | previous tool in the session)  (Laplace-smoothed bigram model)
  log_arg_chars    size of the arguments
  n_args           number of arguments
  log_dt           seconds since the session's previous call
  privileged       tool is privileged
  calls_last_min   burstiness
  tainted          session holds untrusted data

The forest is trained on a synthetic "normal usage" baseline and can be re-trained from ALLOWed
audit-log rows. If scikit-learn is missing the detector degrades to disabled.
"""
from __future__ import annotations

import math
import random
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Any

try:  # scikit-learn is optional at runtime
    import numpy as np
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - exercised only without sklearn
    np = None  # type: ignore[assignment]
    IsolationForest = None  # type: ignore[assignment]

FEATURES = ["tool_freq", "transition_prob", "log_arg_chars", "n_args", "log_dt", "privileged",
            "calls_last_min", "tainted"]
START = "<start>"
NOMINAL_DT = 60.0


def synthetic_baseline(seed: int = 7, n_sessions: int = 120) -> list[dict[str, Any]]:
    """Generate plausible benign tool-call traffic (weather lookups, the odd file read / email)."""
    rng = random.Random(seed)
    events: list[dict[str, Any]] = []
    t = 1_000_000.0
    for s in range(n_sessions):
        t += rng.uniform(3_600, 20_000)
        for _ in range(rng.randint(3, 12)):
            t += rng.uniform(2, 60) if rng.random() > 0.15 else rng.uniform(0.5, 2)
            r = rng.random()
            if r < 0.62:
                tool, chars, n = "weather.get_weather", rng.randint(3, 14), 1
            elif r < 0.85:
                tool, chars, n = "weather.get_forecast", rng.randint(4, 16), 2
            elif r < 0.92:
                tool, chars, n = "office.list_files", rng.randint(1, 10), 1
            elif r < 0.97:
                tool, chars, n = "office.read_file", rng.randint(9, 30), 1
            else:
                tool, chars, n = "office.send_email", rng.randint(60, 220), 3
            privileged = tool.startswith("office.")
            # Benign sessions occasionally touch untrusted data, but then only do harmless lookups.
            tainted = (not privileged) and rng.random() < 0.08
            events.append({"session": f"syn-{s}", "ts": t, "tool": tool, "arg_chars": chars, "n_args": n,
                           "privileged": privileged, "tainted": tainted})
    return events


class AnomalyDetector:
    def __init__(self, enabled: bool = True, n_estimators: int = 200, flag_threshold: float | None = None,
                 min_training_rows: int = 150, seed: int = 42):
        self.available = IsolationForest is not None
        self.enabled = enabled and self.available
        self.n_estimators = n_estimators
        self.seed = seed
        self.min_training_rows = min_training_rows
        self._fixed_threshold = flag_threshold
        self.threshold = flag_threshold or 0.6
        self._lock = threading.RLock()
        self._model: Any = None
        self._tool_counts: Counter[str] = Counter()
        self._trans_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self._total = 0
        self._vocab = 1
        self._history: dict[str, dict[str, Any]] = {}
        self.trained_on = 0
        self.source = "none"
        if self.enabled:
            self.fit(synthetic_baseline(), source="synthetic baseline")

    # ---- feature engineering -------------------------------------------------------------
    def _vector(self, tool: str, prev: str, chars: int, n_args: int, dt: float, privileged: bool,
                recent: int, tainted: bool) -> list[float]:
        tool_freq = (self._tool_counts[tool] + 1) / (self._total + self._vocab)
        prev_total = sum(self._trans_counts[prev].values()) if prev in self._trans_counts else 0
        trans = (self._trans_counts[prev][tool] + 1) / (prev_total + self._vocab) if prev_total else tool_freq
        return [tool_freq, trans, math.log1p(chars), float(n_args), math.log1p(dt), float(privileged),
                float(recent), float(tainted)]

    def fit(self, events: list[dict[str, Any]], source: str = "audit log") -> bool:
        if not self.available or len(events) < self.min_training_rows:
            return False
        events = sorted(events, key=lambda e: e["ts"])
        with self._lock:
            self._tool_counts = Counter(e["tool"] for e in events)
            self._total = len(events)
            self._vocab = len(self._tool_counts) + 1
            self._trans_counts = defaultdict(Counter)
            last: dict[str, tuple[str, float]] = {}
            for e in events:
                prev = last.get(e["session"], (START, 0.0))[0]
                self._trans_counts[prev][e["tool"]] += 1
                last[e["session"]] = (e["tool"], e["ts"])
            rows = []
            last = {}
            recent: dict[str, deque[float]] = defaultdict(deque)
            for e in events:
                prev, prev_ts = last.get(e["session"], (START, None))
                dt = NOMINAL_DT if prev_ts is None else max(0.0, e["ts"] - prev_ts)
                window = recent[e["session"]]
                while window and e["ts"] - window[0] > 60:
                    window.popleft()
                rows.append(self._vector(e["tool"], prev, e["arg_chars"], e["n_args"], dt,
                                         bool(e.get("privileged")), len(window), bool(e.get("tainted"))))
                window.append(e["ts"])
                last[e["session"]] = (e["tool"], e["ts"])
            X = np.array(rows, dtype=float)
            model = IsolationForest(n_estimators=self.n_estimators, contamination="auto", random_state=self.seed)
            model.fit(X)
            train_scores = -model.score_samples(X)
            self._model = model
            if self._fixed_threshold is None:
                self.threshold = float(max(0.55, np.quantile(train_scores, 0.995)))
            self.trained_on = len(events)
            self.source = source
            self._history.clear()
        return True

    # ---- online scoring -------------------------------------------------------------------
    def score(self, session: str, tool: str, n_args: int, arg_chars: int, privileged: bool, tainted: bool,
              now: float | None = None, record: bool = True) -> dict[str, Any]:
        """Return {"score": 0..1, "flagged": bool, "threshold": float, "enabled": bool}."""
        if not self.enabled or self._model is None:
            return {"score": 0.0, "flagged": False, "threshold": self.threshold, "enabled": False}
        now = time.time() if now is None else now
        with self._lock:
            hist = self._history.setdefault(session, {"prev": START, "last_ts": None, "window": deque()})
            dt = NOMINAL_DT if hist["last_ts"] is None else max(0.0, now - hist["last_ts"])
            window: deque[float] = hist["window"]
            while window and now - window[0] > 60:
                window.popleft()
            vec = self._vector(tool, hist["prev"], arg_chars, n_args, dt, privileged, len(window), tainted)
            raw = float(-self._model.score_samples(np.array([vec]))[0])
            if record:
                hist["prev"], hist["last_ts"] = tool, now
                window.append(now)
        return {"score": round(raw, 4), "flagged": raw > self.threshold, "threshold": round(self.threshold, 4),
                "enabled": True}

    def reset_sessions(self) -> None:
        with self._lock:
            self._history.clear()

    def info(self) -> dict[str, Any]:
        return {"available": self.available, "enabled": self.enabled, "trained_on": self.trained_on,
                "source": self.source, "threshold": round(self.threshold, 4), "features": FEATURES}


def events_from_audit(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert audit-log rows into training events."""
    events = []
    for r in rows:
        args = r.get("arguments") or {}
        comps = r.get("components") or {}
        text = args if isinstance(args, str) else " ".join(str(v) for v in (args.values() if isinstance(args, dict) else []))
        events.append({"session": r["session"], "ts": r["ts"], "tool": f"{r['server']}.{r['tool']}",
                       "arg_chars": len(text), "n_args": len(args) if isinstance(args, dict) else 0,
                       "privileged": bool(comps.get("privileged")), "tainted": bool(comps.get("tainted"))})
    return events
