"""Isolation Forest anomaly detection."""
from __future__ import annotations

from byteshield.anomaly import AnomalyDetector


def test_isolation_forest_separates_attack_from_normal():
    det = AnomalyDetector()
    assert det.enabled and det.trained_on >= 150
    now = 9_000_000.0
    normal = det.score("n", "weather.get_weather", 1, 6, False, False, now=now)
    normal2 = det.score("n", "weather.get_forecast", 2, 8, False, False, now=now + 12)
    attack = det.score("a", "office.send_email", 3, 600, True, True, now=now)
    assert not normal["flagged"] and not normal2["flagged"]
    assert attack["flagged"] and attack["score"] > max(normal["score"], normal2["score"])


def test_anomaly_detector_retrains_and_can_be_disabled():
    det = AnomalyDetector()
    from byteshield.anomaly import synthetic_baseline
    assert det.fit(synthetic_baseline(seed=1), source="test") and det.source == "test"
    assert not det.fit(synthetic_baseline()[:10])  # too little data -> keeps old model
    off = AnomalyDetector(enabled=False)
    assert off.score("s", "x.y", 1, 1, False, False)["enabled"] is False
