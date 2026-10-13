"""Policy engine: risk levels and ALLOW / REQUIRE_APPROVAL / BLOCK decisions."""
from __future__ import annotations

import pytest
import yaml

from byteshield.config import ROOT
from byteshield.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, PolicyEngine
from byteshield.taint import TaintCheck


@pytest.fixture()
def engine():
    with open(ROOT / "config" / "policy.yaml", encoding="utf-8") as fh:
        return PolicyEngine(yaml.safe_load(fh))


TRUSTED = {"status": "trusted", "reason": "", "poison_score": 0}


def test_policy_low_risk_allowed(engine):
    v = engine.evaluate("weather", "get_weather", {"city": "Paris"}, TRUSTED, TaintCheck())
    assert (v.decision, v.risk_level) == (ALLOW, "LOW")


def test_policy_privileged_send_requires_approval(engine):
    v = engine.evaluate("office", "send_email", {"to": "bob@corp.example", "subject": "s", "body": "b"}, TRUSTED, TaintCheck())
    assert v.decision == REQUIRE_APPROVAL and v.risk_level == "MEDIUM"


def test_policy_external_recipient_is_high_and_blocked(engine):
    v = engine.evaluate("office", "send_email", {"to": "someone@gmail.com", "subject": "s", "body": "b"}, TRUSTED, TaintCheck())
    assert v.decision == BLOCK and v.risk_level == "HIGH"


def test_policy_sensitive_path_blocked(engine):
    for path in ("~/.ssh/id_rsa", "../../etc/passwd", ".env"):
        v = engine.evaluate("office", "read_file", {"path": path}, TRUSTED, TaintCheck())
        assert v.decision == BLOCK, path


def test_policy_quarantined_and_unknown_tools_blocked(engine):
    q = {"status": "quarantined", "reason": "rug_pull: changed", "poison_score": 80}
    assert engine.evaluate("weather", "get_weather", {}, q, TaintCheck()).decision == BLOCK
    assert engine.evaluate("weather", "get_weather", {}, None, TaintCheck()).decision == BLOCK


def test_policy_confused_deputy_levels(engine):
    entity = TaintCheck(tainted=True, entity_overlap=["attacker@evil.example"], sources=["poisoned.fetch_webpage"])
    assert engine.evaluate("office", "read_file", {"path": "notes/a.txt"}, TRUSTED, entity).decision == BLOCK
    tainted_only = TaintCheck(tainted=True, sources=["poisoned.fetch_webpage"])
    assert engine.evaluate("office", "read_file", {"path": "notes/a.txt"}, TRUSTED, tainted_only).decision == REQUIRE_APPROVAL
    # non-privileged tools are unaffected by taint
    assert engine.evaluate("weather", "get_weather", {"city": "Rome"}, TRUSTED, tainted_only).decision == ALLOW


def test_policy_monitor_mode_flag():
    with open(ROOT / "config" / "policy.yaml", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    cfg["mode"] = "monitor"
    assert not PolicyEngine(cfg).enforcing
