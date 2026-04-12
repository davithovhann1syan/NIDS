from __future__ import annotations

import pytest

from detection.sig_detector import SignatureDetector, Alert
from detection.signatures import Rule


# ── Minimal inline rules — no dependency on signatures.py ────────────────────

PATTERN_RULE: list[Rule] = [
    {
        "name":       "Suspicious Port",
        "type":       "pattern",
        "severity":   "HIGH",
        "conditions": {"dst_port": 4444, "protocol": 6},
    }
]

MULTI_VALUE_RULE: list[Rule] = [
    {
        "name":       "C2 Ports",
        "type":       "pattern",
        "severity":   "CRITICAL",
        "conditions": {"dst_port": [4444, 1337, 31337]},
    }
]

RATE_RULE: list[Rule] = [
    {
        "name":           "SYN Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions":     {"flags": "S", "protocol": 6},
        "threshold":      5,
        "window_seconds": 10,
    }
]


def _feat(*, src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol=6,
          dst_port=80, flags="S", flags_int=2, icmp_type=None,
          timestamp=1_000.0, **kw) -> dict:
    """Build a minimal feature dict with sensible defaults."""
    return {
        "timestamp": timestamp,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "protocol":  protocol,
        "length":    60,
        "ttl":       64,
        "src_port":  12345,
        "dst_port":  dst_port,
        "flags":     flags,
        "flags_int": flags_int,
        "icmp_type": icmp_type,
        **kw,
    }


# ── Pattern rules ─────────────────────────────────────────────────────────────

class TestPatternRule:
    def test_fires_on_match(self):
        det = SignatureDetector(PATTERN_RULE)
        alerts = det.process(_feat(dst_port=4444, protocol=6))
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "Suspicious Port"

    def test_no_alert_on_mismatch(self):
        det = SignatureDetector(PATTERN_RULE)
        alerts = det.process(_feat(dst_port=80, protocol=6))
        assert alerts == []

    def test_all_conditions_must_match(self):
        """dst_port matches but protocol doesn't — should not fire."""
        det = SignatureDetector(PATTERN_RULE)
        alerts = det.process(_feat(dst_port=4444, protocol=17))
        assert alerts == []

    def test_alert_schema_keys(self):
        det = SignatureDetector(PATTERN_RULE)
        alert = det.process(_feat(dst_port=4444, protocol=6))[0]
        assert "rule"     in alert
        assert "severity" in alert
        assert "src_ip"   in alert
        assert "dst_ip"   in alert
        assert "dst_port" in alert
        assert "count"    not in alert   # no count on pattern alerts

    def test_alert_values(self):
        det = SignatureDetector(PATTERN_RULE)
        alert = det.process(_feat(dst_port=4444, protocol=6, src_ip="1.2.3.4", dst_ip="5.6.7.8"))[0]
        assert alert["severity"] == "HIGH"
        assert alert["src_ip"]   == "1.2.3.4"
        assert alert["dst_ip"]   == "5.6.7.8"
        assert alert["dst_port"] == 4444

    def test_list_condition_membership(self):
        det = SignatureDetector(MULTI_VALUE_RULE)
        for port in [4444, 1337, 31337]:
            assert det.process(_feat(dst_port=port)) != []

    def test_list_condition_no_match(self):
        det = SignatureDetector(MULTI_VALUE_RULE)
        assert det.process(_feat(dst_port=9999)) == []


# ── Rate rules ────────────────────────────────────────────────────────────────

class TestRateRule:
    def test_does_not_fire_below_threshold(self):
        det = SignatureDetector(RATE_RULE)
        for i in range(4):
            alerts = det.process(_feat(timestamp=1000.0 + i))
        assert alerts == []

    def test_fires_at_threshold(self):
        det = SignatureDetector(RATE_RULE)
        for i in range(5):
            alerts = det.process(_feat(timestamp=1000.0 + i))
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "SYN Flood"

    def test_count_field_present(self):
        det = SignatureDetector(RATE_RULE)
        for i in range(5):
            alerts = det.process(_feat(timestamp=1000.0 + i))
        assert "count" in alerts[0]
        assert alerts[0]["count"] == 5

    def test_window_expiry_resets_count(self):
        """Packets outside the 10-second window must not contribute to threshold."""
        det = SignatureDetector(RATE_RULE)
        # 4 packets at t=0..3 — not enough to fire
        for i in range(4):
            det.process(_feat(timestamp=float(i)))
        # Jump past the window; old packets expire
        for i in range(4):
            alerts = det.process(_feat(timestamp=100.0 + i))
        # Only 4 fresh packets — still below threshold of 5
        assert alerts == []

    def test_fires_again_after_window_refills(self):
        det = SignatureDetector(RATE_RULE)
        # First wave fires at threshold=5
        for i in range(5):
            alerts = det.process(_feat(timestamp=float(i)))
        assert alerts != []
        # Jump past window — old entries expire, 5 new ones fire again
        for i in range(5):
            alerts = det.process(_feat(timestamp=100.0 + i))
        assert alerts != []

    def test_per_src_ip_isolation(self):
        """Two source IPs must not share rate state."""
        det = SignatureDetector(RATE_RULE)
        # 4 packets from IP A — no fire
        for i in range(4):
            det.process(_feat(src_ip="10.0.0.1", timestamp=float(i)))
        # 4 packets from IP B — no fire either
        for i in range(4):
            alerts = det.process(_feat(src_ip="10.0.0.2", timestamp=float(i)))
        assert alerts == []

    def test_non_matching_packets_ignored(self):
        """UDP packets must not increment the SYN-flood (TCP SYN only) counter."""
        det = SignatureDetector(RATE_RULE)
        for i in range(10):
            alerts = det.process(_feat(protocol=17, flags=None, timestamp=float(i)))
        assert alerts == []


# ── Multiple rules ────────────────────────────────────────────────────────────

class TestMultipleRules:
    def test_multiple_rules_can_fire_on_one_packet(self):
        rules: list[Rule] = [
            {"name": "Rule A", "type": "pattern", "severity": "HIGH",
             "conditions": {"protocol": 6}},
            {"name": "Rule B", "type": "pattern", "severity": "MEDIUM",
             "conditions": {"dst_port": 80}},
        ]
        det = SignatureDetector(rules)
        alerts = det.process(_feat(protocol=6, dst_port=80))
        assert len(alerts) == 2
        names = {a["rule"] for a in alerts}
        assert names == {"Rule A", "Rule B"}

    def test_empty_rules_list(self):
        det = SignatureDetector([])
        assert det.process(_feat()) == []
