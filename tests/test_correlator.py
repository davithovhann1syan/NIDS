from __future__ import annotations

import pytest

from detection.correlator import correlate, CorrelatedAlert
from detection.sig_detector import Alert


def _alert(rule="Test Rule", severity="HIGH", src_ip="10.0.0.1",
           dst_ip="10.0.0.2", dst_port=80, **kw) -> Alert:
    """Build a minimal Alert dict."""
    a = Alert(rule=rule, severity=severity, src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)
    a.update(kw)  # type: ignore[arg-type]
    return a


# ── Empty input ───────────────────────────────────────────────────────────────

class TestEmpty:
    def test_returns_none_for_empty_list(self):
        assert correlate([]) is None


# ── Single alert ──────────────────────────────────────────────────────────────

class TestSingleAlert:
    def test_returns_correlated_alert(self):
        result = correlate([_alert()])
        assert result is not None

    def test_rule_name_preserved(self):
        result = correlate([_alert(rule="Port Scan")])
        assert result["rule"] == "Port Scan"

    def test_severity_preserved(self):
        result = correlate([_alert(severity="CRITICAL")])
        assert result["severity"] == "CRITICAL"

    def test_src_ip_preserved(self):
        result = correlate([_alert(src_ip="1.2.3.4")])
        assert result["src_ip"] == "1.2.3.4"

    def test_dst_ip_preserved(self):
        result = correlate([_alert(dst_ip="5.6.7.8")])
        assert result["dst_ip"] == "5.6.7.8"

    def test_dst_port_preserved(self):
        result = correlate([_alert(dst_port=443)])
        assert result["dst_port"] == 443

    def test_dst_port_none_preserved(self):
        result = correlate([_alert(dst_port=None)])
        assert result["dst_port"] is None

    def test_correlated_false_for_single(self):
        result = correlate([_alert()])
        assert result["correlated"] is False

    def test_also_triggered_empty_for_single(self):
        result = correlate([_alert()])
        assert result["also_triggered"] == []

    def test_count_carried_from_rate_alert(self):
        alert = _alert()
        alert["count"] = 42
        result = correlate([alert])
        assert result["count"] == 42

    def test_count_absent_for_pattern_alert(self):
        result = correlate([_alert()])
        assert "count" not in result


# ── Priority selection ────────────────────────────────────────────────────────

class TestPrioritySelection:
    def test_critical_beats_high(self):
        alerts = [_alert(rule="A", severity="HIGH"), _alert(rule="B", severity="CRITICAL")]
        result = correlate(alerts)
        assert result["severity"] == "CRITICAL"
        assert result["rule"] == "B"

    def test_high_beats_medium(self):
        alerts = [_alert(rule="A", severity="MEDIUM"), _alert(rule="B", severity="HIGH")]
        result = correlate(alerts)
        assert result["severity"] == "HIGH"
        assert result["rule"] == "B"

    def test_medium_beats_low(self):
        alerts = [_alert(rule="A", severity="LOW"), _alert(rule="B", severity="MEDIUM")]
        result = correlate(alerts)
        assert result["severity"] == "MEDIUM"
        assert result["rule"] == "B"

    def test_all_severities_picks_critical(self):
        alerts = [
            _alert(rule="Lo", severity="LOW"),
            _alert(rule="Me", severity="MEDIUM"),
            _alert(rule="Hi", severity="HIGH"),
            _alert(rule="Cr", severity="CRITICAL"),
        ]
        result = correlate(alerts)
        assert result["severity"] == "CRITICAL"
        assert result["rule"] == "Cr"


# ── Correlation metadata ──────────────────────────────────────────────────────

class TestCorrelationMetadata:
    def test_correlated_true_for_multiple(self):
        result = correlate([_alert(rule="A"), _alert(rule="B")])
        assert result["correlated"] is True

    def test_also_triggered_contains_other_rules(self):
        result = correlate([
            _alert(rule="Leader", severity="HIGH"),
            _alert(rule="Other1", severity="LOW"),
            _alert(rule="Other2", severity="MEDIUM"),
        ])
        assert set(result["also_triggered"]) == {"Other1", "Other2"}
        assert "Leader" not in result["also_triggered"]

    def test_leader_not_in_also_triggered(self):
        result = correlate([_alert(rule="Alpha", severity="CRITICAL"),
                            _alert(rule="Beta",  severity="LOW")])
        assert "Alpha" not in result["also_triggered"]
        assert "Beta"  in result["also_triggered"]

    def test_count_from_winning_rate_alert(self):
        """count should come from the leading (highest-severity) alert."""
        leader = _alert(rule="Fast Flood", severity="CRITICAL")
        leader["count"] = 99
        other  = _alert(rule="Port Scan",  severity="LOW")
        other["count"] = 5
        result = correlate([leader, other])
        assert result["count"] == 99


# ── Output schema ─────────────────────────────────────────────────────────────

class TestOutputSchema:
    def test_all_required_keys_present(self):
        result = correlate([_alert()])
        for key in ("rule", "severity", "src_ip", "dst_ip", "dst_port",
                    "correlated", "also_triggered"):
            assert key in result, f"missing key: {key}"
