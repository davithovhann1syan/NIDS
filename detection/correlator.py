from __future__ import annotations

import time
from collections import defaultdict
from typing import NotRequired, TypedDict

import config
from detection.signatures import Severity
from detection.sig_detector import Alert


class CorrelatedAlert(TypedDict):
    rule:            str            # highest-severity rule name (leads the alert)
    severity:        Severity       # highest severity level across all fired rules
    src_ip:          str
    dst_ip:          str
    dst_port:        int | None
    protocol:        str            # "TCP", "UDP", "ICMP", or numeric string
    correlated:      bool           # True if more than one rule fired on this packet
    also_triggered:  list[str]      # names of every other rule that also fired
    count:           NotRequired[int]   # carried from the leading alert if it's a rate rule
    threat_score:    NotRequired[int]   # 0–100: IP's cross-packet attack diversity score


_SEV_UP: dict[str, Severity] = {
    "LOW":    "MEDIUM",
    "MEDIUM": "HIGH",
    "HIGH":   "CRITICAL",
}


class Correlator:
    """Stateful per-packet correlator with cross-packet IP threat tracking.

    Per-packet correlation: selects the highest-severity alert from all rules
    that fired on a single packet and annotates it with the others (also_triggered).

    Cross-packet threat tracking: maintains a sliding window of distinct rules
    fired per source IP.  When an IP accumulates many distinct rules (multi-stage
    attack behaviour — e.g. scan → brute-force → C2), the alert severity is
    escalated and a threat_score (0–100) is attached.

    Thread safety: designed for single-threaded use (analysis loop on Thread 2).
    """

    def __init__(self, threat_window_sec: int = 300) -> None:
        self._window = threat_window_sec
        # {src_ip: {rule_name: last_fired_timestamp}}
        self._history: defaultdict[str, dict[str, float]] = defaultdict(dict)

    def correlate(self, alerts: list[Alert]) -> CorrelatedAlert | None:
        """Correlate all alerts fired for a single packet.

        Applies priority in order: CRITICAL > HIGH > MEDIUM > LOW.
        If multiple alerts share the highest severity, the first one leads.
        If the list is empty, returns None.

        The also_triggered field preserves the names of every other rule that
        fired so analysts see the full picture in a single log entry.
        The threat_score reflects how broadly this source IP has been attacking
        across the recent threat window — a high score means multi-stage activity.

        Args:
            alerts: All alerts fired by SignatureDetector for a single packet.

        Returns:
            A CorrelatedAlert built from the highest-severity match, or None if
            alerts is empty.
        """
        if not alerts:
            return None

        leader = max(alerts, key=lambda a: config.SEVERITY_RANK[a["severity"]])
        others = [a["rule"] for a in alerts if a is not leader]

        src_ip = leader["src_ip"]
        now    = time.time()

        # Update the IP's rule history with every rule that fired this packet.
        ip_history = self._history[src_ip]
        for a in alerts:
            ip_history[a["rule"]] = now

        # Count how many distinct rules this IP has triggered within the threat window.
        active_rules = {
            rule for rule, ts in ip_history.items()
            if now - ts <= self._window
        }
        threat_score = min(100, len(active_rules) * 10)

        # Escalate severity when multi-stage attack behaviour is detected.
        # 3+ distinct rules (score ≥ 30) → bump LOW to MEDIUM.
        # 5+ distinct rules (score ≥ 50) → bump anything below HIGH to HIGH.
        # 8+ distinct rules (score ≥ 80) → bump anything below CRITICAL to CRITICAL.
        severity = leader["severity"]
        rank     = config.SEVERITY_RANK
        if threat_score >= 80 and rank[severity] < rank["CRITICAL"]:
            severity = "CRITICAL"
        elif threat_score >= 50 and rank[severity] < rank["HIGH"]:
            severity = "HIGH"
        elif threat_score >= 30 and rank[severity] < rank["MEDIUM"]:
            severity = "MEDIUM"

        correlated = CorrelatedAlert(
            rule=leader["rule"],
            severity=severity,
            src_ip=src_ip,
            dst_ip=leader["dst_ip"],
            dst_port=leader["dst_port"],
            protocol=leader["protocol"],
            correlated=len(others) > 0,
            also_triggered=others,
            threat_score=threat_score,
        )

        if "count" in leader:
            correlated["count"] = leader["count"]

        return correlated

    def purge_old_history(self) -> None:
        """Evict IP history entries that have fully expired from the threat window.

        Call periodically from main.py (same cadence as dedup.purge_expired)
        to prevent unbounded memory growth when many distinct source IPs appear
        during a scan or DDoS and then go quiet.
        """
        now = time.time()
        for ip in list(self._history.keys()):
            self._history[ip] = {
                rule: ts
                for rule, ts in self._history[ip].items()
                if now - ts <= self._window
            }
            if not self._history[ip]:
                del self._history[ip]
