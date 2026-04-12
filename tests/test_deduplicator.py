from __future__ import annotations

import time

import pytest

from alerting.deduplicator import Deduplicator
from detection.correlator import CorrelatedAlert


def _alert(rule="Port Scan", src_ip="10.0.0.1",
           dst_ip="10.0.0.2", dst_port=80,
           severity="HIGH") -> CorrelatedAlert:
    """Build a minimal CorrelatedAlert."""
    return CorrelatedAlert(
        rule=rule,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        correlated=False,
        also_triggered=[],
    )


# ── First-seen behaviour ──────────────────────────────────────────────────────

class TestFirstSeen:
    def test_first_alert_is_not_duplicate(self):
        dedup = Deduplicator(cooldown_sec=30)
        assert dedup.is_duplicate(_alert()) is False

    def test_immediate_second_alert_is_duplicate(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert())
        assert dedup.is_duplicate(_alert()) is True

    def test_suppressed_count_starts_at_zero(self):
        dedup = Deduplicator(cooldown_sec=30)
        assert dedup.suppressed_count == 0

    def test_suppressed_count_increments_on_duplicate(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert())
        dedup.is_duplicate(_alert())
        dedup.is_duplicate(_alert())
        assert dedup.suppressed_count == 2


# ── Cooldown window ───────────────────────────────────────────────────────────

class TestCooldownWindow:
    def test_alert_passes_after_cooldown_expires(self):
        dedup = Deduplicator(cooldown_sec=0.05)
        dedup.is_duplicate(_alert())
        time.sleep(0.06)
        assert dedup.is_duplicate(_alert()) is False

    def test_alert_still_suppressed_before_cooldown(self):
        dedup = Deduplicator(cooldown_sec=5)
        dedup.is_duplicate(_alert())
        assert dedup.is_duplicate(_alert()) is True


# ── Key isolation ─────────────────────────────────────────────────────────────

class TestKeyIsolation:
    def test_different_rules_independent(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert(rule="Rule A"))
        # Rule B has never been seen — must pass through
        assert dedup.is_duplicate(_alert(rule="Rule B")) is False

    def test_different_src_ips_independent(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert(src_ip="10.0.0.1"))
        # Different source IP — not a duplicate
        assert dedup.is_duplicate(_alert(src_ip="10.0.0.2")) is False

    def test_same_rule_different_ip_not_suppressed(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert(rule="Flood", src_ip="1.1.1.1"))
        dedup.is_duplicate(_alert(rule="Flood", src_ip="1.1.1.1"))  # suppress this
        # Different IP, same rule — should not be suppressed
        assert dedup.is_duplicate(_alert(rule="Flood", src_ip="2.2.2.2")) is False

    def test_dst_ip_and_port_not_part_of_key(self):
        """dst_ip and dst_port changes must not bypass deduplication."""
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert(dst_ip="10.0.0.2", dst_port=80))
        # Same rule + src_ip — different dst should still be suppressed
        assert dedup.is_duplicate(_alert(dst_ip="10.0.0.3", dst_port=443)) is True


# ── purge_expired ─────────────────────────────────────────────────────────────

class TestPurgeExpired:
    def test_purge_removes_expired_entries(self):
        dedup = Deduplicator(cooldown_sec=0.05)
        dedup.is_duplicate(_alert(rule="R1", src_ip="1.1.1.1"))
        dedup.is_duplicate(_alert(rule="R2", src_ip="2.2.2.2"))
        time.sleep(0.06)
        dedup.purge_expired()
        # After purge the entries are gone — both should pass again as fresh
        assert dedup.is_duplicate(_alert(rule="R1", src_ip="1.1.1.1")) is False
        assert dedup.is_duplicate(_alert(rule="R2", src_ip="2.2.2.2")) is False

    def test_purge_leaves_active_entries(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.is_duplicate(_alert(rule="Active"))
        dedup.purge_expired()
        # Cooldown has not expired — still duplicate
        assert dedup.is_duplicate(_alert(rule="Active")) is True

    def test_purge_is_safe_on_empty_state(self):
        dedup = Deduplicator(cooldown_sec=30)
        dedup.purge_expired()  # must not raise
        assert dedup.suppressed_count == 0
