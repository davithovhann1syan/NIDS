from __future__ import annotations

import time

import config
from detection.correlator import CorrelatedAlert


class Deduplicator:
    """Suppresses repeated alerts for the same (rule, src_ip) within a cooldown window.

    Each (rule, src_ip) pair has its own independent cooldown timer.
    Only the first alert in each cooldown window passes through — subsequent
    identical alerts are silently discarded until the cooldown expires.

    Single-threaded: designed for use exclusively from the analysis loop (Thread 2).
    No lock is needed — adding one would be pure overhead with no safety benefit.
    """

    def __init__(self, cooldown_sec: float = config.ALERT_COOLDOWN_SEC) -> None:
        self._cooldown_sec     = cooldown_sec
        self._last_seen:       dict[tuple[str, str], float] = {}
        self._suppressed_count: int = 0

    def is_duplicate(self, alert: CorrelatedAlert) -> bool:
        """Return True if this alert should be suppressed.

        Checks whether the same (rule, src_ip) pair was alerted within the
        cooldown window. If not a duplicate, records the current time so the
        cooldown starts now.

        Args:
            alert: A CorrelatedAlert from the correlator.

        Returns:
            True if the alert is a duplicate and should be discarded.
            False if the alert is new or the cooldown has expired.
        """
        key = (alert["rule"], alert["src_ip"])
        now = time.monotonic()

        last = self._last_seen.get(key)
        if last is not None and (now - last) < self._cooldown_sec:
            self._suppressed_count += 1
            return True
        self._last_seen[key] = now
        return False

    def purge_expired(self) -> None:
        """Remove entries whose cooldown has fully expired.

        Keeps _last_seen from growing unboundedly on long-running systems
        with many source IPs. Call periodically from main.py.
        """
        now = time.monotonic()
        expired = [
            k for k, t in self._last_seen.items()
            if now - t >= self._cooldown_sec
        ]
        for k in expired:
            del self._last_seen[k]

    @property
    def suppressed_count(self) -> int:
        """Total alerts suppressed since this instance was created."""
        return self._suppressed_count
