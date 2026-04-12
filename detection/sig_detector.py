from __future__ import annotations

from collections import defaultdict, deque
from typing import NotRequired, TypedDict

from detection.signatures import SIGNATURES, Rule, Severity
from parser.extractor import FeatureDict


class Alert(TypedDict):
    rule:     str
    severity: Severity
    src_ip:   str
    dst_ip:   str
    dst_port: int | None
    count:    NotRequired[int]   # present only for rate rule alerts


class SignatureDetector:
    """Pattern match and rate-based signature detection engine.

    Maintains sliding-window state for rate rules keyed by (src_ip, rule_name).
    Stateless between packets for pattern rules.

    Thread safety: designed for single-threaded use (Thread 2 / analysis loop).
    Do not share an instance across threads without external locking.
    """

    def __init__(self, rules: list[Rule] = SIGNATURES) -> None:
        self._rules = rules
        # Sliding window buckets: {(src_ip, rule_name): deque of packet timestamps}
        self._rate_state: defaultdict[tuple[str, str], deque[float]] = defaultdict(deque)

    def process(self, features: FeatureDict) -> list[Alert]:
        """Evaluate all rules against a feature dict.

        Args:
            features: A fully-populated FeatureDict from extractor.extract().

        Returns:
            A list of Alert dicts for every rule that fired. Empty if nothing matched.
        """
        alerts: list[Alert] = []

        for rule in self._rules:
            match rule["type"]:
                case "pattern":
                    if self._matches_conditions(rule["conditions"], features):
                        alerts.append(self._make_pattern_alert(rule, features))
                case "rate":
                    alert = self._check_rate(rule, features)
                    if alert is not None:
                        alerts.append(alert)

        return alerts

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _matches_conditions(
        conditions: dict[str, object],
        features: FeatureDict,
    ) -> bool:
        """Return True if every condition matches the feature dict.

        Condition values may be a single value (equality check) or a list
        (membership check). This applies uniformly to all condition keys.
        """
        feat: dict[str, object] = features  # type: ignore[assignment]
        for key, expected in conditions.items():
            actual = feat.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True

    @staticmethod
    def _make_pattern_alert(rule: Rule, features: FeatureDict) -> Alert:
        """Build an Alert dict for a pattern rule match. No count field."""
        return Alert(
            rule=rule["name"],
            severity=rule["severity"],
            src_ip=features["src_ip"],
            dst_ip=features["dst_ip"],
            dst_port=features["dst_port"],
        )

    def _check_rate(self, rule: Rule, features: FeatureDict) -> Alert | None:
        """Evaluate a rate rule against the current feature dict.

        Appends the packet's timestamp to the sliding window bucket for
        (src_ip, rule_name), prunes entries outside the window, then fires
        if the bucket reaches the threshold.

        Empty buckets are deleted from _rate_state to prevent unbounded
        memory growth over long runtimes with many source IPs.

        Returns an Alert with count if the threshold is met, else None.

        Note: once the threshold is crossed, this fires on every subsequent
        matching packet until the window slides. The deduplicator downstream
        suppresses the repeats — this is an intentional design tradeoff.
        """
        if not self._matches_conditions(rule["conditions"], features):
            return None

        src_ip = features["src_ip"]
        ts     = features["timestamp"]
        key    = (src_ip, rule["name"])
        window = rule["window_seconds"]

        bucket = self._rate_state[key]
        bucket.append(ts)

        # Prune timestamps that have fallen outside the window.
        # Entries at exactly the boundary (ts - window) are considered expired.
        cutoff = ts - window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        # Self-clean: remove the bucket entirely when empty so _rate_state
        # does not grow unboundedly over long runtimes with many source IPs.
        if not bucket:
            del self._rate_state[key]
            return None

        if len(bucket) >= rule["threshold"]:
            return Alert(
                rule=rule["name"],
                severity=rule["severity"],
                src_ip=src_ip,
                dst_ip=features["dst_ip"],
                dst_port=features["dst_port"],
                count=len(bucket),
            )

        return None
