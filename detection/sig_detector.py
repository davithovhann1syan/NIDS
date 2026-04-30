from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import NotRequired, TypedDict

from detection.signatures import SIGNATURES, Rule, Severity
from parser.extractor import FeatureDict


_PROTO_NAME: dict[int, str] = {1: "ICMP", 6: "TCP", 17: "UDP"}


class Alert(TypedDict):
    rule:     str
    severity: Severity
    src_ip:   str
    dst_ip:   str
    dst_port: int | None
    protocol: str           # "TCP", "UDP", "ICMP", or numeric string for other IP protocols
    count:    NotRequired[int]


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
        # Multi-destination buckets: {(src_ip, rule_name): deque of (timestamp, tracked_value)}
        self._multidest_state: defaultdict[tuple[str, str], deque[tuple[float, object]]] = defaultdict(deque)
        # Precomputed window size per rule — used by purge_stale() to avoid O(rules) lookups.
        self._rule_windows: dict[str, int] = {
            r["name"]: r["window_seconds"]  # type: ignore[typeddict-item]
            for r in self._rules
            if r["type"] in ("rate", "multi_destination")
        }

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
                        alerts.append(self._build_alert(rule, features))
                case "rate":
                    alert = self._check_rate(rule, features)
                    if alert is not None:
                        alerts.append(alert)
                case "multi_destination":
                    alert = self._check_multi_destination(rule, features)
                    if alert is not None:
                        alerts.append(alert)

        return alerts

    def purge_stale(self) -> None:
        """Evict expired sliding-window entries for source IPs that have gone quiet.

        Called periodically from main.py (every ~2 minutes) to prevent _rate_state
        and _multidest_state from growing unboundedly when many distinct source IPs
        appear briefly then disappear — common during a scan or DDoS.
        """
        now = time.time()

        stale: list[tuple[str, str]] = []
        for key, bucket in self._rate_state.items():
            cutoff = now - self._rule_windows.get(key[1], 0)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                stale.append(key)
        for k in stale:
            del self._rate_state[k]

        stale = []
        for key, bucket in self._multidest_state.items():
            cutoff = now - self._rule_windows.get(key[1], 0)
            while bucket and bucket[0][0] <= cutoff:
                bucket.popleft()
            if not bucket:
                stale.append(key)
        for k in stale:
            del self._multidest_state[k]

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _matches_conditions(
        conditions: dict[str, object],
        features: FeatureDict,
    ) -> bool:
        """Return True if every condition matches the feature dict.

        Condition values support four forms:
        - Plain value:  equality check  (e.g. "protocol": 6)
        - List:         membership check (e.g. "dst_port": [80, 443])
        - Dict of ops:  comparison operators applied to the feature value:
            {">":  v}       actual >  v
            {">=": v}       actual >= v
            {"<":  v}       actual <  v
            {"<=": v}       actual <= v
            {"!=": v}       actual != v
            {"not_in": []}  actual not in list
            {"mask": v}     (actual & v) == v  — all bits in v are set in actual
          Multiple operators in one dict are ANDed together.
        """
        feat: dict[str, object] = features  # type: ignore[assignment]
        for key, expected in conditions.items():
            actual = feat.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif isinstance(expected, dict):
                for op, val in expected.items():
                    match op:
                        case ">" | "gt":
                            if actual is None or actual <= val:  # type: ignore[operator]
                                return False
                        case ">=" | "gte":
                            if actual is None or actual < val:  # type: ignore[operator]
                                return False
                        case "<" | "lt":
                            if actual is None or actual >= val:  # type: ignore[operator]
                                return False
                        case "<=" | "lte":
                            if actual is None or actual > val:  # type: ignore[operator]
                                return False
                        case "!=" | "not":
                            if actual == val:
                                return False
                        case "not_in":
                            if actual in val:
                                return False
                        case "mask":
                            # All bits in val must be set in actual.
                            if actual is None or (actual & val) != val:  # type: ignore[operator]
                                return False
            else:
                if actual != expected:
                    return False
        return True

    @staticmethod
    def _build_alert(rule: Rule, features: FeatureDict) -> Alert:
        return Alert(
            rule=rule["name"],
            severity=rule["severity"],
            src_ip=features["src_ip"],
            dst_ip=features["dst_ip"],
            dst_port=features["dst_port"],
            protocol=_PROTO_NAME.get(features["protocol"], str(features["protocol"])),
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
        cutoff = ts - window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

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
                protocol=_PROTO_NAME.get(features["protocol"], str(features["protocol"])),
                count=len(bucket),
            )

        return None

    def _check_multi_destination(self, rule: Rule, features: FeatureDict) -> Alert | None:
        """Evaluate a multi_destination rule.

        Counts unique values of the tracked field (dst_port or dst_ip) from a single
        source IP within a sliding window.  Fires when the unique count reaches the
        threshold — more accurate than raw packet counts for detecting real port/host scans.

        Like rate rules, fires on every matching packet once the threshold is crossed;
        the deduplicator downstream suppresses the repeats.
        """
        if not self._matches_conditions(rule["conditions"], features):
            return None

        src_ip = features["src_ip"]
        ts     = features["timestamp"]
        key    = (src_ip, rule["name"])
        window: int = rule["window_seconds"]  # type: ignore[typeddict-item]
        track: str  = rule["track"]           # type: ignore[typeddict-item]

        feat: dict[str, object] = features  # type: ignore[assignment]
        tracked_val = feat.get(track)
        if tracked_val is None:
            return None

        bucket = self._multidest_state[key]
        bucket.append((ts, tracked_val))

        cutoff = ts - window
        while bucket and bucket[0][0] <= cutoff:
            bucket.popleft()

        if not bucket:
            del self._multidest_state[key]
            return None

        unique_count = len({v for _, v in bucket})
        if unique_count >= rule["threshold"]:  # type: ignore[typeddict-item]
            return Alert(
                rule=rule["name"],
                severity=rule["severity"],
                src_ip=src_ip,
                dst_ip=features["dst_ip"],
                dst_port=features["dst_port"],
                protocol=_PROTO_NAME.get(features["protocol"], str(features["protocol"])),
                count=unique_count,
            )

        return None
