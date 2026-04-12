from __future__ import annotations

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
    correlated:      bool           # True if more than one rule fired on this packet
    also_triggered:  list[str]      # names of every other rule that also fired
    count:           NotRequired[int]  # carried from the leading alert if it's a rate rule


def correlate(alerts: list[Alert]) -> CorrelatedAlert | None:
    """Select the highest-severity alert and annotate it with all other fired rules.

    Applies priority in order: CRITICAL > HIGH > MEDIUM > LOW.
    If multiple alerts share the highest severity, the first one leads.
    If the list is empty, returns None (packet is discarded with no alert).

    The also_triggered field preserves the names of every other rule that fired
    on the same packet, giving analysts the full picture in a single log entry.
    A CRITICAL hit that also triggered an SMB sweep and a port scan is a stronger
    signal than any of those alerts alone.

    Args:
        alerts: All alerts fired by sig_detector for a single packet.

    Returns:
        A CorrelatedAlert built from the highest-severity match, or None if
        alerts is empty.
    """
    if not alerts:
        return None

    leader = max(alerts, key=lambda a: config.SEVERITY_RANK[a["severity"]])
    others = [a["rule"] for a in alerts if a is not leader]

    correlated = CorrelatedAlert(
        rule=leader["rule"],
        severity=leader["severity"],
        src_ip=leader["src_ip"],
        dst_ip=leader["dst_ip"],
        dst_port=leader["dst_port"],
        correlated=len(others) > 0,
        also_triggered=others,
    )

    if "count" in leader:
        correlated["count"] = leader["count"]

    return correlated
