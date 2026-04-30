"""
Feed a .pcap file through the NIDS detection pipeline and print a threat analysis report.

No root required. No live interface. No notifications sent.

Usage:
    python scripts/replay_pcap.py --file capture.pcap
    python scripts/replay_pcap.py --file capture.pcap --output alerts.json
    python scripts/replay_pcap.py --file capture.pcap --quiet
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from dotenv import load_dotenv
load_dotenv()

try:
    from scapy.all import PcapReader
except ImportError:
    sys.exit("[error] scapy is not installed.  Run: pip install scapy")

from parser.extractor import extract
from detection.sig_detector import SignatureDetector
from detection.correlator import Correlator

# Category lookup — defined in dashboard/app.py; fall back to empty dict if unavailable.
try:
    from dashboard.app import RULE_CATEGORY
except Exception:
    RULE_CATEGORY: dict[str, str] = {}

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_RANK  = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Replay a .pcap file through the NIDS detection engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python scripts/replay_pcap.py -f capture.pcap\n"
            "  python scripts/replay_pcap.py -f capture.pcap -o alerts.json\n"
            "  python scripts/replay_pcap.py -f capture.pcap --quiet\n"
        ),
    )
    p.add_argument("--file", "-f", required=True, metavar="PATH",
                   help="Path to the .pcap or .pcapng file")
    p.add_argument("--output", "-o", metavar="PATH",
                   help="Write triggered alerts as JSON lines to this file")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress per-alert output; show only the final report")
    return p.parse_args()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

def _duration_str(seconds: float) -> str:
    s = int(seconds)
    if s < 60:    return f"{s}s"
    if s < 3600:  return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"

def _bar(count: int, max_count: int, width: int = 36) -> str:
    if max_count == 0:
        return " " * width
    filled = round(count / max_count * width)
    return "▓" * filled + "░" * (width - filled)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    args      = _parse_args()
    pcap_path = Path(args.file)

    if not pcap_path.exists():
        sys.exit(f"[error] File not found: {pcap_path}")

    detector   = SignatureDetector()
    correlator = Correlator()

    alerts:         list[dict] = []
    total_packets:  int        = 0
    non_ip_packets: int        = 0
    first_ts:       float | None = None
    last_ts:        float | None = None

    output_fh = open(args.output, "w") if args.output else None

    print(f"[replay] Scanning {pcap_path.name}  ({pcap_path.stat().st_size / 1024:.1f} KB) ...")

    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                total_packets += 1

                # Progress tick on large files
                if total_packets % 10_000 == 0:
                    print(f"[replay] {total_packets:,} packets processed, {len(alerts)} alerts so far ...")

                pkt_ts = float(pkt.time)
                if first_ts is None or pkt_ts < first_ts:
                    first_ts = pkt_ts
                if last_ts is None or pkt_ts > last_ts:
                    last_ts = pkt_ts

                try:
                    features = extract(pkt)
                except ValueError:
                    non_ip_packets += 1
                    continue

                # Use the original capture timestamp so rate-window sliding is
                # accurate relative to when the packets actually occurred.
                features["timestamp"] = pkt_ts  # type: ignore[typeddict-unknown-key]

                raw_alerts = detector.process(features)
                alert      = correlator.correlate(raw_alerts)

                if alert is None:
                    continue

                record: dict = {
                    "timestamp":      _iso(pkt_ts),
                    "rule":           alert["rule"],
                    "severity":       alert["severity"],
                    "src_ip":         alert["src_ip"],
                    "dst_ip":         alert["dst_ip"],
                    "dst_port":       alert["dst_port"],
                    "protocol":       alert["protocol"],
                    "correlated":     alert["correlated"],
                    "also_triggered": alert["also_triggered"],
                    "threat_score":   alert.get("threat_score", 0),
                    "category":       RULE_CATEGORY.get(alert["rule"], "Other"),
                }
                if "count" in alert:
                    record["count"] = alert["count"]

                alerts.append(record)

                if not args.quiet:
                    port_str  = f":{alert['dst_port']}" if alert.get("dst_port") else ""
                    score_str = f"  score={alert.get('threat_score', 0)}" if alert.get("threat_score") else ""
                    also_str  = (f"  +{len(alert['also_triggered'])} more rules"
                                 if alert.get("also_triggered") else "")
                    print(
                        f"  [{_fmt_ts(pkt_ts)}]  {alert['severity']:<8}  "
                        f"{alert['rule']:<40}  "
                        f"{alert['src_ip']} → {alert['dst_ip']}{port_str}"
                        f"{score_str}{also_str}"
                    )

                if output_fh:
                    output_fh.write(json.dumps(record) + "\n")

    except FileNotFoundError:
        sys.exit(f"[error] Could not read file: {pcap_path}")
    except Exception as exc:
        print(f"[replay] Warning: stopped early due to read error: {exc}", file=sys.stderr)

    finally:
        if output_fh:
            output_fh.flush()
            output_fh.close()

    _print_report(
        pcap_path, total_packets, non_ip_packets, alerts,
        first_ts, last_ts, args.output,
    )


# ── Report ────────────────────────────────────────────────────────────────────

def _print_report(
    pcap_path:      Path,
    total_packets:  int,
    non_ip_packets: int,
    alerts:         list[dict],
    first_ts:       float | None,
    last_ts:        float | None,
    output_path:    str | None,
) -> None:
    W   = 80
    div = "─" * W

    # ── Aggregate ─────────────────────────────────────────────────────────────
    by_sev:  dict[str, int]  = defaultdict(int)
    by_rule: dict[str, dict] = {}
    by_cat:  dict[str, int]  = defaultdict(int)
    by_ip:   dict[str, dict] = {}

    for a in alerts:
        sev  = a.get("severity", "LOW")
        rule = a.get("rule", "Unknown")
        src  = a.get("src_ip", "")
        cat  = a.get("category", "Other")

        by_sev[sev] += 1
        by_cat[cat] += 1

        if rule not in by_rule:
            by_rule[rule] = {"count": 0, "severity": sev}
        by_rule[rule]["count"] += 1

        if src not in by_ip:
            by_ip[src] = {
                "count":      0,
                "worst_sev":  sev,
                "score":      0,
                "categories": set(),
            }
        entry = by_ip[src]
        entry["count"] += 1
        if _SEV_RANK[sev] > _SEV_RANK[entry["worst_sev"]]:
            entry["worst_sev"] = sev
        score = a.get("threat_score") or 0
        if score > entry["score"]:
            entry["score"] = score
        entry["categories"].add(cat)

    top_rules = sorted(by_rule.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    top_ips   = sorted(
        by_ip.items(),
        key=lambda x: (_SEV_RANK[x[1]["worst_sev"]], x[1]["score"], x[1]["count"]),
        reverse=True,
    )[:10]

    total_alerts = len(alerts)
    ip_packets   = total_packets - non_ip_packets
    duration     = (last_ts - first_ts) if (first_ts and last_ts) else 0.0

    crit_high = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]

    # ── Header ────────────────────────────────────────────────────────────────
    print()
    print("=" * W)
    print("  PCAP THREAT ANALYSIS REPORT")
    print(f"  File:     {pcap_path.name}  ({pcap_path.stat().st_size / 1024:.1f} KB)")
    print(f"  Analyzed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * W)

    # ── Overview ──────────────────────────────────────────────────────────────
    print()
    print("  OVERVIEW")
    print(f"  {div}")
    print(f"  Total packets    {total_packets:>10,}    "
          f"Capture start   {_fmt_ts(first_ts) if first_ts else 'n/a'}")
    print(f"  IP packets       {ip_packets:>10,}    "
          f"Capture end     {_fmt_ts(last_ts) if last_ts else 'n/a'}")
    print(f"  Non-IP skipped   {non_ip_packets:>10,}    "
          f"Duration        {_duration_str(duration)}")
    print(f"  Alerts generated {total_alerts:>10,}    "
          f"Unique attackers {len(by_ip):>5}")
    if output_path:
        print(f"  Alerts saved to  {output_path}")
    print(f"  {div}")

    if total_alerts == 0:
        print()
        print("  No alerts triggered — no traffic matched any NIDS signature.")
        print("=" * W)
        return

    # ── Severity breakdown ────────────────────────────────────────────────────
    print()
    print("  SEVERITY BREAKDOWN")
    print(f"  {div}")
    max_sev_count = max(by_sev.values(), default=1)
    for sev in _SEV_ORDER:
        cnt = by_sev.get(sev, 0)
        pct = cnt / total_alerts * 100 if total_alerts else 0.0
        bar = _bar(cnt, max_sev_count)
        print(f"  {sev:<8}  {bar}  {cnt:>5}  ({pct:>5.1f}%)")

    # ── Category breakdown ────────────────────────────────────────────────────
    print()
    print("  CATEGORY BREAKDOWN")
    print(f"  {div}")
    max_cat_count = max(by_cat.values(), default=1)
    for cat, cnt in sorted(by_cat.items(), key=lambda x: x[1], reverse=True):
        bar = _bar(cnt, max_cat_count, width=26)
        print(f"  {cat:<30}  {bar}  {cnt:>5}")

    # ── Top rules ────────────────────────────────────────────────────────────
    print()
    print("  TOP RULES TRIGGERED")
    print(f"  {div}")
    print(f"  {'#':<4} {'Rule':<44} {'Severity':<10} {'Count':>6}")
    print(f"  {div}")
    for i, (rule, info) in enumerate(top_rules, 1):
        print(f"  {i:<4} {rule:<44} {info['severity']:<10} {info['count']:>6}")

    # ── Top attacking IPs ────────────────────────────────────────────────────
    print()
    print("  TOP ATTACKING IPs")
    print(f"  {div}")
    print(f"  {'Source IP':<18} {'Worst':<10} {'Score':>5}  {'Alerts':>6}  Categories")
    print(f"  {div}")
    for ip, info in top_ips:
        cats = ", ".join(sorted(info["categories"]))
        # Truncate category list so line fits
        if len(cats) > 34:
            cats = cats[:31] + "..."
        print(
            f"  {ip:<18} {info['worst_sev']:<10} {info['score']:>5}  "
            f"{info['count']:>6}  {cats}"
        )

    # ── CRITICAL / HIGH details ───────────────────────────────────────────────
    if crit_high:
        limit = 20
        heading = (f"CRITICAL & HIGH ALERTS  (showing {limit} of {len(crit_high)})"
                   if len(crit_high) > limit
                   else f"CRITICAL & HIGH ALERTS  ({len(crit_high)} total)")
        print()
        print(f"  {heading}")
        print(f"  {div}")
        for a in crit_high[:limit]:
            port_str  = f":{a['dst_port']}" if a.get("dst_port") else ""
            score_str = f"  threat={a['threat_score']}/100" if a.get("threat_score") else ""
            also      = a.get("also_triggered") or []
            also_str  = f"  also: {', '.join(also[:2])}" if also else ""
            if len(also) > 2:
                also_str += f" (+{len(also) - 2} more)"
            ts_short  = a["timestamp"][:19].replace("T", " ")
            print(f"  [{ts_short}]  {a['severity']:<8}  {a['rule']}")
            print(f"    {a['src_ip']} → {a['dst_ip']}{port_str}{score_str}{also_str}")

    # ── Verdict ───────────────────────────────────────────────────────────────
    print()
    print("=" * W)
    crit_n = by_sev.get("CRITICAL", 0)
    high_n = by_sev.get("HIGH", 0)
    med_n  = by_sev.get("MEDIUM", 0)
    low_n  = by_sev.get("LOW", 0)

    if crit_n:
        verdict = f"CRITICAL THREATS DETECTED — {crit_n} critical, {high_n} high alerts"
    elif high_n:
        verdict = f"HIGH-SEVERITY THREATS DETECTED — {high_n} high alerts"
    elif med_n:
        verdict = f"MEDIUM-SEVERITY ACTIVITY — {med_n} medium alerts"
    else:
        verdict = f"LOW-SEVERITY ACTIVITY ONLY — {low_n} low alerts"

    print(f"  VERDICT: {verdict}")
    print("=" * W)
    print()


if __name__ == "__main__":
    main()
