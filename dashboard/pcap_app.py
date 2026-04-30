"""
Offline PCAP Analysis Dashboard.

Reads the JSON alerts file produced by scripts/replay_pcap.py,
pre-computes all aggregates, and serves a rich web dashboard at
http://localhost:5001.

Run via the nids shell script:
    ./nids --offline capture.pcap

Or directly:
    python dashboard/pcap_app.py --file alerts.json --pcap capture.pcap
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from flask import Flask, abort, jsonify, send_from_directory

app = Flask(__name__)
_TEMPLATES = Path(__file__).parent / "templates"

_IP_RE = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}'
    r'|'
    r'[0-9a-fA-F:]{2,39}'
    r')$'
)


def _valid_ip(s: str) -> bool:
    if not _IP_RE.match(s):
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

_ALERTS: list[dict] = []
_DATA:   dict       = {}          # pre-computed; served by /api/data

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_RANK  = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# ── Data loading & aggregation ────────────────────────────────────────────────

def _load(alerts_path: Path, pcap_path: str) -> None:
    global _ALERTS, _DATA

    with alerts_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                _ALERTS.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    by_sev:  dict[str, int]  = defaultdict(int)
    by_rule: dict[str, dict] = {}
    by_cat:  dict[str, int]  = defaultdict(int)
    by_ip:   dict[str, dict] = {}
    timeline: dict[str, dict] = {}

    for a in _ALERTS:
        sev  = a.get("severity", "LOW")
        rule = a.get("rule", "Unknown")
        src  = a.get("src_ip", "?")
        cat  = a.get("category", "Other")
        ts   = a.get("timestamp", "")

        by_sev[sev] += 1
        by_cat[cat] += 1

        if rule not in by_rule:
            by_rule[rule] = {"count": 0, "severity": sev, "category": cat}
        by_rule[rule]["count"] += 1

        if src not in by_ip:
            by_ip[src] = {
                "count": 0, "worst_sev": sev, "score": 0,
                "categories": set(), "rules": set(),
            }
        entry = by_ip[src]
        entry["count"] += 1
        if _SEV_RANK[sev] > _SEV_RANK[entry["worst_sev"]]:
            entry["worst_sev"] = sev
        score = a.get("threat_score") or 0
        if score > entry["score"]:
            entry["score"] = score
        entry["categories"].add(cat)
        entry["rules"].add(rule)

        # Timeline bucketed by minute
        bucket = ts[:16] if len(ts) >= 16 else ts  # "2023-11-14T22:13"
        if bucket not in timeline:
            timeline[bucket] = {"t": bucket, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        timeline[bucket][sev] = timeline[bucket].get(sev, 0) + 1

    timestamps = [a.get("timestamp", "") for a in _ALERTS if a.get("timestamp")]
    first_ts   = min(timestamps) if timestamps else ""
    last_ts    = max(timestamps) if timestamps else ""

    _DATA = {
        "meta": {
            "pcap_file":     Path(pcap_path).name if pcap_path else "unknown.pcap",
            "analyzed_at":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "total_alerts":  len(_ALERTS),
            "first_ts":      first_ts[:19].replace("T", " ") if first_ts else "—",
            "last_ts":       last_ts[:19].replace("T", " ")  if last_ts  else "—",
        },
        "by_severity": {sev: by_sev.get(sev, 0) for sev in _SEV_ORDER},
        "by_category":  dict(sorted(by_cat.items(), key=lambda x: x[1], reverse=True)),
        "top_rules":    [
            {"rule": r, **info}
            for r, info in sorted(by_rule.items(), key=lambda x: x[1]["count"], reverse=True)[:15]
        ],
        "top_ips": [
            {
                "ip":         ip,
                "count":      info["count"],
                "worst_sev":  info["worst_sev"],
                "score":      info["score"],
                "categories": sorted(info["categories"]),
                "rules":      sorted(info["rules"]),
            }
            for ip, info in sorted(
                by_ip.items(),
                key=lambda x: (_SEV_RANK[x[1]["worst_sev"]], x[1]["score"], x[1]["count"]),
                reverse=True,
            )[:20]
        ],
        "timeline": sorted(timeline.values(), key=lambda x: x["t"]),
        "alerts":   _ALERTS,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(_TEMPLATES, "pcap_dashboard.html")


@app.route("/api/data")
def api_data():
    return jsonify(_DATA)


@app.route("/api/ip/<ip>")
def api_ip(ip: str):
    if not ip or not _valid_ip(ip):
        abort(400)
    alerts = [a for a in _ALERTS if a.get("src_ip") == ip]
    by_rule: dict[str, int] = defaultdict(int)
    by_sev:  dict[str, int] = defaultdict(int)
    for a in alerts:
        by_rule[a.get("rule", "Unknown")] += 1
        by_sev[a.get("severity", "LOW")] += 1
    return jsonify({
        "ip":      ip,
        "total":   len(alerts),
        "by_sev":  dict(by_sev),
        "by_rule": dict(sorted(by_rule.items(), key=lambda x: x[1], reverse=True)),
        "alerts":  sorted(alerts, key=lambda a: a.get("timestamp", ""), reverse=True),
    })


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="NIDS offline PCAP analysis dashboard")
    p.add_argument("--file",  required=True, help="Path to alerts JSON file from replay_pcap.py")
    p.add_argument("--pcap",  default="",    help="Original pcap path (for display)")
    p.add_argument("--port",  type=int, default=5001)
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        sys.exit(f"[pcap_app] Alerts file not found: {path}")

    _load(path, args.pcap)
    print(f"[pcap]  Loaded {len(_ALERTS)} alerts from {path.name}")
    print(f"[pcap]  Dashboard → http://localhost:{args.port}  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
