"""
Offline PCAP Analysis Dashboard.

Two modes:
  1. Upload mode (default): open http://localhost:5001, drag-and-drop a .pcap file.
  2. CLI mode (backwards-compatible):
       python dashboard/pcap_app.py --file alerts.json --pcap capture.pcap

Run via the nids shell script:
    ./nids --offline capture.pcap

Or directly (upload mode):
    python dashboard/pcap_app.py
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import tempfile
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from flask import Flask, abort, jsonify, redirect, request, send_from_directory
from werkzeug.utils import secure_filename
import config                                                 # noqa: E402
from detection.categories import RULE_CATEGORY, SEV_ORDER    # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB upload limit
_TEMPLATES = Path(__file__).parent / "templates"

_IP_RE = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}'
    r'|'
    r'[0-9a-fA-F:]{2,39}'
    r')$'
)

ALLOWED_EXT = frozenset({".pcap", ".pcapng", ".cap"})
_UPLOAD_DIR = Path(tempfile.gettempdir()) / "nids_pcap_uploads"
_UPLOAD_DIR.mkdir(exist_ok=True)


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


# ── Global state ──────────────────────────────────────────────────────────────

_ALERTS: list[dict] = []
_DATA:   dict       = {}
_STATE:  dict       = {"status": "idle", "error": None, "pcap_name": ""}
_LOCK                = threading.Lock()

_SEV_ORDER = SEV_ORDER
_SEV_RANK  = {sev: i for i, sev in enumerate(reversed(SEV_ORDER))}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _build_aggregates(alerts: list[dict], pcap_name: str) -> dict:
    """Pre-compute all dashboard aggregates from an alerts list."""
    by_sev:   dict[str, int]  = defaultdict(int)
    by_rule:  dict[str, dict] = {}
    by_cat:   dict[str, int]  = defaultdict(int)
    by_ip:    dict[str, dict] = {}
    timeline: dict[str, dict] = {}

    for a in alerts:
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

        bucket = ts[:16] if len(ts) >= 16 else ts
        if bucket not in timeline:
            timeline[bucket] = {"t": bucket, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        timeline[bucket][sev] = timeline[bucket].get(sev, 0) + 1

    timestamps = [a.get("timestamp", "") for a in alerts if a.get("timestamp")]
    first_ts   = min(timestamps) if timestamps else ""
    last_ts    = max(timestamps) if timestamps else ""

    return {
        "meta": {
            "pcap_file":    pcap_name,
            "analyzed_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "total_alerts": len(alerts),
            "first_ts":     first_ts[:19].replace("T", " ") if first_ts else "—",
            "last_ts":      last_ts[:19].replace("T", " ")  if last_ts  else "—",
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
        "alerts":   alerts,
    }


def _load(alerts_path: Path, pcap_path: str) -> None:
    """Load pre-computed alerts from a JSON-lines file (CLI / backwards-compat mode)."""
    global _ALERTS, _DATA
    alerts: list[dict] = []
    with alerts_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    _ALERTS = alerts
    _DATA   = _build_aggregates(alerts, Path(pcap_path).name if pcap_path else alerts_path.name)


def _analyze_pcap(pcap_path: Path) -> None:
    """Run a .pcap file through the full NIDS detection pipeline."""
    global _ALERTS, _DATA

    try:
        from scapy.all import PcapReader  # type: ignore[import]
    except ImportError:
        raise RuntimeError("scapy is not installed — run: pip install scapy")

    from parser.extractor import extract
    from detection.sig_detector import SignatureDetector
    from detection.correlator import Correlator

    detector   = SignatureDetector()
    correlator = Correlator()
    alerts: list[dict] = []

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            pkt_ts = float(pkt.time)
            try:
                features = extract(pkt)
            except ValueError:
                continue

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

    _ALERTS = alerts
    _DATA   = _build_aggregates(alerts, pcap_path.name)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(_TEMPLATES, "pcap_dashboard.html")


@app.route("/api/status")
def api_status():
    with _LOCK:
        return jsonify(dict(_STATE))


@app.route("/api/data")
def api_data():
    if not _DATA:
        abort(404)
    return jsonify(_DATA)


@app.route("/api/ip/<ip>")
def api_ip(ip: str):
    if not ip or not _valid_ip(ip):
        abort(400)
    alerts  = [a for a in _ALERTS if a.get("src_ip") == ip]
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


@app.route("/upload", methods=["POST"])
def upload():
    """Accept a .pcap file upload, run analysis, return JSON status."""
    with _LOCK:
        if _STATE["status"] == "running":
            return jsonify({"status": "error", "error": "An analysis is already running"}), 409

    f = request.files.get("pcap")
    if not f or not f.filename:
        return jsonify({"status": "error", "error": "No file provided"}), 400

    filename = secure_filename(f.filename or "upload.pcap")
    ext      = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        return jsonify({
            "status": "error",
            "error":  f"Unsupported file type '{ext}'. Please upload a .pcap, .pcapng, or .cap file.",
        }), 400

    save_path = _UPLOAD_DIR / filename
    try:
        f.save(str(save_path))

        with _LOCK:
            _STATE["status"]   = "running"
            _STATE["pcap_name"] = filename
            _STATE["error"]    = None

        _analyze_pcap(save_path)

        with _LOCK:
            _STATE["status"] = "done"

        return jsonify({"status": "done", "total": len(_ALERTS)})

    except Exception as exc:
        with _LOCK:
            _STATE["status"] = "error"
            _STATE["error"]  = str(exc)
        return jsonify({"status": "error", "error": str(exc)}), 500

    finally:
        try:
            save_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.route("/reset")
def reset():
    """Clear current analysis and return to upload mode."""
    global _ALERTS, _DATA
    with _LOCK:
        _ALERTS = []
        _DATA   = {}
        _STATE["status"]    = "idle"
        _STATE["error"]     = None
        _STATE["pcap_name"] = ""
    return redirect("/")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="NIDS offline PCAP analysis dashboard")
    p.add_argument("--file", "-f", default="",
                   help="Path to alerts JSON file from replay_pcap.py (optional — omit for upload mode)")
    p.add_argument("--pcap",  default="", help="Original pcap path (for display)")
    p.add_argument("--port",  type=int, default=5001)
    args = p.parse_args()

    if args.file:
        path = Path(args.file)
        if not path.exists():
            sys.exit(f"[pcap_app] Alerts file not found: {path}")
        _load(path, args.pcap)
        with _LOCK:
            _STATE["status"]    = "done"
            _STATE["pcap_name"] = Path(args.pcap).name if args.pcap else path.name
        print(f"[pcap]  Loaded {len(_ALERTS)} alerts from {path.name}")
    else:
        print("[pcap]  Upload mode — open the dashboard and drop a .pcap file")

    print(f"[pcap]  Dashboard → http://localhost:{args.port}  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
