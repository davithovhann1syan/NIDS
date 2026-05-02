from __future__ import annotations

import json
import os
import signal
import subprocess as _sp
import sys
import threading
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import ipaddress
import re

from flask import Flask, jsonify, send_from_directory, request, abort
from werkzeug.utils import secure_filename

_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))
import allowlist                          # noqa: E402
import config                             # noqa: E402
from detection.categories import RULE_CATEGORY, SEV_ORDER  # noqa: E402

app = Flask(__name__)
_LOG_PATH = _project_root / config.LOG_PATH

# ── Capture engine process management ─────────────────────────────────────────
_capture_proc:       "_sp.Popen | None" = None
_capture_started_at: "datetime | None"  = None
_capture_iface: str                     = config.INTERFACE
_capture_lock                           = threading.Lock()


def _find_external_nids_pid() -> "int | None":
    """Return the PID of a running main.py process we did not spawn ourselves."""
    try:
        result = _sp.run(
            ["pgrep", "-a", "-f", r"python.*main\.py"],
            capture_output=True, text=True, timeout=2,
        )
        my_pid = os.getpid()
        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 1)
            if not parts:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid == my_pid:
                continue
            cmd = parts[1] if len(parts) > 1 else ""
            if "main.py" in cmd:
                return pid
    except Exception:
        pass
    return None

_IP_RE = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}'          # IPv4
    r'|'
    r'[0-9a-fA-F:]{2,39}'             # IPv6 (compact or full)
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


def _read_alerts(limit: int = 500) -> list[dict]:
    """Read the last `limit` alerts from nids.log, newest first.

    Seeks from the end of the file so large logs don't cause memory spikes.
    Uses ~350 bytes/line as a conservative estimate; 2× safety buffer.
    If the file is smaller than the estimated chunk, the full file is read.
    """
    if not _LOG_PATH.exists():
        return []
    try:
        with _LOG_PATH.open("rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            chunk = min(file_size, limit * 700)
            f.seek(max(0, file_size - chunk))
            if file_size > chunk:
                f.readline()  # discard the partial line at the seek boundary
            raw = f.read()
        text = raw.decode(errors="replace")
    except OSError:
        return []

    alerts: list[dict] = []
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        a["category"] = RULE_CATEGORY.get(a.get("rule", ""), "Other")
        a.setdefault("also_triggered", [])
        a.setdefault("correlated", False)
        a.setdefault("threat_score", 0)
        # Stable ID: timestamp + rule (microseconds make collisions negligible)
        a["id"] = a.get("timestamp", "") + "|" + a.get("rule", "")
        alerts.append(a)
        if len(alerts) >= limit:
            break
    return alerts


@app.route("/")
def index():
    return send_from_directory(
        Path(__file__).parent / "templates", "index.html"
    )


@app.route("/api/alerts")
def api_alerts():
    try:
        limit = min(int(request.args.get("limit", 500)), 2000)
    except (TypeError, ValueError):
        abort(400)
    severity = request.args.get("severity") or None
    since    = request.args.get("since") or None
    ip_q     = request.args.get("ip") or None
    rule_q   = request.args.get("rule") or None

    # Over-read so filters don't starve the result set
    alerts = _read_alerts(min(limit * 4, 2000))

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if ip_q:
        alerts = [a for a in alerts if ip_q in a.get("src_ip", "")]
    if rule_q:
        rq = rule_q.lower()
        alerts = [a for a in alerts if rq in a.get("rule", "").lower()]
    if since:
        # Timestamps are ISO strings — lexicographic comparison is correct
        alerts = [a for a in alerts if a.get("timestamp", "") > since]

    return jsonify(alerts[:limit])


@app.route("/api/stats")
def api_stats():
    alerts = _read_alerts(10_000)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_rule: dict[str, int] = {}
    by_src:  dict[str, int] = {}
    today = 0

    for a in alerts:
        sev = a.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1
        rule = a.get("rule", "Unknown")
        by_rule[rule] = by_rule.get(rule, 0) + 1
        src = a.get("src_ip", "")
        if src:
            by_src[src] = by_src.get(src, 0) + 1
        if a.get("timestamp", "").startswith(today_str):
            today += 1

    top_src   = sorted(by_src.items(),  key=lambda x: x[1], reverse=True)[:10]
    top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        "total":          len(alerts),
        "today":          today,
        "by_severity":    by_sev,
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_src],
        "top_rules":      [{"rule": r, "count": c} for r, c in top_rules],
    })


@app.route("/api/health")
def api_health():
    from detection.signatures import SIGNATURES  # noqa: PLC0415
    log_exists = _LOG_PATH.exists()
    log_bytes  = _LOG_PATH.stat().st_size if log_exists else 0
    log_size   = (
        f"{log_bytes / 1024:.1f} KB"  if log_bytes < 1_048_576 else
        f"{log_bytes / 1_048_576:.1f} MB"
    )
    return jsonify({
        "interface":    config.INTERFACE,
        "log_exists":   log_exists,
        "log_size":     log_size,
        "rules_active": len(SIGNATURES),
    })


@app.route("/api/rules")
def api_rules():
    from detection.signatures import SIGNATURES  # noqa: PLC0415
    return jsonify([
        {
            "name":     sig["name"],
            "severity": sig["severity"],
            "type":     sig["type"],
            "category": RULE_CATEGORY.get(sig["name"], "Other"),
            "mitre":    sig.get("mitre"),
        }
        for sig in SIGNATURES
    ])


@app.route("/api/ip/<ip>")
def api_ip(ip: str):
    """Return aggregated investigation data for a specific source IP."""
    if not ip or not _valid_ip(ip):
        abort(400)

    alerts    = _read_alerts(2000)
    ip_alerts = [a for a in alerts if a.get("src_ip") == ip]

    by_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_rule: dict[str, int] = {}

    for a in ip_alerts:
        sev = a.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1
        rule = a.get("rule", "Unknown")
        by_rule[rule] = by_rule.get(rule, 0) + 1

    timestamps = [a["timestamp"] for a in ip_alerts if a.get("timestamp")]
    top_rules  = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]

    # Risk score: each CRITICAL = 20 pts, HIGH = 8 pts, total events capped at 40
    crit  = by_sev["CRITICAL"]
    high  = by_sev["HIGH"]
    score = min(100, crit * 20 + high * 8 + min(len(ip_alerts) * 2, 40))

    return jsonify({
        "ip":          ip,
        "total":       len(ip_alerts),
        "risk_score":  score,
        "by_severity": by_sev,
        "first_seen":  min(timestamps) if timestamps else None,
        "last_seen":   max(timestamps) if timestamps else None,
        "top_rules":   [{"rule": r, "count": c} for r, c in top_rules],
        "recent":      ip_alerts[:20],
    })


@app.route("/api/allowlist", methods=["GET"])
def api_allowlist_get():
    return jsonify({"entries": allowlist.get_entries()})


@app.route("/api/allowlist", methods=["POST"])
def api_allowlist_add():
    body = request.get_json(silent=True) or {}
    entry = body.get("entry", "").strip()
    if not entry:
        abort(400)
    if not allowlist.add_entry(entry):
        abort(422)
    return jsonify({"entries": allowlist.get_entries()}), 201


@app.route("/api/allowlist", methods=["DELETE"])
def api_allowlist_remove():
    body = request.get_json(silent=True) or {}
    entry = body.get("entry", "").strip()
    if not entry:
        abort(400)
    if not allowlist.remove_entry(entry):
        abort(404)
    return jsonify({"entries": allowlist.get_entries()})


# ── Capture engine control ────────────────────────────────────────────────────

@app.route("/api/capture/status")
def api_capture_status():
    with _capture_lock:
        proc    = _capture_proc
        started = _capture_started_at
        iface   = _capture_iface

    running  = False
    pid      = None
    uptime_s = 0
    external = False

    if proc is not None and proc.poll() is None:
        running  = True
        pid      = proc.pid
        if started:
            uptime_s = int((datetime.now(timezone.utc) - started).total_seconds())
    else:
        ext_pid = _find_external_nids_pid()
        if ext_pid:
            running  = True
            pid      = ext_pid
            external = True

    return jsonify({
        "running":    running,
        "pid":        pid,
        "interface":  iface,
        "started_at": started.isoformat() if started else None,
        "uptime_s":   uptime_s,
        "external":   external,
    })


@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    global _capture_proc, _capture_started_at, _capture_iface
    body  = request.get_json(silent=True) or {}
    iface = (body.get("interface") or "").strip() or config.INTERFACE

    if not re.match(r'^[a-zA-Z0-9\-:\.]+$', iface):
        abort(400)

    with _capture_lock:
        if _capture_proc and _capture_proc.poll() is None:
            return jsonify({"error": "Capture already running"}), 409
        try:
            cmd  = ["sudo", "-n", sys.executable,
                    str(_project_root / "main.py"), "--interface", iface]
            proc = _sp.Popen(cmd, cwd=str(_project_root),
                             stdout=_sp.DEVNULL, stderr=_sp.PIPE)
            # Brief pause to catch immediate sudo failures
            time.sleep(0.35)
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace").strip()
                hint = ("sudo requires a password — add NOPASSWD to /etc/sudoers "
                        "or start from terminal: sudo python main.py")
                return jsonify({"error": err or hint}), 500
            _capture_proc       = proc
            _capture_started_at = datetime.now(timezone.utc)
            _capture_iface      = iface
        except FileNotFoundError:
            return jsonify({
                "error": "sudo not found. Start capture from terminal: sudo python main.py"
            }), 500
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "started", "pid": _capture_proc.pid, "interface": iface})


@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    global _capture_proc, _capture_started_at
    with _capture_lock:
        proc = _capture_proc

    if proc is not None and proc.poll() is None:
        try:
            os.kill(proc.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        with _capture_lock:
            _capture_proc       = None
            _capture_started_at = None
        return jsonify({"status": "stopped"})

    ext_pid = _find_external_nids_pid()
    if ext_pid:
        try:
            result = _sp.run(
                ["sudo", "-n", "kill", "-INT", str(ext_pid)],
                capture_output=True, timeout=3,
            )
            if result.returncode == 0:
                return jsonify({"status": "stopped", "pid": ext_pid})
            err = result.stderr.decode(errors="replace").strip()
            return jsonify({
                "error": f"Cannot stop PID {ext_pid}: {err or 'sudo permission denied'}"
            }), 500
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return jsonify({"error": "No running capture found"}), 404


# ── PCAP Analysis ─────────────────────────────────────────────────────────────

app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

PCAP_ALLOWED_EXT = frozenset({".pcap", ".pcapng", ".cap"})
_UPLOAD_DIR      = Path(tempfile.gettempdir()) / "nids_pcap_uploads"
_UPLOAD_DIR.mkdir(exist_ok=True)

_PCAP_ALERTS: list[dict] = []
_PCAP_DATA:   dict       = {}
_PCAP_STATE:  dict       = {"status": "idle", "error": None, "pcap_name": ""}
_PCAP_LOCK                = threading.Lock()

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_RANK  = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _pcap_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _pcap_build_aggregates(alerts: list[dict], pcap_name: str) -> dict:
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
            by_ip[src] = {"count": 0, "worst_sev": sev, "score": 0,
                          "categories": set(), "rules": set()}
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


def _pcap_analyze(pcap_path: Path) -> None:
    global _PCAP_ALERTS, _PCAP_DATA
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
                "timestamp":      _pcap_iso(pkt_ts),
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

    _PCAP_ALERTS = alerts
    _PCAP_DATA   = _pcap_build_aggregates(alerts, pcap_path.name)


@app.route("/pcap/api/status")
def pcap_api_status():
    with _PCAP_LOCK:
        return jsonify(dict(_PCAP_STATE))


@app.route("/pcap/api/data")
def pcap_api_data():
    if not _PCAP_DATA:
        abort(404)
    return jsonify(_PCAP_DATA)


@app.route("/pcap/api/ip/<ip>")
def pcap_api_ip(ip: str):
    if not ip or not _valid_ip(ip):
        abort(400)
    alerts  = [a for a in _PCAP_ALERTS if a.get("src_ip") == ip]
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


@app.route("/pcap/upload", methods=["POST"])
def pcap_upload():
    with _PCAP_LOCK:
        if _PCAP_STATE["status"] == "running":
            return jsonify({"status": "error", "error": "An analysis is already running"}), 409

    f = request.files.get("pcap")
    if not f or not f.filename:
        return jsonify({"status": "error", "error": "No file provided"}), 400

    filename = secure_filename(f.filename or "upload.pcap")
    ext      = Path(filename).suffix.lower()
    if ext not in PCAP_ALLOWED_EXT:
        return jsonify({
            "status": "error",
            "error":  f"Unsupported file type '{ext}'. Upload a .pcap, .pcapng, or .cap file.",
        }), 400

    save_path = _UPLOAD_DIR / filename
    try:
        f.save(str(save_path))
        with _PCAP_LOCK:
            _PCAP_STATE["status"]    = "running"
            _PCAP_STATE["pcap_name"] = filename
            _PCAP_STATE["error"]     = None
        _pcap_analyze(save_path)
        with _PCAP_LOCK:
            _PCAP_STATE["status"] = "done"
        return jsonify({"status": "done", "total": len(_PCAP_ALERTS)})
    except Exception as exc:
        with _PCAP_LOCK:
            _PCAP_STATE["status"] = "error"
            _PCAP_STATE["error"]  = str(exc)
        return jsonify({"status": "error", "error": str(exc)}), 500
    finally:
        try:
            save_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.route("/pcap/reset")
def pcap_reset():
    global _PCAP_ALERTS, _PCAP_DATA
    with _PCAP_LOCK:
        _PCAP_ALERTS = []
        _PCAP_DATA   = {}
        _PCAP_STATE["status"]    = "idle"
        _PCAP_STATE["error"]     = None
        _PCAP_STATE["pcap_name"] = ""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
