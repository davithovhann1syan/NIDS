from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import ipaddress
import re

from flask import Flask, jsonify, send_from_directory, request, abort

_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))
import allowlist  # noqa: E402
import config     # noqa: E402

app = Flask(__name__)
_LOG_PATH = _project_root / config.LOG_PATH

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

# Map rule names → display category (mirrors section headers in signatures.py)
RULE_CATEGORY: dict[str, str] = {
    # Reconnaissance
    "Port Scan (SYN)":                          "Reconnaissance",
    "Port Scan (Distinct Ports)":               "Reconnaissance",
    "Host Discovery Sweep (Distinct IPs)":      "Reconnaissance",
    "Null Scan":                                "Reconnaissance",
    "XMAS Scan":                                "Reconnaissance",
    "FIN Scan":                                 "Reconnaissance",
    "Maimon Scan":                              "Reconnaissance",
    "ACK Scan":                                 "Reconnaissance",
    "ICMP Host Sweep (Ping Sweep)":             "Reconnaissance",
    "UDP Port Scan":                            "Reconnaissance",
    "Invalid TCP Flags: SYN+RST":              "Reconnaissance",
    "Invalid TCP Flags: SYN+FIN":              "Reconnaissance",
    "Oversized ICMP Packet":                    "Reconnaissance",
    "Low TTL Probe (Traceroute / Evasion)":     "Reconnaissance",
    "TCP SYN with Large Payload":               "Reconnaissance",
    # Brute Force
    "SSH Brute Force":                          "Brute Force",
    "RDP Brute Force":                          "Brute Force",
    "FTP Brute Force":                          "Brute Force",
    "Telnet Brute Force":                       "Brute Force",
    "SMTP Auth Brute Force":                    "Brute Force",
    "IMAP Brute Force":                         "Brute Force",
    "POP3 Brute Force":                         "Brute Force",
    "VNC Brute Force":                          "Brute Force",
    "MySQL Brute Force":                        "Brute Force",
    "PostgreSQL Brute Force":                   "Brute Force",
    "MSSQL Brute Force":                        "Brute Force",
    "Kerberos Brute Force (AS-REP Roasting / Password Spray)": "Brute Force",
    # Denial of Service
    "SYN Flood":                                "Denial of Service",
    "ICMP Flood":                               "Denial of Service",
    "UDP Flood":                                "Denial of Service",
    "RST Flood":                                "Denial of Service",
    "ACK Flood":                                "Denial of Service",
    "DNS Amplification Attack":                 "Denial of Service",
    "NTP Amplification Attack":                 "Denial of Service",
    "Memcached Exposed (DDoS Amplification)":   "Denial of Service",
    # Suspicious Services
    "Telnet Attempt":                           "Suspicious Services",
    "FTP Cleartext Login":                      "Suspicious Services",
    "rlogin / rsh Attempt":                     "Suspicious Services",
    "TFTP Access":                              "Suspicious Services",
    "SNMP Access (v1/v2)":                      "Suspicious Services",
    "NFS Access":                               "Suspicious Services",
    "LLMNR Traffic (Possible Responder / MITM)": "Suspicious Services",
    "SSDP / UPnP Discovery":                    "Suspicious Services",
    # Command & Control
    "Known C2 / Backdoor Port":                 "Malware & C2",
    "Possible Reverse Shell (High Outbound Port)": "Malware & C2",
    "IRC Traffic (Possible Botnet C2)":         "Malware & C2",
    "Tor Default Port":                         "Malware & C2",
    "DNS over Non-Standard Port (Possible DNS Tunneling)": "Malware & C2",
    "Cobalt Strike Default Beacon Port":        "Malware & C2",
    "Netcat / Bind Shell Default Port":         "Malware & C2",
    "Aggressive Outbound SYN Rate (Worm / Scanner)": "Malware & C2",
    # Lateral Movement
    "SMB Access (Possible Lateral Movement)":   "Lateral Movement",
    "SMB Sweep (Ransomware Propagation)":       "Lateral Movement",
    "WinRM Access (Possible Lateral Movement)": "Lateral Movement",
    "DCOM / RPC Access":                        "Lateral Movement",
    "NetBIOS Name / Datagram Service":          "Lateral Movement",
    "LDAP Enumeration":                         "Lateral Movement",
    # Exposed Services
    "Log4Shell Target Port (8080/8443)":        "Exposed Services",
    "Redis Exposed (No Auth)":                  "Exposed Services",
    "Elasticsearch Exposed":                    "Exposed Services",
    "MongoDB Exposed":                          "Exposed Services",
    "Docker API Exposed":                       "Exposed Services",
    "Kubernetes API Exposed":                   "Exposed Services",
    "etcd Exposed":                             "Exposed Services",
    "CouchDB Exposed":                          "Exposed Services",
    "Hadoop / HDFS Exposed":                    "Exposed Services",
    # Exfiltration
    "DNS Query Flood UDP (Possible DNS Tunneling)": "Exfiltration",
    "DNS Query Flood TCP (Possible DNS Tunneling)": "Exfiltration",
    "ICMP Exfiltration (Large Volume)":         "Exfiltration",
    "FTP Data Channel (Possible Exfiltration)": "Exfiltration",
    # Network Infrastructure Attacks
    "BGP Connection Attempt":                   "Infrastructure Attack",
    "OSPF Injection":                           "Infrastructure Attack",
    "EIGRP Traffic":                            "Infrastructure Attack",
    "GRE Tunnel Traffic":                       "Infrastructure Attack",
    "IPv6-in-IPv4 Tunnel":                      "Infrastructure Attack",
    "ICMP Redirect (Routing Manipulation)":     "Infrastructure Attack",
    # ICS / SCADA
    "Modbus Access (ICS Protocol)":             "ICS / SCADA",
    "DNP3 Access (ICS Protocol)":               "ICS / SCADA",
    "EtherNet/IP Access (ICS Protocol)":        "ICS / SCADA",
    "BACnet Access (Building Automation)":      "ICS / SCADA",
    # Miscellaneous
    "Proxy / Anonymizer Port":                  "Policy Violation",
    "P2P / BitTorrent Port":                    "Policy Violation",
    "Cryptocurrency Mining Pool":               "Policy Violation",
}


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
