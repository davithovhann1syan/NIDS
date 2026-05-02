# Network Intrusion Detection System (NIDS)

**Author:** Davit Hovhannisyan
**Course:** Network Security
**Date:** May 2026

A Python-based signature-driven Network Intrusion Detection System for low-to-medium traffic internal network segments (< 100 Mbps). Captures live packets from a Linux network interface, runs them through a multi-stage rule engine, deduplicates and correlates alerts, writes structured JSON logs, sends real-time notifications, and exposes a live web dashboard for monitoring and investigation. 74 rules across 11 threat categories.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [The Problem](#the-problem)
- [Research Background](#research-background)
- [Architecture Philosophy](#architecture-philosophy)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Threading Model](#threading-model)
- [The Queue — The System's Pressure Valve](#the-queue--the-systems-pressure-valve)
- [Packet Capture](#packet-capture----capturesniferpy)
- [Packet Parsing](#packet-parsing----parserextractorpy)
- [Detection Engine](#detection-engine)
- [Alert Correlation and Threat Scoring](#alert-correlation-and-threat-scoring)
- [Alerting Pipeline](#alerting-pipeline)
- [Dashboard](#dashboard)
- [Scripts](#scripts)
- [Signature Rule Coverage](#signature-rule-coverage)
- [False Positive Reduction](#false-positive-reduction)
- [Configuration — `config.py`](#configuration----configpy)
- [Alert Schema](#alert-schema)
- [Commands](#commands)
- [Completed Components](#completed-components)
- [Deployment](#deployment-production)
- [Known Limitations](#known-limitations)
- [Future Improvements](#future-improvements)
- [Lessons Learned](#lessons-learned)

---

## Executive Summary

NIDS is a Python-based Network Intrusion Detection System designed for low-to-medium traffic internal network segments (< 100 Mbps). It captures live packets from a Linux network interface, runs them through a multi-stage rule engine, deduplicates and correlates alerts, writes structured logs, sends real-time notifications, and exposes a live web dashboard for monitoring and investigation.

The system is purely signature-based — no machine learning or statistical anomaly detection. Detection quality is determined entirely by the quality and coverage of the signature rules. The current ruleset contains 74 rules spanning 11 threat categories, all mapped to MITRE ATT&CK techniques.

Target environment: home or small office network running Linux.

---

## The Problem

### The Visibility Gap in Internal Networks

Most home networks, small offices, and lab environments operate with zero network-level monitoring. Firewalls filter incoming traffic at the perimeter, but once an attacker is inside — or generates traffic from within — there is typically nothing watching the wire. This creates a silent kill chain: an attacker can perform reconnaissance, brute-force credentials, establish command-and-control channels, and exfiltrate data without triggering a single alert.

### Threat Landscape Addressed

This project targets the following classes of active threats observed on internal IPv4 network segments:

| Category | Examples |
|---|---|
| Reconnaissance | Port scans (SYN, FIN, NULL, XMAS), ping sweeps, host discovery |
| Brute Force | SSH, RDP, FTP, database, and VNC credential stuffing |
| Denial of Service | SYN flood, ICMP flood, UDP flood, amplification |
| Malware & C2 | Known backdoor ports, reverse shells, Cobalt Strike beacons, DNS tunneling |
| Lateral Movement | SMB sweeps, WinRM access, ransomware propagation |
| Data Exfiltration | DNS tunneling, high-volume ICMP, FTP data channels |
| Exposed Services | Unauthenticated Redis, MongoDB, Docker API, Kubernetes API |
| Infrastructure Attacks | BGP hijacking, OSPF injection, NTP/DNS amplification |
| ICS / SCADA | Modbus, DNP3, EtherNet/IP, BACnet protocol access |
| Policy Violations | Proxy/anonymizer ports, P2P traffic, crypto mining |

### Why Existing Tools Fall Short

Enterprise-grade IDS solutions like Snort and Suricata are powerful but carry significant operational overhead: they require dedicated hardware, complex rule management pipelines (PulledPork, Oinkmaster), and ongoing tuning by security engineers. Zeek produces rich traffic logs but requires a separate analysis layer to translate those logs into alerts. None of these are practical for a single-operator home lab or small office without dedicated security staff.

The gap: there is no lightweight, self-contained, easy-to-deploy intrusion detection system that provides real-time alerting, a human-readable dashboard, and a tunable signature engine — without requiring enterprise infrastructure.

---

## Research Background

### Intrusion Detection Approaches

Network intrusion detection systems fall into two broad categories:

**Signature-based (misuse) detection** matches observed traffic against a library of known attack patterns. Detection is deterministic and produces almost no false positives for well-tuned signatures. The weakness is that zero-day attacks — traffic that matches no known signature — are completely invisible.

**Anomaly-based detection** builds a statistical model of "normal" traffic and alerts on deviations. This can catch novel attacks but produces significantly more false positives and requires a training period to establish baselines. Bayesian classifiers, k-means clustering, and neural networks have all been applied here.

This project implements signature-based detection, chosen for its precision and suitability for a first deployment where low false-positive rates are more operationally valuable than broad coverage of unknown threats.

### MITRE ATT&CK Framework

The MITRE ATT&CK framework (Adversarial Tactics, Techniques, and Common Knowledge) is a publicly maintained knowledge base of adversary behaviors observed in real-world intrusions. It organizes techniques into 14 tactics (Reconnaissance → Initial Access → Execution → … → Exfiltration → Impact).

Each of the 74 detection rules in this project is mapped to a MITRE technique ID (e.g., T1046 for Network Service Scanning, T1110 for Brute Force, T1498 for Network Denial of Service). This mapping serves two purposes:

1. It ensures rule coverage is grounded in documented real-world adversary behavior rather than theoretical threat modelling.
2. It allows alerts to be correlated with the ATT&CK matrix, making it easier to identify which phase of an attack is in progress.

### Relevant Attack Techniques

**Port Scanning (T1046)**
Port scanning is the first step in almost every network attack. Nmap's default SYN scan sends a TCP SYN to each target port; if a SYN-ACK is returned the port is open. Stealth scans (FIN, NULL, XMAS, Maimon) exploit RFC 793 edge cases: a closed port responds with RST, while an open port ignores the malformed packet entirely. These scan types are designed to evade stateful firewalls that track only SYN-initiated connections.

**Brute Force (T1110)**
Credential stuffing attacks repeatedly attempt authentication against a service. SSH brute force (Hydra, Medusa) is among the most common attacks on internet-exposed machines. The rate of login attempts is typically limited by the server's response time, making rate-based detection effective: a legitimate user does not send 10 SSH SYN packets in 60 seconds.

**SYN Flood (T1498.001)**
A SYN flood exhausts the target's TCP connection state table by sending large volumes of SYN packets with spoofed source IPs. The target allocates half-open connection state for each SYN, waiting for the final ACK that never arrives. Modern operating systems mitigate this with SYN cookies, but detection remains valuable for identifying when an attack is being directed at the network.

**DNS Tunneling (T1048.001, T1071.004)**
DNS tunneling encodes arbitrary data inside DNS queries and responses to bypass firewalls that allow port 53 outbound. Tools like dnscat2 and iodine use this technique for command-and-control or data exfiltration. The signature: a single host generating hundreds of DNS queries per minute to external resolvers, or DNS traffic appearing on non-standard ports.

**Exposed Cloud-Native Services (T1190, T1610)**
Unauthenticated access to Redis, MongoDB, Elasticsearch, Docker's remote API, or the Kubernetes API server can lead to full cluster compromise or data theft. Shodan regularly finds tens of thousands of such services publicly accessible. On internal networks, these services are sometimes deployed by developers without authentication, making lateral movement trivial for any attacker who gains initial access.

**Cobalt Strike (T1105)**
Cobalt Strike is a commercial penetration testing framework widely abused by threat actors. Its default beacon communicates over port 50050 (team server) and uses configurable malleable C2 profiles to disguise traffic. Pattern-based detection of the default port provides a high-confidence signal even when content inspection is unavailable.

### Packet Capture with Scapy

Scapy is a Python library for packet manipulation, capture, and analysis. It provides a high-level API over raw socket I/O: `sniff()` opens a raw socket, applies a BPF (Berkeley Packet Filter) kernel-level filter, and delivers matched packets to a Python callback. Using the BPF filter `"ip"` at the kernel level means only IPv4 packets ever reach userspace, substantially reducing processing overhead compared to filtering in Python.

Scapy's layer-aware parsing (`pkt[IP]`, `pkt[TCP]`, `pkt.haslayer(ICMP)`) handles malformed or truncated packets gracefully, making it suitable for hostile traffic where an attacker may send intentionally malformed frames to confuse analysis tools.

### Sliding Window State for Rate Detection

Rate-based detection requires tracking how many matching packets a given source IP has sent within a rolling time window. The standard approach is a sliding window deque: a `collections.deque` that stores timestamps of matching packets. On each new matching packet:

1. Append the current timestamp.
2. Prune all entries older than `window_seconds` from the left end.
3. If `len(deque) >= threshold`, fire the alert.

This runs in O(k) time where k is the threshold count, is bounded in memory, and does not require a separate timer thread. State is keyed by `(src_ip, rule_name)` so rules are independent and cannot interfere with each other.

---

## Architecture Philosophy

**1. Strict one-way data flow**
No module downstream ever reaches back upstream. The dashboard does not touch the detector. The detector does not touch the logger. This prevents circular dependencies and makes each stage independently testable.

**2. Single responsibility per module**
Each file does exactly one thing. `sniffer.py` only captures. `extractor.py` only parses. `logger.py` is the only thing that writes to disk.

**3. Fail safely under load**
If the system cannot keep up with traffic, packets are **dropped at the queue boundary** rather than consuming unbounded memory. It is better to miss some packets than to crash.

**4. Dashboard fully isolated from detection**
The web dashboard is a completely separate process that reads only the log file — a bug in the dashboard cannot corrupt detection state or affect live packet capture.

### Pipeline

```
[NIC] → sniffer.py → Queue → extractor.py → sig_detector.py → correlator.py → deduplicator.py → logger.py → notifier.py
                                                                        dashboard/app.py reads logs/ independently
```

---

## Project Structure

```
nids/
├── main.py                      # Entry point — starts threads, handles shutdown
├── config.py                    # Single source of truth for all tuneable values
├── allowlist.py                 # IP/CIDR allowlist — suppress alerts from trusted hosts
├── allowlist.json               # Allowlisted entries (editable from dashboard or directly)
├── nids                         # Shell script wrapper: ./nids --interface wlan0
├── requirements.txt
├── setup.sh                     # Installs dependencies and sets up the environment
├── .gitignore                   # Excludes: logs/, .venv/
│
├── capture/
│   ├── sniffer.py               # Scapy sniff() — enqueues packets, nothing else
│   └── queue_manager.py         # Thread-safe bounded Queue (maxsize 10,000)
│
├── parser/
│   └── extractor.py             # Packet → FeatureDict. Handles missing layers safely.
│
├── detection/
│   ├── signatures.py            # 74 rule definitions (pattern, rate, multi_destination)
│   ├── sig_detector.py          # Pattern match + rate + multi_destination engine
│   ├── correlator.py            # Per-packet correlation + cross-packet threat scoring
│   └── categories.py            # RULE_CATEGORY dict + SEV_ORDER — single source of truth
│
├── alerting/
│   ├── deduplicator.py          # Suppresses (rule, src_ip) repeats within cooldown
│   ├── logger.py                # JSON-lines writer — the only module that writes to disk
│   └── notifier.py              # Batched email + Slack dispatch, daemon thread
│
├── dashboard/
│   ├── app.py                   # Live dashboard — Flask REST API + capture engine control
│   ├── pcap_app.py              # Offline PCAP dashboard — upload & analyse .pcap files
│   ├── templates/
│   │   ├── index.html           # Live dashboard UI (React, 7 views, dark/light theme)
│   │   └── pcap_dashboard.html  # Standalone PCAP analysis UI (served by pcap_app.py)
│   └── static/                  # JS/JSX component files loaded by index.html
│       ├── nids-data.js         # Demo data, rule list, geo data
│       ├── nids-ui.jsx          # UI primitives: badges, drawers, toasts, shortcuts
│       ├── nids-charts.jsx      # Chart.js wrappers + SVG world map
│       └── tweaks-panel.jsx     # Settings panel component
│
├── deploy/
│   ├── nids.service             # systemd unit for the capture engine (runs as root)
│   ├── nids-dashboard.service   # systemd unit for the dashboard (runs as normal user)
│   └── nids-logrotate           # logrotate config — daily rotation, 30-day retention
│
├── scripts/
│   ├── gen_traffic.py           # 52 attacks + 10 scenarios + interactive mode
│   ├── test_capture.py          # Smoke test for sniffer + extractor on live traffic
│   └── replay_pcap.py           # Feed a .pcap through the detection engine offline
│
└── logs/
    └── nids.log                 # Gitignored. Append-only JSON lines.
```

---

## Technologies Used

| Technology | Version | Role |
|---|---|---|
| **Python** | 3.10+ | Core language. Uses structural pattern matching (`match/case`) for protocol dispatch in the packet extractor and condition evaluation in the signature engine. |
| **Scapy** | ≥ 2.5 | Packet capture and parsing. `sniff()` with BPF filter `"ip"`; parsing of Ether/IP/TCP/UDP/ICMP layers. Requires root privileges for live capture. |
| **Flask** | ≥ 3.0 | Web microframework for the dashboard REST API and HTML delivery. Two apps: `dashboard/app.py` (live, port 5000) and `dashboard/pcap_app.py` (offline PCAP analysis, port 5001). |
| **React 18** | CDN | Client-side UI framework for the live dashboard (`index.html`). Loaded from CDN; transpiled in-browser via Babel Standalone. All component state is local — no server-side session needed. |
| **Chart.js** | 4.4 | Data visualisation library (CDN). Used for the timeline line chart, severity doughnut, horizontal bar charts (top IPs, top rules, top ports), and stacked timeline in the PCAP analysis view. |
| **smtplib** | stdlib | Standard library SMTP client. Used by the notifier for email delivery. Maintains a persistent connection and reconnects automatically on stale-socket failures. |
| **urllib.request** | stdlib | Standard library HTTP client. Used by the notifier to POST alerts to a Slack incoming webhook URL. |
| **threading** | stdlib | Standard library OS-level threads. Thread 1: sniffer. Thread 2: analysis loop. Thread 3: notifier daemon. |
| **queue.Queue** | stdlib | Standard library thread-safe FIFO queue. Decouples sniffer from analysis. Bounded at 10,000 packets; drops on overflow to prevent unbounded memory growth. |
| **json** | stdlib | All alerts persisted as JSON lines (ndjson) in `nids.log`. Also used by the dashboard API responses. |
| **signal** | stdlib | Catches `SIGHUP` (sent by logrotate) to reopen `nids.log` after rotation without restarting the process. |
| **collections** | stdlib | `defaultdict`, `deque`. Sliding-window state for rate and multi_destination rules stored as deques keyed by `(src_ip, rule_name)`. |
| **typing** | stdlib | `TypedDict`, `Literal`, `NotRequired`. All inter-module data structures (`FeatureDict`, `Alert`, `CorrelatedAlert`, Rule subtypes) are fully typed. |

---

## Threading Model

The main process runs three threads:

| Thread | Module | Responsibility |
|--------|--------|----------------|
| T1 | `capture/sniffer.py` | Scapy `sniff()` loop. Enqueues raw packets. No processing. |
| T2 | `main.py` analysis loop | Dequeues, extracts, detects, correlates, deduplicates, logs. |
| T3 | `alerting/notifier.py` | Daemon thread — drains notification queue, sends email/Slack. |

The **dashboard** runs as a completely separate process (not a thread):

```bash
python -m dashboard.app     # independent process, no root needed
```

All threads in the main process are daemon threads — they die automatically when the main process exits. `main.py` catches `SIGINT` (Ctrl+C), signals the sniffer to stop, then **drains** remaining packets before closing the log file so no buffered data is lost.

**Why single-threaded analysis (T2)?**
Making the analysis loop multi-threaded would require locking the rate detector's sliding-window state and the deduplicator's cooldown dict. For < 100 Mbps, a single analysis thread is fast enough — rule matching is CPU-cheap and the real bottleneck is packet I/O on T1.

---

## The Queue — The System's Pressure Valve

`capture/queue_manager.py` wraps Python's `queue.Queue` with `maxsize=10_000`.

When T1 (sniffer) is faster than T2 (analysis):
- The queue fills up
- New packets are dropped (`put_nowait` — never blocks the sniffer)
- Memory usage stays bounded — never exceeds ~10,000 raw packet objects

At ~500 bytes average packet size, 10,000 packets ≈ 5 MB — small enough to be safe, large enough to absorb short bursts. `maxsize` is configurable in `config.py`.

Monitor queue saturation:
```bash
nids --interface wlan0 --stats-interval 10
```
This prints queue depth, captured/dropped counts, drop rate, alerts logged, and suppressed counts every 10 seconds. Sustained drops mean the hardware cannot keep up with traffic volume.

---

## Packet Capture — `capture/sniffer.py`

Uses Scapy's `sniff()` with a BPF filter `"ip"` — only IPv4 packets reach Python, reducing userspace overhead. The capture callback does exactly one thing:

```python
def _packet_callback(pkt):
    pkt_queue.put_nowait(pkt)   # drop silently if full
```

No processing happens in the callback. Root privileges are required for raw socket access on Linux.

Key behaviors:
- BPF filter `"ip"` applied at the kernel level — non-IP traffic never reaches Python
- Drop rate tracked in real time: `drop_count / enqueue_count × 100%`
- Graceful shutdown: `Ctrl+C` sets a `stop_event`, the sniffer thread exits, and the analysis loop drains remaining packets before closing the log file

---

## Packet Parsing — `parser/extractor.py`

Converts a raw Scapy `Packet` into a plain `FeatureDict`. After this point **Scapy objects are discarded** — no downstream module imports Scapy. This keeps rule logic framework-independent and safe to share across threads. Raises `ValueError` for non-IP packets that bypass the BPF filter; these are silently discarded upstream.

### FeatureDict — Always Complete

```python
{
    "timestamp":  float,        # time.time() — captured timestamp
    "src_ip":     str,          # e.g. "192.168.1.5"
    "dst_ip":     str,
    "protocol":   int,          # IP proto: 6=TCP, 17=UDP, 1=ICMP
    "length":     int,          # IP-declared total length (bytes)
    "ttl":        int,
    "src_port":   int | None,   # None if not TCP/UDP
    "dst_port":   int | None,
    "flags":      str | None,   # "S", "SA", "PA", "FPU", etc. None if not TCP
    "flags_int":  int,          # TCP flags as bitmask, 0 if not TCP
    "icmp_type":  int | None,   # None if not ICMP
}
```

**No key is ever absent.** This is a hard contract — rule conditions can always safely reference any field without a `KeyError`.

Protocol dispatch uses Python 3.10+ `match/case`:
```python
match protocol:
    case 6:   # TCP — extract ports, flags, flags_int
    case 17:  # UDP — extract ports
    case 1:   # ICMP — extract icmp_type
    case _:   # transport fields stay at defaults (None / 0)
```

---

## Detection Engine

### Rule Types — `detection/signatures.py`

Rules are plain Python dicts — data, not code. All 74 rules live in `signatures.py` only; no rule logic leaks into `sig_detector.py`. This means adding a new rule requires only editing the data file, not the engine.

**Pattern Rule** — fires on a single packet that satisfies all conditions. Stateless — no per-IP memory required:

```python
{
    "name":       "Null Scan",
    "type":       "pattern",
    "severity":   "HIGH",
    "mitre":      "T1046",
    "conditions": {
        "protocol":  6,
        "flags_int": 0,     # TCP packet with zero flags — never valid per RFC 793
    }
}
```

**Rate Rule** — fires when a source IP sends ≥ threshold matching packets within a time window:

```python
{
    "name":           "SSH Brute Force",
    "type":           "rate",
    "severity":       "CRITICAL",
    "mitre":          "T1110.001",
    "conditions":     {"protocol": 6, "dst_port": 22, "flags": "S"},
    "threshold":      10,
    "window_seconds": 60,
}
```

**Multi-Destination Rule** — fires when a source IP reaches ≥ threshold *unique* values of a tracked field (`dst_port` or `dst_ip`) within a window. More accurate than raw packet counts for scan detection: a client opening 50 connections to one port scores 1, not 50:

```python
{
    "name":           "Port Scan (Distinct Ports)",
    "type":           "multi_destination",
    "severity":       "HIGH",
    "mitre":          "T1046",
    "conditions":     {"protocol": 6, "flags": "S"},
    "track":          "dst_port",
    "threshold":      25,
    "window_seconds": 30,
}
```

### Condition Matching — `detection/sig_detector.py`

Each condition field supports five matching forms:

| Form | Example | Meaning |
|------|---------|---------|
| Equality | `"protocol": 6` | exact match |
| Membership | `"dst_port": [80, 443]` | value in list |
| Comparison | `{">=": 1400}` | also `>`, `<`, `<=`, `!=` |
| Exclusion | `{"not_in": [22, 80]}` | value not in list |
| Bitmask | `{"mask": 0x02}` | all bits must be set |

Multiple operators in one dict are ANDed together.

Sliding-window state for rate and multi_destination rules is stored as `defaultdict(deque)` keyed by `(src_ip, rule_name)`. On each matching packet: append timestamp, prune entries older than `window_seconds`, check count/unique-count. Stale entries are evicted every 2 minutes from the main loop.

---

## Alert Correlation and Threat Scoring

### Per-Packet Correlation — `detection/correlator.py`

A single packet can match multiple rules simultaneously. The correlator resolves this into a single alert:

- The highest-severity rule becomes the "leader" of the alert
- All other fired rule names are attached as `also_triggered`
- The analyst sees the full picture in one log entry rather than fragmented events

### Cross-Packet Threat Tracking

The correlator maintains a 5-minute sliding window of distinct rules fired per source IP. A `threat_score` (0–100) is computed as `min(100, distinct_rules × 10)`.

Severity is automatically escalated based on multi-stage attack behaviour:

| Distinct rules (score) | Escalation |
|------------------------|------------|
| 3+ (score ≥ 30) | bump to at least MEDIUM |
| 5+ (score ≥ 50) | bump to at least HIGH |
| 8+ (score ≥ 80) | escalate to CRITICAL |

An IP that scans → brute-forces → contacts a C2 port will have its alerts escalated to CRITICAL automatically, even if each individual rule fires at MEDIUM.

### MITRE ATT&CK Mapping

Most rules carry a `mitre` field (e.g. `"T1046"` for network service scanning) for correlation with the ATT&CK framework.

---

## Alerting Pipeline

### `alerting/deduplicator.py` — Noise Reduction

Each `(rule, src_ip)` pair has an independent 30-second cooldown timer. Only the first alert in each window passes through; subsequent duplicates are counted but discarded. The `suppressed_count` is exposed on the `Deduplicator` instance for stats output. Expired entries are purged every 2 minutes to prevent memory growth.

### `alerting/logger.py` — The Only Disk Writer

Every non-duplicate alert is written as one JSON line to `logs/nids.log`. The file is line-buffered — each line is flushed immediately, so no alert is lost on a crash. Supports `SIGHUP` (sent by logrotate) to reopen the file after rotation without restarting the process.

### `alerting/notifier.py` — Active Notification

A dedicated daemon thread handles all outbound I/O so the analysis loop is never blocked by network latency.

Key behaviors:
- **Configurable threshold**: only notifies for alerts at `NOTIFY_MIN_SEVERITY` (default: HIGH) or above. LOW and MEDIUM are logged only.
- **Batching**: alerts arriving within a 3-second window are collapsed into a single email/Slack message, preventing alert storms during active attacks.
- **Bounded internal queue** (100 slots): when full, the oldest pending alert is evicted to make room for the newest. An analyst reading email hours later cares about the most recent events.
- **Email (SMTP/STARTTLS)**: persistent connection reused across sends, with one automatic reconnect on stale-socket failures.
- **Slack (incoming webhook)**: severity-appropriate emoji, multi-alert batches sent as one message.
- All credentials loaded from environment only — never hardcoded.

---

## Dashboard

Two Flask applications serve the dashboard, both importable from the project root.

### Live Dashboard — `dashboard/app.py`

Runs as a **separate process** that reads `nids.log` directly — it imports nothing from the detection layer. A bug in the dashboard cannot affect packet capture or detection.

Tail-first log reading: seeks from the end of the file so large logs do not cause memory spikes.

```bash
python -m dashboard.app
# open http://localhost:5000  (no root required)
```

#### REST API

| Endpoint | Description |
|----------|-------------|
| `GET /` | Serves the dashboard UI (`index.html`) |
| `GET /api/alerts` | Last N alerts, newest first. Query params: `?limit`, `?severity`, `?ip`, `?rule`, `?since` |
| `GET /api/stats` | Aggregates: total, today, by_severity, top 10 source IPs, top 10 rules |
| `GET /api/health` | Active interface, log file size, `rules_active` count |
| `GET /api/rules` | Full rule list with name, severity, type, category, MITRE ATT&CK ID |
| `GET /api/ip/<ip>` | Per-IP investigation: risk score (0–100), first/last seen, breakdown by severity and rule, 20 most recent events |
| `GET /api/capture_status` | Whether the capture engine is running, its PID, uptime, and interface |
| `POST /api/capture_start` | Spawn `main.py` as a subprocess (body: `{"interface": "wlan0"}`) |
| `POST /api/capture_stop` | Send SIGTERM to the running capture subprocess |
| `GET /api/allowlist` | List all allowlisted IPs and subnets |
| `POST /api/allowlist/add` | Add an IP or CIDR subnet (body: `{"entry": "10.0.0.0/8"}`) |
| `POST /api/allowlist/remove` | Remove an entry |
| `POST /pcap/upload` | Upload a .pcap file for offline analysis |
| `GET /pcap/api/status` | PCAP analysis job status: `idle`, `running`, `done`, `error` |
| `GET /pcap/api/data` | Full analysis results (alerts, aggregates, timeline) |
| `GET /pcap/api/ip/<ip>` | Per-IP investigation within the loaded PCAP |
| `POST /pcap/reset` | Clear the current PCAP analysis result |

Risk score formula (per IP):
```
score = min(100, CRITICAL_count × 20 + HIGH_count × 8 + min(total_alerts × 2, 40))
```

#### Frontend — 7 Views

The UI (`index.html`) is a single-page React app with a collapsible sidebar (state persists across sessions), dark/light theme toggle, and keyboard shortcuts.

| View | Key | Description |
|------|-----|-------------|
| Dashboard | `1` | Stat cards (total, crit, high, top attacker, packet rate), threat posture banner (NORMAL / ELEVATED / HIGH / CRITICAL), alerts-over-time line chart, severity donut, live alert table, top attackers sidebar. Demo Mode banner shown when no live backend is detected. |
| Alert Feed | `2` | Full filterable table: severity, category, source IP, rule. Expandable rows with all alert fields + MITRE ID. Pause/resume live feed; CSV export of filtered view. Per-row Investigate, Block IP, Copy IP actions. |
| Attack Map | `3` | SVG world map — dots sized by alert volume, colored by severity. Hover tooltip shows IP, country, alert count. Click any dot to open the investigation drawer. |
| Rules | `4` | All 74 signatures grouped by category. Hit counter and severity badge per rule. MITRE ATT&CK ID badges; rule type indicator. |
| Analytics | `5` | Category breakdown cards with percentage bars. Top source IPs / target ports / rules (bar charts). MITRE technique frequency heatmap. |
| Allowlist | `6` | Add/remove trusted IPs and CIDR subnets. Changes reflected in the detection engine within ~2 minutes. |
| PCAP Analysis | `7` | Drag-and-drop .pcap upload; runs all 74 signatures offline. Overview / Alerts / Attackers / Timeline tabs. Per-IP investigation panel; CSV export. |

Additional UI features:
- **Collapsible sidebar** — click the `‹/›` chevron to collapse to a 52px icon rail; saves horizontal space on smaller screens
- **Capture engine control** — start/stop `main.py` from the sidebar without touching the terminal
- **IP investigation drawer** — click any source IP to open a side panel with risk score, first/last seen, top rules, MITRE techniques, and recent events
- **Toast notifications** — pop-up alerts for CRITICAL/HIGH events (configurable to CRITICAL-only)
- **Demo mode banner** — shown when no live backend is detected; displays simulated traffic so the UI is fully explorable without running the engine
- **Keyboard shortcuts** — `P` pause, `E` export CSV, `C` clear filters, `T` toggle theme, `/` focus rule search, `?` show all shortcuts
- **Tweaks panel** — runtime controls for refresh interval, max table rows, compact mode, toast filter

### Standalone PCAP Dashboard — `dashboard/pcap_app.py`

An independent Flask app for offline analysis without the live dashboard running. Accepts `.pcap`/`.pcapng`/`.cap` uploads up to 500 MB, runs the full detection pipeline offline, and returns aggregated results. Useful for analysing captures on a machine where the engine was never deployed.

```bash
python -m dashboard.pcap_app
# open http://localhost:5001
```

Also supports a CLI mode for scripted use:

```bash
python dashboard/pcap_app.py --file alerts.json --pcap capture.pcap
```

Or via the shell wrapper:

```bash
./nids --offline capture.pcap
```

---

## Scripts

### `scripts/gen_traffic.py` — Traffic Generator
Crafts and sends real packets that trigger NIDS signatures. 52 individual attacks covering all 74 rules, plus 10 pre-built multi-step scenarios. **Root required.**

```bash
# Browse everything available
sudo python scripts/gen_traffic.py --list
sudo python scripts/gen_traffic.py --scenarios

# Single attack
sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_scan
sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack brute_force --port 22
sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_flood --count 250

# Multi-step scenario (runs a full attack chain with pauses between stages)
sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario apt_campaign
sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario ransomware
sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario full_demo

# Interactive menu — pick attacks or scenarios by name/number
sudo python scripts/gen_traffic.py --target 192.168.1.5 --interactive

# Options: --iface to specify interface, --delay MS for inter-packet pacing
sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack dns_tunnel --delay 50
```

Available scenarios: `apt_campaign`, `ransomware`, `ddos_wave`, `reflection_ddos`, `insider_threat`, `red_team_recon`, `exposed_databases`, `ics_attack`, `infra_attack`, `full_demo`.

### `scripts/test_capture.py` — Capture Smoke Test
Verifies that the sniffer and extractor work correctly on real traffic. Run it while generating some background network activity.

```bash
sudo .venv/bin/python scripts/test_capture.py
```

### `scripts/replay_pcap.py` — PCAP Replay
Feeds a saved `.pcap` or `.pcapng` file through the full detection pipeline offline. No root required, no live interface, no notifications sent.

```bash
python scripts/replay_pcap.py --file capture.pcap
python scripts/replay_pcap.py --file capture.pcap --output alerts.json
python scripts/replay_pcap.py --file capture.pcap --quiet
```

Packet timestamps from the original capture are preserved and used for rate-window analysis, so rules fire at the same times they would have in real traffic. The final report shows severity breakdown, category breakdown, top rules, top attacking IPs with threat scores, and all CRITICAL/HIGH alert details.

---

## Signature Rule Coverage

**Total rules: 74 | Rule IDs: R001–R074**
Rule types: `pattern`, `rate`, `multi_destination`
Severities: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

Rules are deliberately conservative — thresholds and rule types were tuned to minimise false positives on real home/office network traffic. See the [False Positive Reduction](#false-positive-reduction) section for details.

### Reconnaissance (16 rules — R001–R016)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R001 | Port Scan (SYN) | rate | HIGH | T1046 | 100 SYN/10s |
| R002 | Port Scan (Distinct Ports) | multi_dest | HIGH | T1046 | 25 unique ports/30s |
| R003 | Host Discovery Sweep (Distinct IPs) | multi_dest | HIGH | T1018 | 20 unique IPs/30s |
| R004 | Null Scan | pattern | HIGH | T1046 | — |
| R005 | XMAS Scan | pattern | HIGH | T1046 | — |
| R006 | FIN Scan | pattern | MEDIUM | T1046 | — |
| R007 | Maimon Scan | multi_dest | MEDIUM | T1046 | 20 unique FA ports/30s |
| R008 | ACK Scan | multi_dest | MEDIUM | T1046 | 30 unique ACK ports/30s |
| R009 | ICMP Host Sweep (Ping Sweep) | rate | MEDIUM | T1018 | 20 pings/10s |
| R010 | UDP Port Scan | rate | MEDIUM | T1046 | 500 UDP/10s |
| R011 | Invalid TCP Flags: SYN+RST | pattern | MEDIUM | T1046 | — |
| R012 | Invalid TCP Flags: SYN+FIN | pattern | MEDIUM | T1046 | — |
| R013 | Oversized ICMP Packet (>1,000 B) | pattern | MEDIUM | T1498.001 | — |
| R014 | Low TTL Probe (≤4, Traceroute/Evasion) | pattern | LOW | T1040 | — |
| R015 | ICMP Redirect (Routing Manipulation) | pattern | HIGH | T1565 | — |
| R016 | TCP SYN with Large Payload (>80 B) | pattern | MEDIUM | T1499.002 | — |

### Brute Force (12 rules — R017–R028)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R017 | SSH Brute Force | rate | CRITICAL | T1110.001 | 10 SYN/60s |
| R018 | RDP Brute Force | rate | CRITICAL | T1110.001 | 10 SYN/60s |
| R019 | FTP Brute Force | rate | HIGH | T1110.001 | 10 SYN/60s |
| R020 | Telnet Brute Force | rate | HIGH | T1110.001 | 5 SYN/30s |
| R021 | SMTP Auth Brute Force | rate | HIGH | T1110.003 | 10 SYN/60s |
| R022 | IMAP Brute Force | rate | HIGH | T1110.001 | 10 SYN/60s |
| R023 | POP3 Brute Force | rate | HIGH | T1110.001 | 10 SYN/60s |
| R024 | VNC Brute Force | rate | CRITICAL | T1110.001 | 10 SYN/60s |
| R025 | MySQL Brute Force | rate | CRITICAL | T1110.001 | 5 SYN/30s |
| R026 | PostgreSQL Brute Force | rate | CRITICAL | T1110.001 | 5 SYN/30s |
| R027 | MSSQL Brute Force | rate | CRITICAL | T1110.001 | 5 SYN/30s |
| R028 | Kerberos Brute Force (AS-REP/Spray) | rate | CRITICAL | T1558.003 | 20/30s |

### Denial of Service (5 rules — R029–R033)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R029 | SYN Flood | rate | CRITICAL | T1498.001 | 200 SYN/5s |
| R030 | ICMP Flood | rate | HIGH | T1498.001 | 100 pings/10s |
| R031 | UDP Flood | rate | HIGH | T1498.001 | 1000 UDP/10s |
| R032 | RST Flood | rate | HIGH | T1499 | 100 RST/10s |
| R033 | ACK Flood | rate | HIGH | T1498.001 | 500 ACK/10s |

### Suspicious Services (4 rules — R034–R037)

| ID | Name | Type | Severity | MITRE | Notes |
|----|------|------|----------|-------|-------|
| R034 | Telnet Attempt | pattern | MEDIUM | T1078 | SYN-only |
| R035 | rlogin / rsh Attempt | pattern | HIGH | T1021 | — |
| R036 | TFTP Access | pattern | MEDIUM | T1105 | — |
| R037 | LLMNR Traffic (Possible MITM) | pattern | LOW | T1557.001 | — |

### Malware & C2 (8 rules — R038–R045)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R038 | Known C2 / Backdoor Port | pattern | CRITICAL | T1571 | — |
| R039 | Possible Reverse Shell (High Port) | multi_dest | HIGH | T1059 | 5 unique ports >60000/60s |
| R040 | IRC Traffic (Possible Botnet C2) | pattern | MEDIUM | T1571 | — |
| R041 | Tor Default Port | pattern | MEDIUM | T1090.003 | — |
| R042 | DNS over Non-Standard Port | pattern | MEDIUM | T1071.004 | — |
| R043 | Cobalt Strike Default Beacon Port | pattern | CRITICAL | T1105 | — |
| R044 | Netcat / Bind Shell Default Port | pattern | HIGH | T1059 | — |
| R045 | Aggressive Outbound SYN Rate (Worm) | rate | MEDIUM | T1595 | 300 SYN/60s |

### Lateral Movement (2 rules — R046–R047)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R046 | SMB Sweep (Ransomware Propagation) | rate | CRITICAL | T1570 | 10 SYN/10s |
| R047 | WinRM Access (Possible Lateral Move) | pattern | MEDIUM | T1021.006 | — |

### Exposed Services (9 rules — R048–R056)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R048 | Redis Exposed (No Auth) | rate | CRITICAL | T1190 | 3 SYN/60s |
| R049 | Elasticsearch Exposed | rate | CRITICAL | T1190 | 3 SYN/60s |
| R050 | MongoDB Exposed | rate | CRITICAL | T1190 | 3 SYN/60s |
| R051 | Docker API Exposed | rate | CRITICAL | T1610 | 3 SYN/60s |
| R052 | Kubernetes API Exposed | rate | CRITICAL | T1610 | 3 SYN/60s |
| R053 | etcd Exposed | rate | CRITICAL | T1552.007 | 3 SYN/60s |
| R054 | Memcached Exposed (DDoS Amplification) | rate | HIGH | T1498.002 | 3 UDP/60s |
| R055 | CouchDB Exposed | rate | HIGH | T1190 | 3 SYN/60s |
| R056 | Hadoop / HDFS Exposed | rate | HIGH | T1190 | 3 SYN/60s |

### Exfiltration (4 rules — R057–R060)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R057 | DNS Query Flood UDP (DNS Tunneling) | rate | HIGH | T1048.001 | 200 UDP/60s |
| R058 | DNS Query Flood TCP (DNS Tunneling) | rate | MEDIUM | T1048.001 | 100 TCP/60s |
| R059 | ICMP Exfiltration (Large Volume) | rate | MEDIUM | T1048.003 | 50 pings/60s |
| R060 | FTP Data Channel (Possible Exfil) | pattern | LOW | T1048 | — |

### Network Infrastructure Attacks (7 rules — R061–R067)

| ID | Name | Type | Severity | MITRE | Threshold |
|----|------|------|----------|-------|-----------|
| R061 | DNS Amplification Attack | rate | CRITICAL | T1498.002 | 500 src:53 UDP/10s |
| R062 | NTP Amplification Attack | rate | CRITICAL | T1498.002 | 200 src:123 UDP/10s |
| R063 | BGP Connection Attempt | pattern | HIGH | T1557 | — |
| R064 | OSPF Injection | pattern | HIGH | T1565 | — |
| R065 | EIGRP Traffic | pattern | HIGH | T1565 | — |
| R066 | GRE Tunnel Traffic | pattern | MEDIUM | T1572 | — |
| R067 | IPv6-in-IPv4 Tunnel | pattern | MEDIUM | T1572 | — |

### ICS / SCADA (4 rules — R068–R071)

| ID | Name | Type | Severity | MITRE | Notes |
|----|------|------|----------|-------|-------|
| R068 | Modbus Access (ICS Protocol) | pattern | HIGH | T0855 | — |
| R069 | DNP3 Access (ICS Protocol) | pattern | HIGH | T0855 | — |
| R070 | EtherNet/IP Access (ICS Protocol) | pattern | HIGH | T0855 | — |
| R071 | BACnet Access (Building Automation) | pattern | MEDIUM | T0855 | — |

### Policy Violations (3 rules — R072–R074)

| ID | Name | Type | Severity | MITRE | Notes |
|----|------|------|----------|-------|-------|
| R072 | Proxy / Anonymizer Port | pattern | LOW | T1090 | — |
| R073 | P2P / BitTorrent Port | pattern | LOW | T1048 | — |
| R074 | Cryptocurrency Mining Pool | pattern | HIGH | T1496 | — |

---

## False Positive Reduction

The original ruleset had 83 rules. During testing, three systematic problems were identified and fixed, reducing the ruleset to 74 rules with near-zero false positives on typical home/office traffic.

### Problem 1 — Own IP Appearing as "Top Attacker"

**Cause:** Outbound packets from the sensor machine have `src_ip = local IP`. Rate rules accumulated hits against the local IP, escalating its `threat_score` to CRITICAL, causing the sensor itself to appear as the top attacker.

**Fix:** `main.py` now auto-detects the interface IP via Scapy's `get_if_addr()` and skips any packet whose `src_ip` is in `{local_ip, 127.0.0.1, ::1}`.

### Problem 2 — False Alerts During nmap Scans

**Cause:** All 9 Exposed Services rules were `pattern` type — one SYN to port 6443 fired "Kubernetes API Exposed". Because nmap probes sequential ports, 9 distinct rules fired on the same source IP, the correlator escalated the threat score, and an unrelated CRITICAL alert appeared.

**Fix:** All Exposed Services rules (R048–R056) converted from `pattern` → `rate` with `threshold=3`, `window=60s`. nmap sends exactly 1 SYN per port and never reaches 3, so no alert fires.

### Problem 3 — Noisy Pattern Rules

Nine rules were removed because they fired on normal background traffic:

| Removed Rule | Reason |
|---|---|
| SMB Access | Every Windows file share mount triggered it |
| DCOM / RPC Access | Fires on every Windows background event |
| NetBIOS Name Service | Fires on every Windows name resolution |
| LDAP Enumeration | Constant in Active Directory environments |
| SNMP Access | Every network monitoring tool poll |
| NFS Access | Every NAS mount operation |
| SSDP / UPnP Discovery | Constant background traffic on home LANs |
| FTP Cleartext Login | Every FTP packet; brute force covered by R019 |
| Log4Shell Port (8080/8443) | Ports too common; single-port detection useless |

Three rules were additionally converted from `pattern`/`rate` to `multi_destination` to eliminate false positives from clients with many legitimate connections — the key insight being that scanners probe many different ports while legitimate connections reuse the same small port set:

| Rule | Before | After |
|---|---|---|
| R007 Maimon Scan | 20 FA packets | 20 unique FIN+ACK destination ports / 30s |
| R008 ACK Scan | 30 ACK packets | 30 unique ACK destination ports / 30s |
| R039 Reverse Shell | Single SYN | 5 unique destination ports >60000 / 60s |

Other threshold/condition fixes:
- **Port Scan (SYN)**: raised `30/5s → 100/10s` (a browser opening 30 tabs was triggering the old threshold)
- **Telnet Attempt**: added `flags="S"` (SYN only) to suppress established session packet noise
- **C2 port list**: removed port 8888 (common Jupyter port) and port 9000 (used by Portainer, SonarQube, PHP-FPM)

---

## Configuration — `config.py`

Every tuneable value lives here. No magic numbers scattered across the codebase.

| Setting | Default | Purpose |
|---------|---------|---------|
| `INTERFACE` | `"wlan0"` | Network interface (overridden by `--interface`) |
| `QUEUE_MAXSIZE` | `10_000` | Max buffered packets before drops |
| `LOG_PATH` | `"logs/nids.log"` | Alert log file |
| `ALERT_COOLDOWN_SEC` | `30` | Dedup window per `(rule, src_ip)` |
| `NOTIFY_MIN_SEVERITY` | `"HIGH"` | Minimum severity for email/Slack |
| `SEVERITY_RANK` | `LOW=0 … CRITICAL=3` | Ordered rank used by correlator and notifier |
| `SMTP_HOST/PORT/USER/PASS` | from env | Email credentials |
| `SLACK_WEBHOOK` | from env | Slack incoming webhook URL |
| `ALERT_EMAIL` | from env | Destination address for alert emails |

Credentials are always loaded from environment variables. Set them in the system environment or via `EnvironmentFile=` in the systemd unit.

---

## Alert Schema

Every line in `logs/nids.log` is a JSON object. Full schema:

```json
{
  "timestamp":      "2026-04-26T14:32:01.123Z",
  "id":             "R001",
  "rule":           "Port Scan (SYN)",
  "severity":       "HIGH",
  "src_ip":         "10.0.0.5",
  "dst_ip":         "10.0.0.1",
  "dst_port":       22,
  "protocol":       "TCP",
  "correlated":     true,
  "also_triggered": ["Host Discovery Sweep (Distinct IPs)"],
  "threat_score":   30,
  "count":          31
}
```

Field notes:
- `id` — rule identifier R001–R074, matching the numbering in `signatures.py`; always present
- `count` — only present on `rate` and `multi_destination` rule alerts; value is the packet/unique-destination count within the window
- `correlated` — `true` when more than one rule fired on this packet
- `also_triggered` — names of every other rule that fired alongside the leader
- `threat_score` — 0–100; reflects how many distinct rules this source IP has triggered in the last 5 minutes
- `protocol` — human-readable: `"TCP"`, `"UDP"`, `"ICMP"`, or a numeric string for other IP protocols

---

## Commands

```bash
# Install dependencies
bash setup.sh

# Live capture on wlan0 — starts dashboard automatically (root required for capture)
./nids --interface wlan0
./nids --interface wlan0 --stats-interval 10

# Verify sniffer + extractor on real traffic (root required)
sudo .venv/bin/python scripts/test_capture.py

# Generate test traffic to validate signatures (root required)
sudo python scripts/gen_traffic.py --list                                          # list all 52 attacks
sudo python scripts/gen_traffic.py --scenarios                                     # list all 10 scenarios
sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_scan
sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack brute_force --port 22
sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario apt_campaign
sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario full_demo
sudo python scripts/gen_traffic.py --target 192.168.1.5 --interactive

# Analyze a saved .pcap file offline (no root needed)
python scripts/replay_pcap.py --file capture.pcap
python scripts/replay_pcap.py --file capture.pcap --output alerts.json --quiet

# Launch the live dashboard (no root needed)
python -m dashboard.app                        # http://localhost:5000

# Launch the standalone PCAP analysis dashboard (no root needed)
python -m dashboard.pcap_app                   # http://localhost:5001
```

---

## Completed Components

- [x] `config.py`
- [x] `allowlist.py` / `allowlist.json` — IP/CIDR suppress list, hot-reload every 2 min
- [x] `capture/sniffer.py`
- [x] `capture/queue_manager.py`
- [x] `parser/extractor.py`
- [x] `detection/signatures.py` — 74 rules (R001–R074), false-positive refactored
- [x] `detection/sig_detector.py` — pattern + rate + multi_destination + rule IDs
- [x] `detection/correlator.py` — per-packet and cross-packet correlation
- [x] `detection/categories.py` — single source of truth for `RULE_CATEGORY` + `SEV_ORDER`
- [x] `alerting/deduplicator.py`
- [x] `alerting/logger.py`
- [x] `alerting/notifier.py` — batched email + Slack, daemon thread
- [x] `main.py` — threading, local-IP exclusion, graceful shutdown
- [x] `nids` (shell script) — starts dashboard + capture engine together
- [x] `scripts/gen_traffic.py` — 52 attacks + 10 scenarios + interactive mode
- [x] `scripts/replay_pcap.py` — offline pcap analysis with full threat report
- [x] `requirements.txt`
- [x] `setup.sh`
- [x] `.gitignore` — excludes `logs/`, `.venv/`
- [x] `dashboard/app.py` — Flask backend, 15 REST endpoints, capture control
- [x] `dashboard/pcap_app.py` — standalone offline PCAP analysis server (port 5001)
- [x] `dashboard/templates/index.html` — live dashboard: 7 views, collapsible sidebar, dark/light theme, investigation drawer, attack map, PCAP tab, toast notifications, keyboard shortcuts
- [x] `dashboard/templates/pcap_dashboard.html` — standalone PCAP analysis UI
- [x] `dashboard/static/nids-ui.jsx` — UI primitives: badges, toasts, investigate drawer
- [x] `dashboard/static/nids-charts.jsx` — Chart.js wrappers + SVG world map
- [x] `dashboard/static/nids-data.js` — demo data, rule list, geo coordinates
- [x] `dashboard/static/tweaks-panel.jsx` — settings panel component
- [x] `deploy/nids.service` — systemd unit for capture engine
- [x] `deploy/nids-dashboard.service` — systemd unit for web dashboard
- [x] `deploy/nids-logrotate` — logrotate config, daily rotation, 30-day retention

---

## Deployment (Production)

The `deploy/` directory contains ready-to-use systemd units and a logrotate config.

```bash
# Copy files to their system locations
sudo cp /opt/nids/deploy/nids.service          /etc/systemd/system/nids.service
sudo cp /opt/nids/deploy/nids-dashboard.service /etc/systemd/system/nids-dashboard.service
sudo cp /opt/nids/deploy/nids-logrotate        /etc/logrotate.d/nids

# Enable and start both services
sudo systemctl daemon-reload
sudo systemctl enable --now nids nids-dashboard

# Monitor
journalctl -u nids -f
journalctl -u nids-dashboard -f
```

Edit `deploy/nids.service` to set the correct `--interface` before deploying. The `nids.service` unit runs as root (required for raw socket access) and restarts automatically on failure. The `nids-dashboard.service` unit runs as a normal user and includes `ExecReload` for graceful config reload. The logrotate config rotates `logs/nids.log` daily (30-day retention) and sends `SIGHUP` after rotation so the logger reopens the new file without a process restart.

---

## Known Limitations

- **IPv4 only.** The BPF filter `"ip"` excludes IPv6. An attacker on a dual-stack network can evade detection by using IPv6.
- **Single interface.** One sniffer thread per process. Multi-homed hosts need multiple instances.
- **Rule-based only.** Novel attacks with no matching signature are invisible. Behavioral anomaly detection would be needed to close this gap.
- **Signature false positives.** Rate rules (e.g. Port Scan (SYN)) can fire on legitimate high-traffic clients. Thresholds are tuned conservatively but will need adjustment for busy environments.
- **No rule hot-reload.** Adding or editing signatures requires a process restart, making it impractical to respond to emerging threats without a brief monitoring gap.
- **Dashboard has no authentication.** Anyone with network access to port 5000 can read alert data. Running it on a loopback or behind a firewall is strongly advised.
- **No HTTPS.** Dashboard traffic is unencrypted on the wire.

---

## Future Improvements

**Near-term (operational gaps)**
- Notifier rate-limit — the notifier already batches alerts within a 3-second window, but a sustained multi-hour attack can still produce hundreds of batched emails; add a maximum notifications-per-hour cap so the analyst's inbox does not flood
- Dashboard authentication — HTTP Basic Auth or token-based authentication to the Flask app so alert data is not readable by anyone on the local network
- HTTPS for dashboard — self-signed cert or Nginx reverse proxy with Let's Encrypt

**Medium-term (capability improvements)**
- IPv6 support — change BPF filter to `"ip or ip6"` and extend `extractor.py` for IPv6 headers
- Multi-interface support — one sniffer thread per interface, all writing to the same bounded queue
- GeoIP enrichment — annotate alerts with country code and ASN from a local MaxMind GeoLite2 database; adds context to the dashboard without requiring an external API call per packet
- SIEM integration — write alerts to a syslog socket or in CEF (Common Event Format) alongside JSON lines; enables forwarding to Splunk, ELK, or any syslog-capable SIEM without post-processing
- Rule hot-reload — `SIGUSR1` handler that reloads `detection/signatures.py` at runtime without stopping packet capture

**Long-term (architectural additions)**
- Anomaly detection layer — complement the signature engine with a lightweight statistical baseline (e.g. exponential moving average of packet rate per source IP, or port entropy per time window) to surface novel attack patterns no rule currently covers
- Machine learning classifier — binary classifier (e.g. Random Forest or a small MLP) trained on labeled `FeatureDicts` to flag suspicious packets that bypass all signature rules
- Packet capture to PCAP — optionally write raw captured packets to a rolling PCAP file alongside the JSON alert log for full forensic replay of incidents after the fact
- Distributed mode — multiple sensor nodes each running the capture and detection pipeline, forwarding correlated alerts to a central aggregator and dashboard
- Custom rule editor in dashboard — define, test, and activate new signatures from the web UI without editing Python files
- MITRE ATT&CK coverage heatmap — generate a heatmap overlay on the ATT&CK Navigator matrix showing which techniques the current ruleset covers and which are blind spots

---

## Lessons Learned

### Effectiveness

Every attack scenario in `scripts/gen_traffic.py` was validated against the live detection engine. All 74 signatures fire as expected for their target traffic patterns. The false-positive reduction work brought the noise level on a typical home/office network to near-zero: no alerts fire during normal web browsing, file sharing, or background OS traffic.

The threat correlation system proved particularly effective in multi-stage attack scenarios. A simulated APT campaign — reconnaissance → SSH brute force → C2 beacon — automatically escalated to CRITICAL within the 5-minute correlation window, even though the individual rules for reconnaissance and C2 fire at HIGH and MEDIUM respectively. This is the key advantage of cross-packet threat scoring over alert-by-alert analysis.

Offline PCAP analysis (`replay_pcap.py` and `pcap_app.py`) allows retrospective investigation of captured traffic without a live deployment, useful for incident response and forensic analysis of pre-captured network data.

### Key Engineering Insights

1. **Rule type matters as much as rule content.** Converting Exposed Services rules from `pattern` to `rate` eliminated an entire class of false positives with no loss of true positive coverage. The right detection primitive — stateless pattern, rate window, or unique-count — is the most important design decision for each rule.

2. **Cross-packet correlation multiplies the value of individual rules.** A single SSH SYN packet is noise. Ten in sixty seconds is brute force. Ten combined with a prior port scan and a subsequent C2 connection is an active intrusion. The correlation layer translates isolated rule firings into a coherent attack narrative.

3. **The sensor machine itself is a source of noise.** Excluding the local IP from analysis is not obvious but is essential — without it, the sensor's own outbound connections contaminate the top-attacker rankings.

4. **Architectural separation protects the detection layer.** Running the dashboard as a completely isolated process that reads only a log file means the UI — which is the most likely attack surface — cannot affect the detection pipeline. This is a pattern worth applying to any monitoring system.
