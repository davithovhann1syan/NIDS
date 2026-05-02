# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System using Scapy for packet capture, a three-type signature engine (pattern, rate, multi-destination) with cross-packet threat correlation, structured JSON logging, batched email/Slack notifications, and a live Flask web dashboard. 74 rules across 11 threat categories. Designed for low-to-medium traffic internal network segments (< 100 Mbps).

---

## Table of Contents

- [What Problem It Solves](#what-problem-it-solves)
- [Architecture Philosophy](#architecture-philosophy)
- [Project Structure](#project-structure)
- [Threading Model](#threading-model)
- [The Queue — The System's Pressure Valve](#the-queue--the-systems-pressure-valve)
- [Packet Capture](#packet-capture----capturesniferpy)
- [Packet Parsing](#packet-parsing----parserextractorpy)
- [Detection Engine](#detection-engine)
- [Alerting Pipeline](#alerting-pipeline)
- [Dashboard](#dashboard----dashboardapppy)
- [Scripts](#scripts)
- [Configuration](#configuration----configpy)
- [Alert Schema](#alert-schema)
- [Commands](#commands)
- [Deployment](#deployment-production)
- [Known Limitations](#known-limitations)
- [Future Improvements](#future-improvements)

---

## What Problem It Solves

A NIDS sits on a network and watches traffic in real time. When it sees something suspicious — a port scan, a connection to a known malware port, an ICMP flood — it logs an alert and optionally notifies you via email or Slack. It does **not** block traffic (that would be an IPS). It only observes and reports.

This implementation targets **internal network segments under ~100 Mbps** — home labs, small office LANs, server subnets. It is not designed for internet edge traffic at gigabit speeds.

---

## Architecture Philosophy

**1. Strict one-way data flow**
No module downstream ever reaches back upstream. The dashboard does not touch the detector. The detector does not touch the logger. This prevents circular dependencies and makes each stage independently testable.

**2. Single responsibility per module**
Each file does exactly one thing. `sniffer.py` only captures. `extractor.py` only parses. `logger.py` is the only thing that writes to disk.

**3. Fail safely under load**
If the system cannot keep up with traffic, packets are **dropped at the queue boundary** rather than consuming unbounded memory. It is better to miss some packets than to crash.

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
├── .env.example                 # Documented template of all environment variables
├── .gitignore                   # Excludes: logs/, .env, .venv/
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

---

## Packet Parsing — `parser/extractor.py`

Converts a raw Scapy `Packet` into a plain `FeatureDict`. After this point **Scapy objects are discarded** — no downstream module imports Scapy. This keeps rule logic framework-independent and safe to share across threads.

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

Rules are plain Python dicts — data, not code. All 74 rules live in `signatures.py` only; no rule logic leaks into `sig_detector.py`.

**Pattern Rule** — fires on a single packet that satisfies all conditions:

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
    "severity":       "HIGH",
    "mitre":          "T1110",
    "conditions":     {"protocol": 6, "dst_port": 22, "flags": "S"},
    "threshold":      10,
    "window_seconds": 10,
}
```

**Multi-Destination Rule** — fires when a source IP reaches ≥ threshold *unique* values of a tracked field (dst_port or dst_ip) within a window. More accurate than raw packet counts for scan detection: a client opening 50 connections to one port scores 1, not 50.

```python
{
    "name":           "Port Scan (Distinct Ports)",
    "type":           "multi_destination",
    "severity":       "HIGH",
    "mitre":          "T1046",
    "conditions":     {"protocol": 6, "flags": "S"},
    "track":          "dst_port",
    "threshold":      20,
    "window_seconds": 10,
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

### Alert Correlation — `detection/correlator.py`

**Per-packet correlation:**
A single packet can match multiple rules. The correlator takes all alerts for one packet, selects the highest-severity alert as the leader, and attaches all other fired rule names as `also_triggered`. The analyst sees the full picture in a single log entry.

**Cross-packet threat tracking:**
The correlator maintains a 5-minute sliding window of distinct rules fired per source IP. A `threat_score` (0–100) is computed as `min(100, distinct_rules × 10)`.

Severity is automatically escalated based on multi-stage attack behaviour:

| Distinct rules (score) | Escalation |
|------------------------|------------|
| 3+ (score ≥ 30) | bump to at least MEDIUM |
| 5+ (score ≥ 50) | bump to at least HIGH |
| 8+ (score ≥ 80) | escalate to CRITICAL |

An IP that scans → brute-forces → contacts a C2 port will have its alerts escalated to CRITICAL automatically, even if each individual rule fires at MEDIUM.

---

## Alerting Pipeline

### `alerting/deduplicator.py` — Noise Reduction

Each `(rule, src_ip)` pair has an independent 30-second cooldown timer. Only the first alert in each window passes through; subsequent duplicates are counted but discarded. Expired entries are purged every 2 minutes to prevent memory growth.

### `alerting/logger.py` — The Only Disk Writer

Every non-duplicate alert is written as one JSON line to `logs/nids.log`. The file is line-buffered — each line is flushed immediately, so no alert is lost on a crash. Supports `SIGHUP` (sent by logrotate) to reopen the file after rotation.

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
| Dashboard | `1` | Stat cards, threat posture banner, timeline chart, severity donut, live alert table, top attackers |
| Alert Feed | `2` | Full alert table with filters (severity, category, source IP, rule), pause/resume, CSV export |
| Attack Map | `3` | SVG world map — dots sized by alert volume, colored by severity; click to investigate IP |
| Rules | `4` | All 74 signatures grouped by category, with hit counts, severity badges, and MITRE ATT&CK IDs |
| Analytics | `5` | Category breakdown cards, top IPs/ports/rules bar charts, MITRE technique frequency |
| Allowlist | `6` | Add/remove trusted IPs and CIDR subnets; changes take effect within ~2 minutes |
| PCAP Analysis | `7` | Drag-and-drop .pcap upload; runs all 74 signatures offline; Overview / Alerts / Attackers / Timeline tabs |

Additional UI features:
- **Collapsible sidebar** — click the `‹/›` chevron to collapse to a 52px icon rail; saves horizontal space on smaller screens
- **Capture engine control** — start/stop `main.py` from the sidebar without touching the terminal
- **IP investigation drawer** — click any source IP to open a side panel with risk score, first/last seen, top rules, MITRE techniques, and recent events
- **Toast notifications** — pop-up alerts for CRITICAL/HIGH events (configurable to CRITICAL-only)
- **Demo mode banner** — shown when no live backend is detected; displays simulated traffic so the UI is fully explorable without running the engine
- **Keyboard shortcuts** — `P` pause, `E` export CSV, `C` clear filters, `T` toggle theme, `/` focus rule search, `?` show all shortcuts
- **Tweaks panel** — runtime controls for refresh interval, max table rows, compact mode

### Standalone PCAP Dashboard — `dashboard/pcap_app.py`

An independent Flask app for offline analysis without the live dashboard running. Useful for analysing captures on a machine where the engine was never deployed.

```bash
python -m dashboard.pcap_app
# open http://localhost:5001
```

Accepts the same drag-and-drop upload interface as the embedded PCAP view. Also supports a CLI mode for scripted use:

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

Credentials are always loaded from environment variables. Use a `.env` file locally (gitignored). In production use the system environment or `EnvironmentFile=` in the systemd unit.

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
sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario apt_campaign
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

Edit `deploy/nids.service` to set the correct `--interface` before deploying. The logrotate config rotates `logs/nids.log` daily (30-day retention) and sends `SIGHUP` after rotation so the logger reopens the new file without a process restart.

---

## Known Limitations

- **IPv4 only.** The BPF filter `"ip"` excludes IPv6. An attacker on a dual-stack network can evade detection by using IPv6.
- **Single interface.** One sniffer thread per process. Multi-homed hosts need multiple instances.
- **Rule-based only.** Novel attacks with no matching signature are invisible.
- **No rule hot-reload.** Adding or editing signatures requires a process restart.
- **Dashboard has no authentication.** Anyone with network access to port 5000 can read alert data.
- **No HTTPS on dashboard.** Dashboard traffic is unencrypted.

---

## Future Improvements

**Near-term (operational gaps)**
- Notifier rate-limit — cap notifications-per-hour to prevent email floods during sustained multi-hour attacks
- Dashboard authentication — HTTP Basic Auth or token so alert data is not publicly readable
- HTTPS for dashboard — self-signed cert or Nginx reverse proxy

**Medium-term (capability)**
- IPv6 support — change BPF filter to `"ip or ip6"` and extend `extractor.py` for IPv6 headers
- Multi-interface support — one sniffer thread per interface, single shared queue
- GeoIP enrichment — annotate alerts with country code and ASN from a local MaxMind database
- SIEM integration — syslog or CEF output format alongside JSON lines
- Rule hot-reload — `SIGUSR1` handler that reloads `signatures.py` without stopping capture

**Long-term (architectural)**
- Anomaly detection layer — statistical baseline (e.g. per-IP packet rate EMA) to surface novel attacks no rule covers
- Machine learning classifier — trained binary classifier on labeled `FeatureDict` data
- Packet capture to PCAP — rolling pcap file alongside the JSON alert log for forensic replay
- Distributed mode — multiple sensor nodes forwarding alerts to a central aggregator and dashboard
- Custom rule editor in dashboard — define and activate new signatures from the web UI without editing Python
- MITRE ATT&CK coverage heatmap — visualize which techniques the current ruleset covers and which are blind spots
