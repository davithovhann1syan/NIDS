# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System using Scapy for packet capture, signature-based (rule-based) detection, structured JSON logging, and a Flask dashboard. Designed for low-to-medium traffic internal network segments (< 100 Mbps).

---

## Table of Contents

- [What Problem It Solves](#what-problem-it-solves)
- [Architecture Philosophy](#architecture-philosophy)
- [Project Structure](#project-structure)
- [Threading Model](#threading-model)
- [The Queue — The System's Pressure Valve](#the-queue--the-systems-pressure-valve)
- [Packet Capture](#packet-capture----capturesniffer.py)
- [Packet Parsing](#packet-parsing----parserextractorpy)
- [Detection](#detection----two-engines)
- [Alerting Pipeline](#alerting-pipeline)
- [Dashboard](#dashboard----dashboardapppy)
- [Scripts](#scripts----scriptsreplay_pcappy)
- [Tests](#tests----tests)
- [Configuration](#configuration----configpy)
- [Coding Conventions](#coding-conventions)
- [Commands](#commands)
- [Deployment](#deployment-production)

---

## What Problem It Solves

A NIDS sits on a network and watches traffic in real time. When it sees something suspicious — a port scan, a connection to a known malware port, an ICMP flood — it logs an alert and optionally notifies you via email or Slack. It does **not** block traffic (that would be an IPS — Intrusion Prevention System). It only observes and reports.

This implementation targets **internal network segments under ~100 Mbps** — think a home lab, small office LAN, or a server subnet. It is not designed for internet edge traffic at gigabit speeds.

---

## Architecture Philosophy

The entire system is built around three principles:

**1. Strict one-way data flow**
No module downstream ever reaches back upstream. The dashboard does not touch the detector. The detector does not touch the logger. This prevents circular dependencies and makes each stage independently testable.

**2. Single responsibility per module**
Each file does exactly one thing. `sniffer.py` only captures. `extractor.py` only parses. `logger.py` is the only thing that writes to disk. This is enforced by convention.

**3. Fail safely under load**
If the system cannot keep up with traffic, packets are **dropped at the queue boundary** rather than consuming unbounded memory. This is a deliberate design choice — it is better to miss some packets than to crash.

### Pipeline (strict one-way, no back-references)

```
[NIC] → sniffer.py → Queue → extractor.py → sig_detector.py → correlator → deduplicator → logger → notifier
                                                                        dashboard reads logs/ independently
```

---

## Project Structure

```
nids/
├── main.py                      # Entry point — starts threads, handles shutdown
├── config.py                    # Single source of truth for all tuneable values
├── requirements.txt
├── .gitignore                   # Excludes: logs/, .env
│
├── capture/
│   ├── sniffer.py               # Scapy sniff() — enqueues packets, nothing else
│   └── queue_manager.py         # Thread-safe bounded Queue (maxsize in config)
│
├── parser/
│   └── extractor.py             # Packet → feature dict. Handles missing layers safely.
│
├── detection/
│   ├── signatures.py            # Rule definitions as plain Python list of dicts
│   ├── sig_detector.py          # Pattern match + rate-based engine
│   └── correlator.py            # Decides final alert severity from signature matches
│
├── alerting/
│   ├── logger.py                # JSON-lines writer — the only module that writes to disk
│   ├── deduplicator.py          # Suppresses duplicate (rule, src_ip) within cooldown window
│   └── notifier.py              # Email + Slack dispatch, only fires on HIGH/CRITICAL
│
├── dashboard/
│   ├── app.py                   # Flask — reads log file only, never touches detection layer
│   └── templates/
│       └── index.html
│
├── scripts/
│   └── replay_pcap.py           # Feed a .pcap file through the detection engine for testing
│
├── logs/
│   └── nids.log                 # Gitignored. Append-only JSON lines.
│
└── tests/
    ├── conftest.py              # Shared fixtures: sample packets, feature dicts, mock config
    ├── test_extractor.py
    ├── test_sig_detector.py
    ├── test_correlator.py
    └── test_deduplicator.py
```

---

## Threading Model

The system runs 3 threads:

| Thread | Module | Responsibility |
|--------|--------|----------------|
| T1 | `sniffer.py` | Scapy `sniff()` loop. Enqueues raw packets. No processing. |
| T2 | `main.py` analysis loop | Dequeues, extracts features, runs both detectors, alerts. |
| T3 | `dashboard/app.py` | Flask server. Reads `nids.log` only. Completely isolated. |

All threads are **daemon threads**, meaning they die automatically when the main process exits. `main.py` catches `SIGINT` (Ctrl+C), signals the sniffer to stop, then **drains** the remaining packets from the queue before exiting — so buffered data is not lost on shutdown.

**Why not more threads for analysis?**
Thread 2 is deliberately single-threaded. Making it multi-threaded would require locking the deduplicator and rate-tracking state, adding significant complexity. For <100 Mbps, a single analysis thread is fast enough — packet parsing and rule matching are CPU-cheap operations.

**Thread safety rules:**
- Only `queue_manager.py` and `deduplicator.py` use locks
- All other modules are stateless or use only thread-local state
- `queue.Queue` is thread-safe by design in Python

---

## The Queue — The System's Pressure Valve

`capture/queue_manager.py` wraps Python's built-in `queue.Queue` with `maxsize=10_000`.

When Thread 1 (sniffer) is faster than Thread 2 (analysis):
- The queue fills up
- Scapy's callback blocks or drops packets depending on configuration
- Memory usage stays bounded — it never grows past ~10,000 raw packet objects

At average packet sizes (~500 bytes), 10,000 packets is ~5 MB of buffered data — small enough to be safe, large enough to absorb short traffic bursts. The `maxsize` is configurable in `config.py`.

Monitor queue saturation with:
```bash
sudo python main.py --interface eth0 --stats-interval 10
```
This prints queue depth and drop count every 10 seconds. If you see drops, the hardware cannot keep up with the traffic volume.

---

## Packet Capture — `capture/sniffer.py`

Uses **Scapy** for raw packet capture. Scapy's `sniff()` takes a callback function — every time a packet arrives on the interface, Scapy calls that callback. The sniffer's callback does exactly one thing: put the raw packet on the queue.

```python
def _packet_callback(pkt):
    queue.put(pkt)
```

No processing happens here. Doing anything else in this callback would slow down the capture loop and cause drops. The entire goal is to get packets off the wire and into memory as fast as possible.

**Root is required** because reading a raw network interface requires kernel privileges on Linux.

---

## Packet Parsing — `parser/extractor.py`

Converts raw Scapy `Packet` objects into plain Python dicts. After this point, **Scapy objects are discarded** — no module downstream ever imports Scapy.

Scapy packets hold references to internal C buffers and are not safely shareable across threads. Converting to a plain dict makes the data safe, serializable, and framework-independent.

### The Feature Dict — Always Complete

```python
{
    "timestamp":  float,        # time.time() — when the packet was captured
    "src_ip":     str,          # e.g. "192.168.1.5"
    "dst_ip":     str,
    "protocol":   int,          # IP proto number: 6=TCP, 17=UDP, 1=ICMP
    "length":     int,          # total packet length in bytes
    "ttl":        int,          # time-to-live (can hint at OS fingerprint)
    "src_port":   int | None,   # None if not TCP/UDP
    "dst_port":   int | None,
    "flags":      str | None,   # "S", "SA", "PA", "R", etc. — None if not TCP
    "flags_int":  int,          # TCP flags as bitmask (0 if not TCP)
    "icmp_type":  int | None,   # None if not ICMP
}
```

**No key is ever missing.** This is a hard contract. If a packet has no TCP layer, `src_port` is `None`, not absent. Rule conditions can always safely reference any key without a `KeyError`.

### Protocol Dispatch with `match/case`

The extractor uses Python 3.10+ structural pattern matching for clean protocol dispatch:

```python
match packet_protocol:
    case 6:    # TCP — extract ports, flags
    case 17:   # UDP — extract ports
    case 1:    # ICMP — extract icmp_type
    case _:    # everything else — set transport fields to None/0
```

---

## Detection — Two Engines

### `detection/signatures.py` — Rules as Data

Rules are plain Python dicts — no classes, no inheritance. Rules are **data, not code**. All detection rules live here and nowhere else; no rule logic leaks into `sig_detector.py`.

**Pattern Rule** — fires on a single packet matching all conditions:

```python
{
    "name": "Suspicious Outbound Port",
    "type": "pattern",
    "severity": "HIGH",
    "conditions": {
        "dst_port": [4444, 1337, 31337, 9001],   # common RAT/C2 ports
    }
}
```

A condition value can be a single value or a list (meaning "any of these").

**Rate Rule** — fires when a source IP exceeds a packet count within a time window:

```python
{
    "name": "Port Scan (SYN)",
    "type": "rate",
    "severity": "HIGH",
    "conditions": {
        "flags": "S",       # only count SYN packets
        "protocol": 6,      # only TCP
    },
    "threshold": 20,        # if a single src_ip sends...
    "window_seconds": 5,    # ...20+ matching packets within 5 seconds → alert
}
```

Other examples of rules you would define:
- ICMP flood (high rate of `icmp_type=8` echo requests)
- SSH brute force (high rate of TCP SYN to `dst_port=22`)
- DNS amplification (high rate of large UDP `dst_port=53` responses)
- Telnet attempts (pattern on `dst_port=23`)

### `detection/sig_detector.py` — The Matching Engine

For **pattern rules**: checks each condition key against the feature dict. If all conditions match, the alert fires.

For **rate rules**: maintains a sliding-window counter per `(src_ip, rule_name)` pair using a `defaultdict(deque)`.

On each matching packet:
1. Append `current_timestamp` to the deque for this `(src_ip, rule_name)`
2. Pop timestamps from the front that are older than `window_seconds`
3. If `len(deque) >= threshold` — fire the alert

This is O(1) amortized per packet per rule. Memory is bounded because old timestamps are always pruned. No `time.sleep()` or background cleanup thread is needed.

### `detection/correlator.py` — Severity Escalation

A single packet can match multiple rules simultaneously. The correlator takes the list of alerts for one packet and applies this priority ladder:

| Condition | Output |
|-----------|--------|
| Any alert is CRITICAL | Emit CRITICAL |
| Any alert is HIGH | Emit HIGH |
| Any alert is MEDIUM | Emit MEDIUM |
| Only LOW alerts | Emit LOW |
| No alerts | Discard |

It **escalates, never averages**. Two LOW alerts do not become MEDIUM. One HIGH alert among five LOWs is still HIGH. This conservative approach is intentional — better to over-alert than under-alert on a security system.

---

## Alerting Pipeline

### `alerting/deduplicator.py` — Noise Reduction

Without deduplication, a port scan at 1000 packets/second would generate 1000 identical alerts per second. The deduplicator prevents this.

It keeps a dict: `{(rule_name, src_ip): last_alert_timestamp}`

When an alert arrives:
- If `(rule, src_ip)` was last alerted more than `ALERT_COOLDOWN_SEC` ago (default: 30s) — **pass through**
- Otherwise — **suppress**

Uses a lock for thread safety.

### `alerting/logger.py` — The Only Disk Writer

This is the **single point of disk I/O** for the entire system. Every alert is written as one JSON line to `logs/nids.log`:

```json
{"timestamp": "2025-01-15T14:32:01.123Z", "rule": "Port Scan (SYN)", "severity": "HIGH", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 22, "count": 24}
```

Key design decisions:
- **JSON lines format** — one JSON object per line, so the file can be appended without reading it, and `tail -f` works naturally
- **Append-only** — never overwrites, never reads back
- **UTC timestamps only** — avoids timezone ambiguity across environments
- Fields not relevant to a rule are omitted (`count` only appears on rate rule alerts)

No other module is allowed to write to disk.

### `alerting/notifier.py` — Active Notification

Only fires for `HIGH` or `CRITICAL` severity (configurable via `NOTIFY_MIN_SEVERITY`). Below that threshold, alerts are logged only.

Supports:
- **Email** via SMTP
- **Slack** via incoming webhook

All credentials come exclusively from environment variables loaded in `config.py`. Never hardcode them.

---

## Dashboard — `dashboard/app.py`

A lightweight Flask app that reads `nids.log` and displays alerts in a browser. Runs as Thread 3.

**Completely isolated** from the rest of the system — it imports nothing from `detection/`, `capture/`, or `alerting/`. It only reads the log file. This means:
- It can be restarted without affecting packet capture or detection
- It can run on a different machine if the log file is shared (NFS, rsync, etc.)
- A bug in the dashboard cannot affect detection

`dashboard/templates/index.html` is the Jinja2 template Flask renders.

Do not run Flask with `debug=True` in production.

---

## Scripts — `scripts/replay_pcap.py`

A developer utility for testing the detection engine without a live interface:

```bash
python scripts/replay_pcap.py --file capture.pcap
```

Reads packets from a `.pcap` file (Wireshark/tcpdump format) and feeds them through the exact same `extractor → sig_detector → correlator → deduplicator → logger` pipeline. No root required, no network needed.

Use cases:
- Test new rules against known-malicious captures
- Reproduce a past incident for analysis
- Benchmark detection throughput offline

---

## Tests — `tests/`

Tests run with **zero external dependencies**: no root, no network interface, no disk writes.

### `tests/conftest.py` — Shared Fixtures

| Fixture | Description |
|---------|-------------|
| `syn_packet` | A Scapy `Ether/IP/TCP(flags="S")` packet object |
| `udp_packet` | A Scapy `Ether/IP/UDP` packet object |
| `sample_feature_dict` | A pre-built dict matching the full feature schema |
| `mock_config` | `config.py` values set to test-safe defaults |

### Test Files

| File | What it covers |
|------|----------------|
| `test_extractor.py` | Correct dict output, missing layer handling, field types |
| `test_sig_detector.py` | Pattern matching, rate window sliding, threshold boundary |
| `test_correlator.py` | Severity escalation for all combinations of alert mixes |
| `test_deduplicator.py` | Cooldown suppression, reset after window expires |

### Test Isolation

Each test file tests **one module only** — `test_sig_detector.py` does not import `extractor.py`. Tests assert on **alert schema keys**, not on string content of alert messages.

For rate rule tests, timestamps are **injected manually** rather than using `time.sleep()`, making tests instantaneous and deterministic:

```python
# Test a 5-second rate window without actually waiting 5 seconds
detector.process(feature_dict, timestamp=0.0)
detector.process(feature_dict, timestamp=2.5)
detector.process(feature_dict, timestamp=4.9)   # still in window → should alert
detector.process(feature_dict, timestamp=6.0)   # outside window → counter resets
```

---

## Configuration — `config.py`

Every tuneable value lives here. No magic numbers scattered across the codebase.

| Setting | Default | Purpose |
|---------|---------|---------|
| `INTERFACE` | `"eth0"` | Network interface to sniff on |
| `QUEUE_MAXSIZE` | `10_000` | Max buffered packets before drops |
| `LOG_PATH` | `"logs/nids.log"` | Alert log file location |
| `ALERT_COOLDOWN_SEC` | `30` | Dedup window per (rule, src_ip) |
| `NOTIFY_MIN_SEVERITY` | `"HIGH"` | Minimum severity for email/Slack |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` | from env | Email credentials |
| `SLACK_WEBHOOK` | from env | Slack incoming webhook URL |
| `ALERT_EMAIL` | from env | Destination email for alerts |

Credentials are always loaded from environment variables. Use a `.env` file locally (gitignored). In production, use the system environment or `EnvironmentFile=` in the systemd unit.

---

## Coding Conventions

| Rule | Reason |
|------|--------|
| Python 3.10+ | Required for `match/case` syntax in `extractor.py` |
| Type hints on every function signature | Readability and IDE support |
| No bare `except:` | Always catch specific exception types — bare except hides bugs |
| No `print()` except `main.py` | All alerting goes through `logger.py`; modules stay silent |
| All times in UTC | Avoids timezone bugs in distributed or long-running deployments |
| Immutable feature dicts | Downstream modules never mutate data; create a new dict if enrichment is needed |
| Rules are data in `signatures.py` | No rule logic leaks into the engine — rules stay readable and editable |
| No database | Flat JSON lines are sufficient and operationally simpler |
| No ML or anomaly detection | Keeps the system auditable, deterministic, and explainable |

---

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run NIDS on a live interface (root required for raw socket)
sudo python main.py --interface eth0

# Run NIDS with queue saturation monitoring (prints stats every 10s)
sudo python main.py --interface eth0 --stats-interval 10

# Feed a pcap file through the detection engine (no root needed)
python scripts/replay_pcap.py --file capture.pcap

# Launch the dashboard (separate terminal, no root needed)
python -m dashboard.app

# Run the full test suite
pytest tests/ -v

# Run a single test file
pytest tests/test_sig_detector.py -v

# List all tests without running them
pytest tests/ -v --co

# Run tests with short tracebacks
pytest tests/ -v --tb=short
```

---

## Deployment (Production)

### systemd Service

```ini
# /etc/systemd/system/nids.service
[Unit]
Description=NIDS
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/nids
EnvironmentFile=/opt/nids/.env
ExecStart=/opt/nids/venv/bin/python main.py --interface eth0
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable nids
sudo systemctl start nids
journalctl -u nids -f          # Follow live logs
```

### Log Rotation

```
# /etc/logrotate.d/nids
/opt/nids/logs/nids.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP nids
    endscript
}
```

Rotates daily, keeps 30 days of compressed history, sends `SIGHUP` after rotation so the process reopens the log file handle.

### Health Check

```bash
# Verify the queue is not saturating under current traffic load
sudo python main.py --interface eth0 --stats-interval 60
```

---

## Alert Schema

Every line in `logs/nids.log` is a JSON object:

```json
{
  "timestamp": "2025-01-15T14:32:01.123Z",
  "rule":      "Port Scan (SYN)",
  "severity":  "HIGH",
  "src_ip":    "10.0.0.5",
  "dst_ip":    "10.0.0.1",
  "dst_port":  22,
  "count":     24
}
```

- `count` is only present on rate rule alerts
- Fields not relevant to a rule are omitted
- The dashboard expects this exact schema — do not add or rename top-level keys without also updating `dashboard/app.py`

---

## Do Not

- Do not store raw Scapy `Packet` objects after the capture thread — extract and discard
- Do not let any module other than `alerting/logger.py` write to disk
- Do not hardcode IPs, ports, or credentials anywhere — use `config.py` or environment variables
- Do not add a database — logs are flat JSON lines
- Do not add anomaly/ML detection — this is a purely rule-based system
- Do not catch `KeyboardInterrupt` in threads — let `main.py` handle shutdown
- Do not run Flask with `debug=True` outside of local development
- Do not change the feature dict schema without simultaneously updating `signatures.py` condition keys and `tests/conftest.py` fixtures
