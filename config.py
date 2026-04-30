from __future__ import annotations

import os

# Capture
INTERFACE     = os.getenv("INTERFACE", "wlan0")
QUEUE_MAXSIZE = 10_000

# Paths
LOG_PATH       = "logs/nids.log"
ALLOWLIST_PATH = "allowlist.json"

# Alerting
ALERT_COOLDOWN_SEC  = 30
NOTIFY_MIN_SEVERITY = "HIGH"

# Severity rank — single source of truth used by correlator and notifier.
# Higher number = higher priority.
SEVERITY_RANK: dict[str, int] = {
    "LOW":      0,
    "MEDIUM":   1,
    "HIGH":     2,
    "CRITICAL": 3,
}

# Notifier — loaded from environment, never hardcoded
SMTP_HOST     = os.getenv("SMTP_HOST")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASS     = os.getenv("SMTP_PASS")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
ALERT_EMAIL   = os.getenv("ALERT_EMAIL")
