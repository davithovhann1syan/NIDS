from __future__ import annotations

import os

# Capture
INTERFACE     = "eth0"
QUEUE_MAXSIZE = 10_000

# Paths
LOG_PATH = "logs/nids.log"

# Alerting
ALERT_COOLDOWN_SEC  = 30
NOTIFY_MIN_SEVERITY = "HIGH"

# Notifier — loaded from environment, never hardcoded
SMTP_HOST     = os.getenv("SMTP_HOST")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASS     = os.getenv("SMTP_PASS")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
ALERT_EMAIL   = os.getenv("ALERT_EMAIL")
