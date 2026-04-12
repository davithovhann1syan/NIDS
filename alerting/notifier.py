from __future__ import annotations

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText

import config
from detection.correlator import CorrelatedAlert

_NOTIFY_TIMEOUT = 10  # seconds — max time to wait for SMTP or Slack response


class Notifier:
    """Dispatches email and Slack notifications for HIGH and CRITICAL alerts.

    Only fires when alert severity >= NOTIFY_MIN_SEVERITY (from config).
    Both channels are optional — if credentials are absent the channel is
    skipped silently. Network failures are caught and printed to stdout
    rather than re-raised, so a notification failure never crashes the
    analysis thread.

    Note: notify() is synchronous and called from Thread 2 (analysis loop).
    Network calls are bounded by _NOTIFY_TIMEOUT. With the deduplicator's
    30-second cooldown this is usually acceptable, but under a sustained
    attack generating many unique (rule, src_ip) pairs the cooldown won't
    protect you and the queue may back up. If queue saturation is observed
    during an attack, move notify() to a dedicated Thread 4 with its own
    internal queue.
    """

    def __init__(self) -> None:
        self._min_rank = config.SEVERITY_RANK[config.NOTIFY_MIN_SEVERITY]

    def notify(self, alert: CorrelatedAlert) -> None:
        """Send notifications for this alert if it meets the severity threshold.

        Checks both email and Slack channels independently — a failure on
        one channel does not prevent the other from being attempted.

        Args:
            alert: A CorrelatedAlert that has passed the deduplicator.
        """
        if config.SEVERITY_RANK[alert["severity"]] < self._min_rank:
            return

        subject = f"[NIDS] {alert['severity']} — {alert['rule']}"
        body    = _format_body(alert)

        if config.SMTP_HOST and config.SMTP_USER and config.SMTP_PASS and config.ALERT_EMAIL:
            self._send_email(subject, body)

        if config.SLACK_WEBHOOK:
            self._send_slack(subject, body, alert)

    # ── Email ─────────────────────────────────────────────────────────────────

    def _send_email(self, subject: str, body: str) -> None:
        msg            = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = config.SMTP_USER
        msg["To"]      = config.ALERT_EMAIL

        try:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=_NOTIFY_TIMEOUT) as smtp:
                smtp.starttls()
                smtp.login(config.SMTP_USER, config.SMTP_PASS)
                smtp.sendmail(config.SMTP_USER, config.ALERT_EMAIL, msg.as_string())
        except (smtplib.SMTPException, OSError) as exc:
            print(f"[notifier] email failed: {exc}")

    # ── Slack ─────────────────────────────────────────────────────────────────

    def _send_slack(self, subject: str, body: str, alert: CorrelatedAlert) -> None:
        payload = json.dumps({
            "username":   "NIDS",
            "text":       f"*{subject}*\n```{body}```",
            "icon_emoji": ":rotating_light:" if alert["severity"] == "CRITICAL" else ":warning:",
        }).encode()

        req = urllib.request.Request(
            url=config.SLACK_WEBHOOK,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_NOTIFY_TIMEOUT) as resp:
                if resp.status != 200:
                    print(f"[notifier] slack returned HTTP {resp.status}")
        except OSError as exc:
            print(f"[notifier] slack failed: {exc}")


# ── Formatting ────────────────────────────────────────────────────────────────

def _format_body(alert: CorrelatedAlert) -> str:
    """Build a human-readable notification body from a CorrelatedAlert."""
    lines = [
        f"Severity  : {alert['severity']}",
        f"Rule      : {alert['rule']}",
        f"Source IP : {alert['src_ip']}",
        f"Dest IP   : {alert['dst_ip']}",
    ]
    if alert["dst_port"] is not None:
        lines.append(f"Dest Port : {alert['dst_port']}")
    if "count" in alert:
        lines.append(f"Count     : {alert['count']} packets in window")
    if alert["also_triggered"]:
        lines.append(f"Also fired: {', '.join(alert['also_triggered'])}")
    return "\n".join(lines)
