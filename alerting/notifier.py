from __future__ import annotations

import json
import queue
import smtplib
import threading
import time
import urllib.parse
import urllib.request
from email.mime.text import MIMEText

import config
from detection.correlator import CorrelatedAlert

_NOTIFY_TIMEOUT = 10   # seconds — max time to wait for SMTP or Slack response
_BATCH_WINDOW   = 3.0  # seconds to wait for additional alerts before sending
_QUEUE_MAXSIZE  = 100  # drop oldest alerts beyond this to avoid stale backlog


class Notifier:
    """Dispatches email and Slack notifications for HIGH and CRITICAL alerts.

    Network I/O runs on a dedicated daemon thread so the analysis loop
    is never blocked waiting for SMTP or a Slack webhook.

    Batching: alerts that arrive within _BATCH_WINDOW seconds of each other
    are collapsed into a single notification, preventing alert storms from
    generating hundreds of individual emails during an active attack.

    Bounded queue: the internal queue is capped at _QUEUE_MAXSIZE.  When full,
    the oldest pending alert is dropped to make room for the newest — an analyst
    reading email an hour later cares about the most recent events, not the
    first ones from a long-over incident.

    Persistent SMTP: one connection is kept open and reused across sends.
    A single reconnect attempt is made automatically on a stale connection
    (servers typically close idle connections after 5–15 minutes).
    """

    def __init__(self) -> None:
        self._min_rank = config.SEVERITY_RANK[config.NOTIFY_MIN_SEVERITY]
        self._queue: queue.Queue[CorrelatedAlert] = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._smtp:  smtplib.SMTP | None = None
        self._worker = threading.Thread(
            target=self._dispatch_loop,
            daemon=True,
            name="notifier",
        )
        self._worker.start()

    def notify(self, alert: CorrelatedAlert) -> None:
        """Enqueue an alert for notification. Returns immediately — never blocks.

        Below-threshold alerts are dropped before queuing so the worker thread
        is not woken for events it would discard anyway.  When the queue is full,
        the oldest pending alert is evicted to make room for the incoming one.
        """
        if config.SEVERITY_RANK[alert["severity"]] < self._min_rank:
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            try:
                self._queue.get_nowait()  # evict oldest
            except queue.Empty:
                pass
            self._queue.put_nowait(alert)

    # ── Worker thread ─────────────────────────────────────────────────────────

    def _dispatch_loop(self) -> None:
        """Drain the notification queue, batching nearby alerts. Runs forever."""
        while True:
            # Block until the first alert arrives.
            alert = self._queue.get()
            batch = [alert]

            # Collect any further alerts that arrive within the batch window.
            deadline = time.monotonic() + _BATCH_WINDOW
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break

            subject = _batch_subject(batch)
            body    = _batch_body(batch)

            if config.SMTP_HOST and config.SMTP_USER and config.SMTP_PASS and config.ALERT_EMAIL:
                self._send_email(subject, body)

            if config.SLACK_WEBHOOK:
                parsed = urllib.parse.urlparse(config.SLACK_WEBHOOK)
                if parsed.scheme == "https" and parsed.netloc:
                    self._send_slack(subject, body, batch)
                else:
                    print("[notifier] SLACK_WEBHOOK must be an https:// URL — skipping")

    # ── Email ─────────────────────────────────────────────────────────────────

    def _smtp_connect(self) -> None:
        """Open and authenticate a fresh SMTP connection."""
        self._smtp = smtplib.SMTP(
            config.SMTP_HOST, config.SMTP_PORT, timeout=_NOTIFY_TIMEOUT
        )
        self._smtp.starttls()
        self._smtp.login(config.SMTP_USER, config.SMTP_PASS)

    def _send_email(self, subject: str, body: str) -> None:
        msg            = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = config.SMTP_USER
        msg["To"]      = config.ALERT_EMAIL

        # Retry once — handles a stale persistent connection (server closed idle socket).
        for attempt in range(2):
            try:
                if self._smtp is None:
                    self._smtp_connect()
                self._smtp.sendmail(config.SMTP_USER, config.ALERT_EMAIL, msg.as_string())
                return
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectionError):
                self._smtp = None  # force reconnect on next attempt
            except (smtplib.SMTPException, OSError) as exc:
                print(f"[notifier] email failed: {exc}")
                self._smtp = None
                return
        print("[notifier] email failed: could not reconnect to SMTP server")

    # ── Slack ─────────────────────────────────────────────────────────────────

    def _send_slack(
        self, subject: str, body: str, batch: list[CorrelatedAlert]
    ) -> None:
        top = max(batch, key=lambda a: config.SEVERITY_RANK[a["severity"]])
        payload = json.dumps({
            "username":   "NIDS",
            "text":       f"*{subject}*\n```{body}```",
            "icon_emoji": ":rotating_light:" if top["severity"] == "CRITICAL" else ":warning:",
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

def _batch_subject(batch: list[CorrelatedAlert]) -> str:
    top = max(batch, key=lambda a: config.SEVERITY_RANK[a["severity"]])
    if len(batch) == 1:
        return f"[NIDS] {top['severity']} — {top['rule']}"
    return f"[NIDS] {len(batch)} alerts — highest: {top['severity']} {top['rule']}"


def _batch_body(batch: list[CorrelatedAlert]) -> str:
    parts = []
    for i, alert in enumerate(batch, 1):
        prefix = f"[{i}/{len(batch)}] " if len(batch) > 1 else ""
        lines = [
            f"{prefix}Severity  : {alert['severity']}",
            f"  Rule      : {alert['rule']}",
            f"  Source IP : {alert['src_ip']}",
            f"  Dest IP   : {alert['dst_ip']}",
        ]
        if alert["dst_port"] is not None:
            lines.append(f"  Dest Port : {alert['dst_port']}")
        if "count" in alert:
            lines.append(f"  Count     : {alert['count']} packets in window")
        score = alert.get("threat_score", 0)
        if score:
            lines.append(f"  Threat    : {score}/100")
        if alert["also_triggered"]:
            lines.append(f"  Also fired: {', '.join(alert['also_triggered'])}")
        parts.append("\n".join(lines))
    return "\n\n".join(parts)
