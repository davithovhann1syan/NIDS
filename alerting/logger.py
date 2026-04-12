from __future__ import annotations

import json
import os
from datetime import datetime
from typing import TextIO

import config
from detection.correlator import CorrelatedAlert


class Logger:
    """Append-only JSON-lines writer. The only module that writes to disk.

    Keeps the log file open between writes for performance. Supports
    reopening after log rotation via reopen() — call this from main.py
    when a SIGHUP is received (triggered by logrotate postrotate script).

    Uses line buffering (buffering=1) so every alert is flushed immediately
    without an explicit flush() call — alerts are never lost in a buffer
    if the process crashes.
    """

    def __init__(self, log_path: str = config.LOG_PATH) -> None:
        self._log_path = log_path
        self._file: TextIO = self._open()

    def _open(self) -> TextIO:
        """Create the log directory if needed and open the file for appending."""
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
        return open(self._log_path, "a", buffering=1)

    def log(self, alert: CorrelatedAlert) -> None:
        """Write one alert as a JSON line to the log file.

        Adds a UTC timestamp at write time. All fields from CorrelatedAlert
        are included. count is only present for rate rule alerts (NotRequired).
        dst_port is null in JSON when the protocol has no port (e.g. ICMP).

        If the write fails (disk full, file deleted mid-run), prints to stdout
        as a last resort rather than crashing the analysis thread.

        Args:
            alert: A CorrelatedAlert that has passed the deduplicator.
        """
        record: dict[str, object] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            **alert,  # type: ignore[misc]
        }
        try:
            self._file.write(json.dumps(record) + "\n")
        except OSError as exc:
            # Last resort — the logger itself has failed so stdout is the only
            # remaining channel. Do not re-raise: a write failure must not crash
            # the analysis thread and take down the entire NIDS.
            print(f"[logger] write failed: {exc}")

    def reopen(self) -> None:
        """Close and reopen the log file.

        Call from main.py on SIGHUP so the logger starts writing to the
        fresh file created by logrotate rather than the rotated-away one.

        Opens the new file before closing the old one to eliminate the window
        where self._file is closed but not yet replaced — prevents a crash if
        log() is called between the two operations.
        """
        old = self._file
        self._file = self._open()
        old.close()

    def close(self) -> None:
        """Flush and close the log file. Call from main.py on shutdown."""
        self._file.close()
