from __future__ import annotations

import argparse
import queue
import signal
import sys
import threading
import time

from dotenv import load_dotenv

load_dotenv()  # load .env into os.environ before config reads it

import config
from capture.queue_manager import PacketQueue
from capture.sniffer import start_sniffing
from parser.extractor import extract
from detection.sig_detector import SignatureDetector
from detection.correlator import correlate
from alerting.deduplicator import Deduplicator
from alerting.logger import Logger
from alerting.notifier import Notifier


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NIDS — Network Intrusion Detection System",
    )
    parser.add_argument(
        "--interface", "-i",
        default=config.INTERFACE,
        help=f"Network interface to sniff on (default: {config.INTERFACE})",
    )
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Print queue and alert stats every N seconds (0 = disabled)",
    )
    return parser.parse_args()


def _print_stats(
    pkt_queue:  PacketQueue,
    dedup:      Deduplicator,
    alerts_logged: int,
) -> None:
    print(
        f"[stats] "
        f"queue={pkt_queue.qsize:>5}  "
        f"captured={pkt_queue.enqueue_count:>8}  "
        f"dropped={pkt_queue.drop_count:>6}  "
        f"drop_rate={pkt_queue.drop_rate:>5.2f}%  "
        f"alerts_logged={alerts_logged:>5}  "
        f"suppressed={dedup.suppressed_count:>6}"
    )


def main() -> None:
    args = _parse_args()

    # ── Component setup ───────────────────────────────────────────────────────
    pkt_queue  = PacketQueue()
    detector   = SignatureDetector()
    dedup      = Deduplicator()
    logger     = Logger()
    notifier   = Notifier()
    stop_event = threading.Event()

    # ── Signal handlers ───────────────────────────────────────────────────────
    # SIGHUP: sent by logrotate after rotating nids.log — reopen the file.
    signal.signal(signal.SIGHUP, lambda *_: logger.reopen())

    # ── Thread 1: packet capture ──────────────────────────────────────────────
    sniffer_thread = threading.Thread(
        target=start_sniffing,
        args=(pkt_queue, stop_event),
        kwargs={"interface": args.interface},
        daemon=True,
        name="sniffer",
    )
    sniffer_thread.start()

    print(f"[main] NIDS running on {args.interface} — press Ctrl+C to stop")
    if args.stats_interval:
        print(f"[main] stats every {args.stats_interval}s")

    # ── Thread 2: analysis loop (runs on main thread) ─────────────────────────
    alerts_logged = 0
    last_purge    = time.monotonic()
    last_stats    = time.monotonic()

    try:
        while True:
            # Use a 1-second timeout so the loop wakes up regularly for stats,
            # purging, and clean KeyboardInterrupt handling on quiet networks.
            try:
                pkt = pkt_queue.get(timeout=1.0)
            except queue.Empty:
                now = time.monotonic()
                if args.stats_interval and now - last_stats >= args.stats_interval:
                    _print_stats(pkt_queue, dedup, alerts_logged)
                    last_stats = now
                continue

            pkt_queue.task_done()

            # Extract features — skip non-IP packets that slipped past BPF filter.
            try:
                features = extract(pkt)
            except ValueError:
                continue

            # Detect → correlate → deduplicate → log → notify.
            raw_alerts = detector.process(features)
            alert      = correlate(raw_alerts)

            if alert is None:
                continue

            if dedup.is_duplicate(alert):
                continue

            logger.log(alert)
            notifier.notify(alert)
            alerts_logged += 1
            print(
                f"[alert] {alert['severity']:<8}  "
                f"{alert['rule']:<35}  "
                f"{alert['src_ip']} -> {alert['dst_ip']}"
                + (f":{alert['dst_port']}" if alert["dst_port"] else "")
                + (f"  (count={alert['count']})" if "count" in alert else "")
            )

            # ── Periodic maintenance ──────────────────────────────────────────
            now = time.monotonic()

            # Purge expired dedup entries every 2 minutes to bound memory usage.
            if now - last_purge >= 120:
                dedup.purge_expired()
                last_purge = now

            # Stats output.
            if args.stats_interval and now - last_stats >= args.stats_interval:
                _print_stats(pkt_queue, dedup, alerts_logged)
                last_stats = now

    except KeyboardInterrupt:
        print("\n[main] shutting down — draining queue...")
        stop_event.set()
        sniffer_thread.join(timeout=3)

        # Drain and process any packets still in the queue before exit.
        while True:
            try:
                pkt = pkt_queue.get(timeout=0.1)
                pkt_queue.task_done()
                try:
                    features   = extract(pkt)
                    raw_alerts = detector.process(features)
                    alert      = correlate(raw_alerts)
                    if alert and not dedup.is_duplicate(alert):
                        logger.log(alert)
                        # notifier intentionally skipped during shutdown drain
                        alerts_logged += 1
                except ValueError:
                    continue
            except queue.Empty:
                break

        logger.close()
        print(f"[main] done — {alerts_logged} alerts logged to {config.LOG_PATH}")
        sys.exit(0)


if __name__ == "__main__":
    main()
