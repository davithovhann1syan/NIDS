"""
Verify the capture + extraction pipeline end-to-end.
Captures N packets from the specified interface, prints their features,
then exits cleanly with a protocol breakdown summary.

Run with:
    sudo .venv/bin/python scripts/test_capture.py
    sudo .venv/bin/python scripts/test_capture.py --interface eth0 --count 50
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # project root

import config
from capture.queue_manager import PacketQueue
from capture.sniffer import start_sniffing
from parser.extractor import FeatureDict, extract
import threading


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the NIDS capture + extraction pipeline.",
    )
    parser.add_argument(
        "--interface", "-i",
        default=config.INTERFACE,
        help=f"Network interface to capture on (default: {config.INTERFACE})",
    )
    parser.add_argument(
        "--count", "-n",
        type=int, default=100,
        metavar="N",
        help="Number of packets to capture before exiting (default: 100)",
    )
    args = parser.parse_args()

    pkt_queue  = PacketQueue()
    stop_event = threading.Event()

    sniffer_thread = threading.Thread(
        target=start_sniffing,
        args=(pkt_queue, stop_event),
        kwargs={"interface": args.interface},
        daemon=True,
    )
    sniffer_thread.start()
    print(f"Capturing {args.count} packets on {args.interface}...\n")

    captured     = 0
    parse_errors = 0
    proto_counts: dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    while captured < args.count:
        pkt = pkt_queue.get()
        pkt_queue.task_done()

        try:
            features: FeatureDict = extract(pkt)
            captured += 1

            match features["protocol"]:
                case 6:  proto_counts["TCP"]  += 1
                case 17: proto_counts["UDP"]  += 1
                case 1:  proto_counts["ICMP"] += 1
                case _:  proto_counts["Other"] += 1

            print(
                f"  [{captured:03d}] "
                f"proto={features['protocol']:>2}  "
                f"{features['src_ip']:>15}:{str(features['src_port'] or ''):>5} -> "
                f"{features['dst_ip']:>15}:{str(features['dst_port'] or ''):>5}  "
                f"flags={features['flags'] or '-':>4}  "
                f"len={features['length']:>5}  "
                f"ttl={features['ttl']:>3}"
            )
        except ValueError:
            parse_errors += 1  # non-IP packet slipped through BPF filter

    stop_event.set()
    sniffer_thread.join(timeout=3)

    print(f"\n{'─' * 60}")
    print(f"  Captured     : {captured}")
    print(f"  Parse errors : {parse_errors}")
    print(f"  Enqueued     : {pkt_queue.enqueue_count}")
    print(f"  Dropped      : {pkt_queue.drop_count}")
    print(f"  Drop rate    : {pkt_queue.drop_rate:.2f}%")
    print(f"{'─' * 60}")
    print(f"  Protocol breakdown:")
    for proto, count in proto_counts.items():
        pct = (count / captured * 100) if captured > 0 else 0.0
        bar = "█" * int(pct / 2)
        print(f"    {proto:<6} {count:>5}  ({pct:5.1f}%)  {bar}")
    print(f"{'─' * 60}")


if __name__ == "__main__":
    main()
