"""
Throwaway script to verify the capture module works end-to-end.
Captures 10 packets from wlan0, prints their summaries, then exits cleanly.

Run with:
    sudo python scripts/test_capture.py
"""
from __future__ import annotations

import sys
import threading
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))  # project root

from capture.queue_manager import PacketQueue
from capture.sniffer import start_sniffing
from parser.extractor import extract, FeatureDict

INTERFACE   = "wlan0"
PACKET_GOAL = 100


def main() -> None:
    pkt_queue  = PacketQueue()
    stop_event = threading.Event()

    sniffer_thread = threading.Thread(
        target=start_sniffing,
        args=(pkt_queue, stop_event),
        kwargs={"interface": INTERFACE},
        daemon=True,
    )
    sniffer_thread.start()
    print(f"Capturing {PACKET_GOAL} packets on {INTERFACE}...\n")

    captured     = 0
    parse_errors = 0
    proto_counts: dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    while captured < PACKET_GOAL:
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
