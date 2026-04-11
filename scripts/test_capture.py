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

INTERFACE   = "wlan0"
PACKET_GOAL = 10000


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

    captured = 0
    while captured < PACKET_GOAL:
        pkt = pkt_queue.get()
        pkt_queue.task_done()
        captured += 1
        print(f"  [{captured:02d}] {pkt.summary()}")

    stop_event.set()
    sniffer_thread.join(timeout=3)

    print(f"\nDone.")
    print(f"  Enqueued : {pkt_queue.enqueue_count}")
    print(f"  Dropped  : {pkt_queue.drop_count}")
    print(f"  Drop rate: {pkt_queue.drop_rate:.2f}%")


if __name__ == "__main__":
    main()
