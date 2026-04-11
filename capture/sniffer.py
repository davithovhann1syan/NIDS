from __future__ import annotations

import threading
from collections.abc import Callable

from scapy.all import Packet, sniff

import config
from capture.queue_manager import PacketQueue


def _make_callback(pkt_queue: PacketQueue) -> Callable[[Packet], None]:
    """Return a Scapy prn callback that enqueues packets onto pkt_queue."""
    def _callback(pkt: Packet) -> None:
        pkt_queue.put_nowait(pkt)
    return _callback


def start_sniffing(
    pkt_queue: PacketQueue,
    stop_event: threading.Event,
    interface: str = config.INTERFACE,
    bpf_filter: str = "ip",
) -> None:
    """Capture packets from interface and enqueue them. Blocks until stop_event is set.

    Uses a 1-second timeout loop so stop_event is checked regularly even on
    quiet networks where no packets arrive.

    Args:
        pkt_queue:  Destination queue for captured packets.
        stop_event: Set this event from main.py to stop capture cleanly.
        interface:  Network interface to sniff on (e.g. "eth0").
        bpf_filter: Kernel-level BPF filter string. Defaults to "ip" (IPv4 only).
                    Filtering at the kernel level is cheaper than filtering in Python.
    """
    # TODO: replace with alerting/logger.py once it exists
    print(f"[sniffer] starting capture on {interface} (filter: '{bpf_filter}')")

    callback = _make_callback(pkt_queue)

    while not stop_event.is_set():
        sniff(
            iface=interface,
            prn=callback,
            store=False,
            filter=bpf_filter,
            timeout=1,
        )
