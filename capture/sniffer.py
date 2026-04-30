from __future__ import annotations

import threading
from collections.abc import Callable

from scapy.all import AsyncSniffer, Packet

import config
from capture.queue_manager import PacketQueue

_RETRY_DELAY = 3.0  # seconds to wait between restart attempts
_MAX_RETRIES = 5    # consecutive failures before giving up


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
    """Capture packets and enqueue them. Blocks until stop_event is set.

    Uses AsyncSniffer to keep a single persistent capture socket open for the
    lifetime of the process.  The previous timeout-loop approach reopened the
    underlying socket every second, adding syscall overhead and creating brief
    gaps at the kernel/socket boundary where packets could be missed under load.

    Restarts capture automatically if the socket fails (e.g. interface bounce)
    up to _MAX_RETRIES consecutive times before giving up.

    Args:
        pkt_queue:  Destination queue for captured packets.
        stop_event: Set this event to stop capture cleanly.
        interface:  Network interface to sniff on (e.g. "eth0").
        bpf_filter: Kernel-level BPF filter applied before Python sees the packet.
                    Filtering at the kernel level is cheaper than filtering in Python.
    """
    print(f"[sniffer] starting capture on {interface} (filter: '{bpf_filter}')")
    callback = _make_callback(pkt_queue)
    failures = 0

    while not stop_event.is_set():
        sniffer: AsyncSniffer | None = None
        try:
            sniffer = AsyncSniffer(
                iface=interface,
                prn=callback,
                store=False,
                filter=bpf_filter,
            )
            sniffer.start()
            failures = 0
            print(f"[sniffer] capture active on {interface}")

            # Block here, waking every second to check stop_event and sniffer health.
            # stop_event.wait(1.0) releases the GIL so the analysis thread runs freely.
            while not stop_event.is_set():
                if not sniffer.running:
                    print("[sniffer] capture thread died unexpectedly — restarting")
                    break
                stop_event.wait(timeout=1.0)

        except (OSError, PermissionError) as exc:
            failures += 1
            if failures >= _MAX_RETRIES:
                print(f"[sniffer] {_MAX_RETRIES} consecutive failures — giving up capture")
                return
            print(
                f"[sniffer] error: {exc} — "
                f"retry {failures}/{_MAX_RETRIES} in {_RETRY_DELAY:.0f}s"
            )
            stop_event.wait(timeout=_RETRY_DELAY)

        finally:
            if sniffer is not None and sniffer.running:
                try:
                    sniffer.stop(join=False)
                except Exception:
                    pass

    print("[sniffer] stopped")
