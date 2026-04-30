from __future__ import annotations

import queue

import config


class PacketQueue:
    """Thread-safe bounded queue between the sniffer and analysis threads.

    If the queue is full (analysis thread falling behind), put_nowait()
    drops the packet and increments the drop counter rather than blocking
    or consuming unbounded memory. This is intentional.

    Stats counters (_enqueue_count, _drop_count) are written exclusively by
    the sniffer thread and read only by the analysis thread for display.
    No lock is needed: CPython's GIL makes single-integer increments atomic,
    and a one-packet-stale stats read is acceptable for health monitoring.
    """

    def __init__(self, maxsize: int = config.QUEUE_MAXSIZE) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._enqueue_count: int = 0
        self._drop_count: int = 0

    def put_nowait(self, item: object) -> None:
        """Enqueue a packet without blocking. Drops silently if full."""
        try:
            self._queue.put_nowait(item)
            self._enqueue_count += 1
        except queue.Full:
            self._drop_count += 1

    def get(self, timeout: float | None = None) -> object:
        """Dequeue a packet, blocking until one is available or timeout expires.

        Raises queue.Empty if timeout expires before a packet arrives.

        Args:
            timeout: Seconds to wait before raising queue.Empty. None = block forever.
        """
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        """Signal that a formerly enqueued packet has been processed."""
        self._queue.task_done()

    @property
    def enqueue_count(self) -> int:
        """Total packets successfully enqueued."""
        return self._enqueue_count

    @property
    def drop_count(self) -> int:
        """Total packets dropped due to queue saturation."""
        return self._drop_count

    @property
    def drop_rate(self) -> float:
        """Percentage of packets dropped due to queue saturation."""
        total = self._enqueue_count + self._drop_count
        return (self._drop_count / total * 100) if total > 0 else 0.0

    @property
    def qsize(self) -> int:
        """Approximate number of packets waiting in the queue.

        Not guaranteed to be exact in multithreaded contexts — use for
        health monitoring only, not for flow control decisions.
        """
        return self._queue.qsize()
