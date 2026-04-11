from __future__ import annotations

import queue
import threading

import config


class PacketQueue:
    """Thread-safe bounded queue between the sniffer and analysis threads.

    If the queue is full (analysis thread falling behind), put_nowait()
    drops the packet and increments the drop counter rather than blocking
    or consuming unbounded memory. This is intentional.
    """

    def __init__(self, maxsize: int = config.QUEUE_MAXSIZE) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._enqueue_count: int = 0
        self._drop_count: int = 0
        self._stats_lock: threading.Lock = threading.Lock()

    def put_nowait(self, item: object) -> None:
        """Enqueue a packet without blocking. Drops silently if full."""
        try:
            self._queue.put_nowait(item)
            with self._stats_lock:
                self._enqueue_count += 1
        except queue.Full:
            with self._stats_lock:
                self._drop_count += 1

    def get(self) -> object:
        """Dequeue a packet, blocking until one is available."""
        return self._queue.get()

    def task_done(self) -> None:
        """Signal that a formerly enqueued packet has been processed."""
        self._queue.task_done()

    def drain(self) -> None:
        """Drain all remaining items from the queue (used on shutdown)."""
        while True:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                break

    @property
    def enqueue_count(self) -> int:
        """Total packets successfully enqueued."""
        with self._stats_lock:
            return self._enqueue_count

    @property
    def drop_count(self) -> int:
        """Total packets dropped due to queue saturation."""
        with self._stats_lock:
            return self._drop_count

    @property
    def drop_rate(self) -> float:
        """Percentage of packets dropped due to queue saturation."""
        with self._stats_lock:
            total = self._enqueue_count + self._drop_count
            return (self._drop_count / total * 100) if total > 0 else 0.0

    @property
    def qsize(self) -> int:
        """Approximate number of packets waiting in the queue.

        Not guaranteed to be exact in multithreaded contexts — use for
        health monitoring only, not for flow control decisions.
        """
        return self._queue.qsize()
