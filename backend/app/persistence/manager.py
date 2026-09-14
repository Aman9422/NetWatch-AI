"""PacketPersistence: the M7 facade the packet pipeline talks to.

The facade ties the three M7 pieces together and owns their lifecycle:

    PacketPersistence            (this module)
        ↓ maps NormalizedPacket  (mapping.py)
    BoundedPacketBuffer          (buffer.py)   — bounded, non-blocking
        ↓ drained by
    PacketPersistenceWorker      (worker.py)   — batch writes + transactions
        ↓ uses
    PacketRepository             → SQLite

``record_packet`` is designed to be called from the capture thread: it maps the
packet, hands the result to the buffer and returns. It **never raises and never
blocks on the database** (M7.8/M7.11), so a database problem can never stop
capture, statistics or device discovery (M7.17).
"""

from __future__ import annotations

import logging
import threading
import time

from app.persistence.buffer import DEFAULT_QUEUE_MAX, BoundedPacketBuffer
from app.persistence.mapping import to_packet_values
from app.persistence.session_factory import SessionFactory, app_session_factory
from app.persistence.worker import PacketPersistenceWorker
from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)

# Defaults mirror ``app.config.settings`` so the class is usable stand-alone.
DEFAULT_BATCH_SIZE = 500
DEFAULT_FLUSH_INTERVAL_SECONDS = 2.0


class PacketPersistence:
    """Maps, buffers and batch-writes normalized packet metadata (M7.4-M7.11)."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
        enabled: bool = True,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        queue_max: int = DEFAULT_QUEUE_MAX,
        autostart: bool = True,
    ) -> None:
        """Create the persistence layer.

        Args:
            session_factory: Builds database sessions. Defaults to the
                application factory; tests inject an isolated one.
            enabled: When False every packet is refused and nothing is written.
            batch_size: Rows per transaction (M7.6).
            flush_interval: Seconds a buffered packet may wait (M7.6).
            queue_max: Hard cap on buffered packets (M7.9).
            autostart: When True the worker thread starts on the first packet;
                tests that want deterministic writes pass False and call
                :meth:`flush` explicitly.

        Raises:
            ValueError: If any numeric argument is out of range.
        """
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if flush_interval <= 0:
            raise ValueError("flush_interval must be positive")
        if queue_max < 1:
            raise ValueError("queue_max must be at least 1")

        self._enabled = enabled
        self._autostart = autostart
        self._session_factory = session_factory or app_session_factory
        self._buffer = BoundedPacketBuffer(queue_max)
        self._worker = PacketPersistenceWorker(
            session_factory=self._session_factory,
            buffer=self._buffer,
            batch_size=batch_size,
            flush_interval=flush_interval,
        )

        self._lifecycle_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._started = False
        self._enqueued = 0
        self._skipped = 0
        self._mapping_errors = 0
        self._last_flush_at: float | None = None

    # -- ingestion (capture thread) ---------------------------------------

    def record_packet(self, packet: NormalizedPacket) -> bool:
        """Map and buffer one normalized packet (M7.4).

        This is the only method the packet pipeline calls. It never raises and
        never blocks on the database.

        Returns:
            True when the packet was accepted for persistence, False when it was
            skipped (no IP address) or persistence is disabled.
        """
        if not self._enabled:
            return False
        try:
            values = to_packet_values(packet)
        except Exception:  # noqa: BLE001 - mapping must never stop capture
            with self._counter_lock:
                self._mapping_errors += 1
            logger.exception("Packet could not be mapped for persistence")
            return False
        if values is None:
            with self._counter_lock:
                self._skipped += 1
            return False

        self._ensure_worker_started()
        self._buffer.put(values)
        with self._counter_lock:
            self._enqueued += 1
        return True

    # -- lifecycle (M7.7 / M7.18) -----------------------------------------

    def start(self) -> None:
        """Start the background worker explicitly."""
        with self._lifecycle_lock:
            self._worker.start()
            self._started = True

    def flush(self) -> int:
        """Write every buffered packet now (M7.7).

        Used on capture stop, on shutdown and explicitly from tests.

        Returns:
            How many rows were written.
        """
        written = self._worker.flush()
        if written:
            self._last_flush_at = time.time()
        return written

    def stop(self, *, flush: bool = True) -> int:
        """Stop the worker, flushing pending packets first (M7.18).

        Returns:
            How many rows the final flush wrote.
        """
        with self._lifecycle_lock:
            written = self._worker.stop(drain=flush)
            self._started = False
        if written:
            self._last_flush_at = time.time()
        return written

    def shutdown(self) -> None:
        """Stop accepting packets, flush what is pending, stop the worker (M7.18)."""
        self._enabled = False
        written = self.stop(flush=True)
        logger.info("Packet persistence shut down (%d packet(s) flushed)", written)

    def _ensure_worker_started(self) -> None:
        """Start the worker lazily on first use, unless autostart is disabled."""
        if not self._autostart or self._started:
            return
        with self._lifecycle_lock:
            if self._started:
                return
            self._worker.start()
            self._started = True

    # -- diagnostics ------------------------------------------------------

    def is_enabled(self) -> bool:
        """Return True when the layer accepts packets."""
        return self._enabled

    def is_running(self) -> bool:
        """Return True while the background worker is alive."""
        return self._worker.is_running()

    def get_enqueued_count(self) -> int:
        """Return how many packets were accepted into the buffer."""
        with self._counter_lock:
            return self._enqueued

    def get_skipped_count(self) -> int:
        """Return how many packets were skipped (no IP address)."""
        with self._counter_lock:
            return self._skipped

    def get_mapping_error_count(self) -> int:
        """Return how many packets failed to map."""
        with self._counter_lock:
            return self._mapping_errors

    def get_persisted_count(self) -> int:
        """Return how many packets reached the database."""
        return self._worker.get_persisted_count()

    def get_failed_count(self) -> int:
        """Return how many packets were dropped by a failed batch."""
        return self._worker.get_failed_count()

    def get_batch_count(self) -> int:
        """Return how many transactions have committed."""
        return self._worker.get_batch_count()

    def get_dropped_count(self) -> int:
        """Return how many packets were evicted because the buffer was full."""
        return self._buffer.dropped_count()

    def get_queue_depth(self) -> int:
        """Return how many packets are buffered but not yet written."""
        return self._buffer.size()

    def get_queue_max(self) -> int:
        """Return the buffer capacity."""
        return self._buffer.max_size

    def get_last_flush_at(self) -> float | None:
        """Return the wall-clock time of the last flush that wrote rows, or None.

        A no-op flush (empty buffer) leaves this untouched, so the value always
        marks the last time packet data actually reached the database through
        this facade.
        """
        return self._last_flush_at


# Shared singleton used by the application at runtime.
_packet_persistence: PacketPersistence | None = None


def get_packet_persistence() -> PacketPersistence:
    """Return the process-wide packet persistence layer, creating it on first use."""
    global _packet_persistence
    if _packet_persistence is None:
        from app.config.settings import settings

        _packet_persistence = PacketPersistence(
            enabled=settings.packet_persistence_enabled,
            batch_size=settings.packet_batch_size,
            flush_interval=settings.packet_flush_interval_seconds,
            queue_max=settings.packet_queue_max,
        )
    return _packet_persistence
