"""Background packet persistence worker (M7.8 / M7.10 / M7.11).

A single daemon thread drains the bounded buffer and writes packets to SQLite in
batches, so the capture thread never waits on the database (M7.8).

Failure policy (M7.11): a batch that fails is rolled back inside the repository
— so the database is never left partially written (M7.10) — then *counted and
logged* and dropped. A failing batch is deliberately **not** requeued: retrying
a permanently-failing batch would spin forever and let the buffer grow, whereas
dropping it keeps capture, statistics and device discovery running while the
loss stays visible in the counters and the log.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Sequence

from app.persistence.buffer import BoundedPacketBuffer, PacketRow
from app.persistence.session_factory import SessionFactory
from app.repositories.packet import PacketRepository

logger = logging.getLogger(__name__)

# How long ``stop`` waits for the worker thread to finish before giving up.
_STOP_TIMEOUT_SECONDS = 5.0


class PacketPersistenceWorker:
    """Writes buffered packets to the database in batches, off the capture thread."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        buffer: BoundedPacketBuffer,
        batch_size: int,
        flush_interval: float,
    ) -> None:
        """Create the worker.

        Args:
            session_factory: Callable returning a new SQLAlchemy ``Session``.
                A session is created per batch because SQLAlchemy sessions are
                not thread-safe.
            buffer: The shared bounded buffer to drain.
            batch_size: Maximum rows written per transaction (M7.6).
            flush_interval: Maximum seconds a buffered packet waits before it is
                written (M7.6/M7.7).

        Raises:
            ValueError: If ``batch_size`` or ``flush_interval`` is not positive.
        """
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if flush_interval <= 0:
            raise ValueError("flush_interval must be positive")

        self._session_factory = session_factory
        self._buffer = buffer
        self._batch_size = batch_size
        self._flush_interval = flush_interval

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._start_lock = threading.Lock()
        # Held while popping from the buffer *and* writing, so a manual flush
        # from another thread can never interleave with a worker write.
        self._write_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._persisted = 0
        self._failed = 0
        self._batch_count = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Start the worker thread (idempotent)."""
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run, name="packet-persistence", daemon=True
            )
            self._thread.start()

    def stop(self, *, drain: bool = True) -> int:
        """Stop the worker, optionally draining first (M7.7/M7.18).

        Args:
            drain: When True (the default) every buffered packet is written
                before returning, so a normal shutdown never silently loses
                accepted packets.

        Returns:
            How many rows the final flush wrote (0 when ``drain`` is False).
        """
        self._stop_event.set()
        self._buffer.wake()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=_STOP_TIMEOUT_SECONDS)
        if not drain:
            return 0
        if thread is not None and thread.is_alive():
            # The worker is wedged (for example inside a stuck database call)
            # and still holds the write lock; flushing here would block forever.
            logger.warning(
                "Persistence worker did not stop in time; skipping final flush"
            )
            return 0
        return self.flush()

    def is_running(self) -> bool:
        """Return True while the worker thread is alive."""
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def flush(self) -> int:
        """Write every currently buffered packet, newest last; return rows written."""
        return self._drain_all()

    # -- worker loop ------------------------------------------------------

    def _run(self) -> None:
        """Write batches until asked to stop.

        The stop flag is re-checked *after* the buffer wait returns, so a
        shutdown that wakes the thread does not race a stray final write: the
        thread breaks out and :meth:`stop` performs the drain on the caller's
        thread, which keeps the returned count correct and honours
        ``drain=False``.
        """
        while not self._stop_event.is_set():
            self._buffer.wait_for_item(self._flush_interval)
            if self._stop_event.is_set():
                break
            self._write_one_batch()

    def _write_one_batch(self) -> int:
        """Write at most ``batch_size`` buffered rows."""
        with self._write_lock:
            batch = self._buffer.get_batch(self._batch_size)
            return self._write(batch)

    def _drain_all(self) -> int:
        """Write everything currently buffered, in ``batch_size`` chunks."""
        written = 0
        with self._write_lock:
            while True:
                batch = self._buffer.get_batch(self._batch_size)
                if not batch:
                    break
                written += self._write(batch)
        return written

    def _write(self, batch: Sequence[PacketRow]) -> int:
        """Persist one batch in its own transaction, isolating failures."""
        if not batch:
            return 0
        session = self._session_factory()
        try:
            written = PacketRepository(session).write_batch(batch)
        except Exception:  # noqa: BLE001 - a DB failure must not stop capture
            self._record_failure(len(batch))
            return 0
        finally:
            session.close()
        self._record_success(written)
        return written

    # -- counters ---------------------------------------------------------

    def _record_success(self, written: int) -> None:
        """Count a successful batch."""
        with self._counter_lock:
            self._persisted += written
            self._batch_count += 1

    def _record_failure(self, dropped: int) -> None:
        """Count and log a failed batch (its packets are dropped)."""
        with self._counter_lock:
            self._failed += dropped
        logger.exception(
            "Packet batch write failed; %d buffered packet(s) dropped. "
            "Capture continues.",
            dropped,
        )

    def get_persisted_count(self) -> int:
        """Return how many packets have been written to the database."""
        with self._counter_lock:
            return self._persisted

    def get_failed_count(self) -> int:
        """Return how many packets were dropped because their batch failed."""
        with self._counter_lock:
            return self._failed

    def get_batch_count(self) -> int:
        """Return how many transactions have been committed."""
        with self._counter_lock:
            return self._batch_count
