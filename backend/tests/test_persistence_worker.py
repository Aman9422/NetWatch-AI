"""Unit tests for the background persistence worker (M7.6-M7.11/M7.19).

The worker owns the batch/flush/transaction behaviour, so these tests cover the
write path directly against an isolated in-memory database: explicit and
interval-driven flushes, batch chunking, drain-on-stop, and — critically — that
a database failure is counted and isolated instead of propagating.
"""

from __future__ import annotations

import time

from sqlalchemy.orm import Session

from app.persistence.buffer import BoundedPacketBuffer
from app.persistence.mapping import to_packet_values
from app.persistence.worker import PacketPersistenceWorker
from app.repositories.packet import PacketRepository
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet


def _row(offset: float = 0.0) -> dict[str, object]:
    """Map a normalized packet onto a storable row with a shifted timestamp."""
    packet = make_normalized_packet(timestamp=PACKET_BASE_TIME + offset)
    values = to_packet_values(packet)
    assert values is not None
    return values


def _make_worker(
    session_factory,
    buffer: BoundedPacketBuffer,
    *,
    batch_size: int = 100,
    flush_interval: float = 0.05,
) -> PacketPersistenceWorker:
    """Build a worker wired to the given factory and buffer."""
    return PacketPersistenceWorker(
        session_factory=session_factory,
        buffer=buffer,
        batch_size=batch_size,
        flush_interval=flush_interval,
    )


def _count(session_factory) -> int:
    """Return how many packet rows are in the database."""
    session: Session = session_factory()
    try:
        return PacketRepository(session).count()
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_batch_size_must_be_positive(session_factory) -> None:
    """A nonsensical batch size is rejected at construction."""
    import pytest

    with pytest.raises(ValueError):
        _make_worker(session_factory, BoundedPacketBuffer(10), batch_size=0)


def test_flush_interval_must_be_positive(session_factory) -> None:
    """A nonsensical flush interval is rejected at construction."""
    import pytest

    with pytest.raises(ValueError):
        _make_worker(session_factory, BoundedPacketBuffer(10), flush_interval=0)


# ---------------------------------------------------------------------------
# Explicit flush
# ---------------------------------------------------------------------------


def test_flush_writes_every_buffered_row(session_factory) -> None:
    """An explicit flush drains the buffer into the database."""
    buffer = BoundedPacketBuffer(100)
    for offset in range(4):
        buffer.put(_row(offset))
    worker = _make_worker(session_factory, buffer)

    written = worker.flush()

    assert written == 4
    assert _count(session_factory) == 4
    assert buffer.size() == 0


def test_flush_of_an_empty_buffer_writes_nothing(session_factory) -> None:
    """Flushing nothing is a no-op that commits no transaction."""
    worker = _make_worker(session_factory, BoundedPacketBuffer(10))

    assert worker.flush() == 0
    assert worker.get_batch_count() == 0


def test_flush_chunks_writes_by_batch_size(session_factory) -> None:
    """Rows are written in batches no larger than ``batch_size``."""
    buffer = BoundedPacketBuffer(100)
    for offset in range(5):
        buffer.put(_row(offset))
    worker = _make_worker(session_factory, buffer, batch_size=2)

    written = worker.flush()

    assert written == 5
    assert worker.get_batch_count() == 3  # 2 + 2 + 1
    assert _count(session_factory) == 5


def test_flush_counts_persisted_packets(session_factory) -> None:
    """The persisted counter tracks rows that reached the database."""
    buffer = BoundedPacketBuffer(100)
    for offset in range(3):
        buffer.put(_row(offset))
    worker = _make_worker(session_factory, buffer)

    worker.flush()

    assert worker.get_persisted_count() == 3
    assert worker.get_failed_count() == 0


# ---------------------------------------------------------------------------
# Lifecycle: start / interval flush / stop
# ---------------------------------------------------------------------------


def test_start_marks_the_worker_running(session_factory) -> None:
    """A started worker reports itself as running."""
    worker = _make_worker(session_factory, BoundedPacketBuffer(10))

    worker.start()
    try:
        assert worker.is_running() is True
    finally:
        worker.stop()


def test_interval_writes_buffered_rows_without_an_explicit_flush(
    session_factory,
) -> None:
    """A buffered row is written once the flush interval elapses (M7.7)."""
    buffer = BoundedPacketBuffer(100)
    worker = _make_worker(session_factory, buffer, flush_interval=0.05)
    worker.start()
    try:
        buffer.put(_row())

        # Wait on the worker's own atomic counter rather than polling the
        # database. The worker writes on its own thread but, in tests, every
        # session shares the single StaticPool connection of the in-memory
        # database; reading from that one connection while the worker inserts
        # can make the worker's transaction fail and its batch be dropped (the
        # intended M7.11 policy), which would lose the very row being awaited.
        # The counter is updated on the worker thread after its session closes,
        # so once it reports a commit the connection is free to read safely.
        deadline = time.time() + 2.0
        while worker.get_persisted_count() == 0 and time.time() < deadline:
            time.sleep(0.02)

        assert worker.get_persisted_count() == 1
        assert worker.get_failed_count() == 0
        assert _count(session_factory) == 1
    finally:
        worker.stop()


def test_stop_drains_pending_rows(session_factory) -> None:
    """Stopping with pending rows flushes them rather than losing them (M7.18)."""
    buffer = BoundedPacketBuffer(100)
    worker = _make_worker(session_factory, buffer, flush_interval=60.0)
    worker.start()
    for offset in range(3):
        buffer.put(_row(offset))

    written = worker.stop(drain=True)

    assert written == 3
    assert _count(session_factory) == 3
    assert worker.is_running() is False


def test_stop_without_drain_leaves_rows_buffered(session_factory) -> None:
    """``drain=False`` stops the worker without writing (explicit opt-out)."""
    buffer = BoundedPacketBuffer(100)
    worker = _make_worker(session_factory, buffer, flush_interval=60.0)
    worker.start()
    buffer.put(_row())

    written = worker.stop(drain=False)

    assert written == 0
    assert buffer.size() == 1


# ---------------------------------------------------------------------------
# Error isolation (M7.11)
# ---------------------------------------------------------------------------


def test_failed_batch_is_counted_and_dropped(session_factory) -> None:
    """A batch the database rejects is counted, logged and dropped.

    ``source_ip`` is NOT NULL, so the batch fails. The worker must not raise;
    it records the loss so the failure stays observable while capture continues.
    """
    buffer = BoundedPacketBuffer(100)
    bad_row = {**_row(0), "source_ip": None}
    buffer.put(bad_row)
    buffer.put(_row(1))
    worker = _make_worker(session_factory, buffer, batch_size=10)

    written = worker.flush()

    # The whole batch failed together, so nothing was written.
    assert written == 0
    assert worker.get_persisted_count() == 0
    assert worker.get_failed_count() == 2
    assert _count(session_factory) == 0


def test_worker_recovers_after_a_failed_batch(session_factory) -> None:
    """A subsequent valid batch is written normally after a failure."""
    buffer = BoundedPacketBuffer(100)
    worker = _make_worker(session_factory, buffer, batch_size=10)

    buffer.put({**_row(0), "source_ip": None})
    worker.flush()

    buffer.put(_row(1))
    written = worker.flush()

    assert written == 1
    assert _count(session_factory) == 1
    assert worker.get_failed_count() == 1
