"""Unit tests for the PacketPersistence facade (M7.4/M7.6/M7.7/M7.11/M7.19).

The facade is what the packet pipeline actually calls, so these tests pin down
its contract from the capture thread's point of view: ``record_packet`` maps and
buffers without ever blocking or raising, skips packets that cannot be stored
without inventing data, keeps the buffer bounded, and flushes pending rows on
stop and shutdown.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.persistence.manager import PacketPersistence
from app.repositories.packet import PacketRepository
from tests.fakes import make_normalized_packet


def _count(session_factory) -> int:
    """Return how many packet rows are in the database."""
    session: Session = session_factory()
    try:
        return PacketRepository(session).count()
    finally:
        session.close()


def _persistence(session_factory, **overrides) -> PacketPersistence:
    """Build a non-autostarting facade so writes happen only on ``flush``."""
    options: dict = {
        "session_factory": session_factory,
        "autostart": False,
        "batch_size": 100,
        "flush_interval": 60.0,
    }
    options.update(overrides)
    return PacketPersistence(**options)


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_batch_size_must_be_positive(session_factory) -> None:
    """A nonsensical batch size is rejected at construction."""
    with pytest.raises(ValueError):
        _persistence(session_factory, batch_size=0)


def test_flush_interval_must_be_positive(session_factory) -> None:
    """A nonsensical flush interval is rejected at construction."""
    with pytest.raises(ValueError):
        _persistence(session_factory, flush_interval=0)


def test_queue_max_must_be_positive(session_factory) -> None:
    """A nonsensical queue capacity is rejected at construction."""
    with pytest.raises(ValueError):
        _persistence(session_factory, queue_max=0)


def test_queue_max_is_exposed(session_factory) -> None:
    """The configured capacity is readable for diagnostics."""
    assert _persistence(session_factory, queue_max=42).get_queue_max() == 42


# ---------------------------------------------------------------------------
# Ingestion (M7.4)
# ---------------------------------------------------------------------------


def test_ip_packet_is_accepted_and_buffered(session_factory) -> None:
    """A packet with both endpoints is accepted into the buffer."""
    persistence = _persistence(session_factory)

    accepted = persistence.record_packet(make_normalized_packet())

    assert accepted is True
    assert persistence.get_enqueued_count() == 1
    assert persistence.get_queue_depth() == 1
    assert persistence.get_skipped_count() == 0


def test_packet_without_ip_is_skipped_not_invented(session_factory) -> None:
    """A packet with no IP address is skipped rather than stored (M7.2)."""
    persistence = _persistence(session_factory)

    accepted = persistence.record_packet(make_normalized_packet(source_ip=None))

    assert accepted is False
    assert persistence.get_enqueued_count() == 0
    assert persistence.get_skipped_count() == 1


def test_disabled_persistence_accepts_nothing(session_factory) -> None:
    """The master switch refuses every packet and buffers nothing."""
    persistence = _persistence(session_factory, enabled=False)

    assert persistence.record_packet(make_normalized_packet()) is False
    assert persistence.is_enabled() is False
    assert persistence.get_enqueued_count() == 0


def test_mapping_failure_is_isolated_and_counted(session_factory, monkeypatch) -> None:
    """A mapping exception never propagates to the capture thread (M7.11)."""
    persistence = _persistence(session_factory)

    def _boom(_packet) -> None:
        raise RuntimeError("simulated mapping failure")

    monkeypatch.setattr("app.persistence.manager.to_packet_values", _boom)

    assert persistence.record_packet(make_normalized_packet()) is False
    assert persistence.get_mapping_error_count() == 1
    assert persistence.get_enqueued_count() == 0


# ---------------------------------------------------------------------------
# Bounded buffer (M7.9)
# ---------------------------------------------------------------------------


def test_buffer_is_bounded(session_factory) -> None:
    """The buffer never holds more than ``queue_max`` packets."""
    persistence = _persistence(session_factory, queue_max=3)

    for _ in range(10):
        persistence.record_packet(make_normalized_packet())

    assert persistence.get_queue_depth() == 3
    assert persistence.get_dropped_count() == 7


# ---------------------------------------------------------------------------
# Flush (M7.7)
# ---------------------------------------------------------------------------


def test_flush_writes_buffered_packets(session_factory) -> None:
    """An explicit flush drains the buffer into the database."""
    persistence = _persistence(session_factory)
    for _ in range(4):
        persistence.record_packet(make_normalized_packet())

    written = persistence.flush()

    assert written == 4
    assert persistence.get_persisted_count() == 4
    assert persistence.get_queue_depth() == 0
    assert _count(session_factory) == 4


def test_flush_of_empty_buffer_writes_nothing(session_factory) -> None:
    """Flushing nothing is a harmless no-op that does not record a flush."""
    persistence = _persistence(session_factory)

    assert persistence.flush() == 0
    assert persistence.get_last_flush_at() is None

    # A flush that actually writes a row is what stamps the flush time.
    persistence.record_packet(make_normalized_packet())
    assert persistence.flush() == 1
    assert persistence.get_last_flush_at() is not None


def test_autostart_only_starts_the_worker_on_first_packet(session_factory) -> None:
    """A facade that is never fed never starts its background thread."""
    persistence = PacketPersistence(
        session_factory=session_factory, autostart=True, flush_interval=60.0
    )

    assert persistence.is_running() is False
    persistence.record_packet(make_normalized_packet())
    assert persistence.is_running() is True
    persistence.stop()


# ---------------------------------------------------------------------------
# Stop / shutdown (M7.18)
# ---------------------------------------------------------------------------


def test_stop_flushes_pending_packets(session_factory) -> None:
    """Stopping writes whatever is buffered."""
    persistence = _persistence(session_factory)
    for _ in range(2):
        persistence.record_packet(make_normalized_packet())

    written = persistence.stop(flush=True)

    assert written == 2
    assert _count(session_factory) == 2


def test_shutdown_flushes_and_disables(session_factory) -> None:
    """Shutdown writes pending packets and stops accepting new ones."""
    persistence = _persistence(session_factory)
    persistence.record_packet(make_normalized_packet())

    persistence.shutdown()

    assert _count(session_factory) == 1
    assert persistence.is_enabled() is False
    assert persistence.record_packet(make_normalized_packet()) is False


# ---------------------------------------------------------------------------
# Failure isolation (M7.11)
# ---------------------------------------------------------------------------


def test_database_failure_is_isolated() -> None:
    """A database error is counted, logged and swallowed — never raised."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        persistence = _persistence(lambda: Session(bind=engine))
        for _ in range(3):
            assert persistence.record_packet(make_normalized_packet()) is True

        written = persistence.flush()

        assert written == 0
        assert persistence.get_persisted_count() == 0
        assert persistence.get_failed_count() == 3
    finally:
        engine.dispose()
