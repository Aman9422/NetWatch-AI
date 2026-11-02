"""Unit tests for packet retention (M7.13/M7.14/M7.19/M7.23).

Retention is the only code in M7 that deletes data, so these tests are written
around safety: it must delete rows *strictly older* than the configured window,
never touch recent rows, do nothing at the boundary, be disabled by a zero
window, and swallow a database failure instead of disturbing capture.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.persistence.retention import (
    RETENTION_FAILURE_MESSAGE,
    PacketRetentionService,
)
from app.repositories.packet import PacketRepository

# A fixed "now" so every assertion is deterministic.
NOW = datetime(2025, 1, 31, 12, 0, 0, tzinfo=timezone.utc)

# The retention window used by most of the tests.
RETENTION_DAYS = 7


def _row(ts: datetime, source_ip: str = "10.0.0.1") -> dict[str, object]:
    """Build a minimal but complete ``packets`` row with a given timestamp."""
    return {
        "timestamp": ts,
        "source_ip": source_ip,
        "destination_ip": "10.0.0.2",
        "source_port": None,
        "destination_port": None,
        "protocol": "TCP",
        "packet_length": 100,
        "tcp_flags": None,
        "ttl": None,
        "payload_length": None,
        "device_id": None,
        "processed": 0,
    }


def _seed(session_factory, timestamps: list[datetime]) -> None:
    """Insert one packet row per timestamp."""
    session: Session = session_factory()
    try:
        PacketRepository(session).write_batch([_row(ts) for ts in timestamps])
    finally:
        session.close()


def _count(session_factory) -> int:
    """Return how many packet rows remain."""
    session: Session = session_factory()
    try:
        return PacketRepository(session).count()
    finally:
        session.close()


def _service(session_factory, retention_days: int = RETENTION_DAYS):
    """Build a retention service pointed at the isolated database."""
    return PacketRetentionService(
        session_factory=session_factory, retention_days=retention_days
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_negative_retention_is_rejected(session_factory) -> None:
    """A negative window is a configuration error."""
    with pytest.raises(ValueError):
        _service(session_factory, retention_days=-1)


def test_retention_days_is_exposed(session_factory) -> None:
    """The configured window is readable."""
    assert _service(session_factory, retention_days=14).retention_days == 14


def test_zero_retention_disables_cleanup(session_factory) -> None:
    """A zero window means "keep forever": nothing is ever deleted."""
    service = _service(session_factory, retention_days=0)
    _seed(session_factory, [NOW - timedelta(days=365)])

    assert service.is_enabled() is False
    assert service.cleanup(now=NOW) == 0
    assert _count(session_factory) == 1


def test_cutoff_is_now_minus_the_window(session_factory) -> None:
    """The cutoff is exactly ``now - retention_days``."""
    service = _service(session_factory)

    assert service.cutoff(now=NOW) == NOW - timedelta(days=RETENTION_DAYS)


# ---------------------------------------------------------------------------
# Cleanup (M7.13)
# ---------------------------------------------------------------------------


def test_old_packets_are_deleted_and_recent_are_kept(session_factory) -> None:
    """Only rows older than the window are removed."""
    service = _service(session_factory)
    _seed(
        session_factory,
        [
            NOW - timedelta(days=10),  # eligible
            NOW - timedelta(days=8),   # eligible
            NOW - timedelta(days=3),   # recent
            NOW,                       # recent
        ],
    )

    deleted = service.cleanup(now=NOW)

    assert deleted == 2
    assert _count(session_factory) == 2


def test_boundary_packet_is_preserved(session_factory) -> None:
    """A packet exactly at the cutoff is kept (strict ``<`` comparison)."""
    service = _service(session_factory)
    _seed(session_factory, [NOW - timedelta(days=RETENTION_DAYS)])

    assert service.cleanup(now=NOW) == 0
    assert _count(session_factory) == 1


def test_cleanup_on_an_empty_database_is_safe(session_factory) -> None:
    """Cleanup tolerates an empty table."""
    assert _service(session_factory).cleanup(now=NOW) == 0


def test_repeated_cleanup_is_idempotent(session_factory) -> None:
    """A second cleanup finds nothing left to delete."""
    service = _service(session_factory)
    _seed(session_factory, [NOW - timedelta(days=30)])

    assert service.cleanup(now=NOW) == 1
    assert service.cleanup(now=NOW) == 0


def test_cleanup_failure_is_isolated(session_factory) -> None:
    """A database error during cleanup returns 0 instead of raising (M7.14)."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        service = PacketRetentionService(
            session_factory=lambda: Session(bind=engine),
            retention_days=RETENTION_DAYS,
        )
        # No tables exist on this engine, so the DELETE statement must fail.
        assert service.cleanup(now=NOW) == 0
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Honest outcomes (M19.3/M19.5)
# ---------------------------------------------------------------------------


def _failing_engine():
    """Return an engine with no tables, so any DELETE against it fails."""
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def test_a_measured_zero_is_not_a_failure(session_factory) -> None:
    """A cleanup that read the store and found nothing is a success (M19.5)."""
    outcome = _service(session_factory).cleanup_outcome(now=NOW)

    assert outcome.deleted == 0
    assert outcome.failed is False
    assert outcome.succeeded is True
    assert outcome.removed_anything is False
    assert outcome.error is None
    assert outcome.enabled is True


def test_a_successful_cleanup_reports_what_it_removed(session_factory) -> None:
    """The outcome carries the deleted count and no error."""
    _seed(session_factory, [NOW - timedelta(days=10), NOW - timedelta(days=9)])

    outcome = _service(session_factory).cleanup_outcome(now=NOW)

    assert outcome.deleted == 2
    assert outcome.removed_anything is True
    assert outcome.failed is False
    assert outcome.error is None


def test_disabled_retention_reports_a_measured_zero(session_factory) -> None:
    """A disabled policy answers ``enabled=False`` rather than looking failed."""
    service = _service(session_factory, retention_days=0)
    _seed(session_factory, [NOW - timedelta(days=365)])

    outcome = service.cleanup_outcome(now=NOW)

    assert outcome.deleted == 0
    assert outcome.failed is False
    assert outcome.enabled is False
    assert _count(session_factory) == 1


def test_a_failed_cleanup_is_reported_as_a_failure(session_factory) -> None:
    """A store that cannot be read is a failure, not an indistinguishable zero.

    This is the defect M19.5 records: M7's ``cleanup`` returned ``0`` whether the
    store said "nothing to delete" or could not be read at all, so a retention
    policy that had silently stopped working looked exactly like a healthy one.
    """
    engine = _failing_engine()
    try:
        service = PacketRetentionService(
            session_factory=lambda: Session(bind=engine),
            retention_days=RETENTION_DAYS,
        )

        outcome = service.cleanup_outcome(now=NOW)

        assert outcome.failed is True
        assert outcome.succeeded is False
        assert outcome.deleted == 0
        assert outcome.error == RETENTION_FAILURE_MESSAGE
        # The count is still 0, because nothing is known to have been removed.
        assert service.cleanup(now=NOW) == 0
    finally:
        engine.dispose()


def test_failures_are_counted_across_attempts(session_factory) -> None:
    """Each failed attempt is counted, so a stopped policy is observable (M19.3)."""
    engine = _failing_engine()
    try:
        service = PacketRetentionService(
            session_factory=lambda: Session(bind=engine),
            retention_days=RETENTION_DAYS,
        )

        assert service.failure_count == 0
        service.cleanup(now=NOW)
        service.cleanup_outcome(now=NOW)

        assert service.failure_count == 2
    finally:
        engine.dispose()


def test_a_success_does_not_count_as_a_failure(session_factory) -> None:
    """A cleanup that worked never increments the failure counter."""
    service = _service(session_factory)
    _seed(session_factory, [NOW - timedelta(days=10)])

    service.cleanup(now=NOW)

    assert service.failure_count == 0


def test_the_failure_message_names_no_internal(session_factory) -> None:
    """The safe sentence cannot leak a path, a statement or a driver (M13.30).

    The check is for *internals*, not for English: the sentence says nothing was
    deleted, which is a fact about the operation rather than a disclosure.
    """
    lowered = RETENTION_FAILURE_MESSAGE.lower()

    leaks = (
        "sqlite",
        "traceback",
        "operationalerror",
        "no such table",
        "delete from",
        "select ",
        "c:\\",
        "/app",
        "/backend",
    )
    for leak in leaks:
        assert leak not in lowered
