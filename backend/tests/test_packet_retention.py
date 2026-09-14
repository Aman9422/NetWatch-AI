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

from app.persistence.retention import PacketRetentionService
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
