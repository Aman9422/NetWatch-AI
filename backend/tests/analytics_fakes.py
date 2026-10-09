"""Builders for the M16 analytics tests.

The analytics layer reads three persisted tables (``packets``, ``connections``,
``alerts``), so the tests need a way to place a *known* row into a table without
going through the milestone that normally writes it. That is what this module
provides: one seeder per table, each taking an offset in seconds from a shared
base instant so a window can be placed around the rows deliberately.

Two conventions the assertions depend on: every row is placed at a whole-second
offset from ``PACKET_BASE_TIME``, so a bucket boundary never falls inside a row's
instant; and every seeder writes through the real store (the M7 repository for
packets, the ORM for the two tables M9 and M11 own), so a test asserts against
the same columns a production write would produce.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.analytics.window import AnalyticsWindow
from app.models.alert import Alert
from app.models.connection import NetworkConnection
from app.persistence.mapping import to_packet_values
from app.repositories.packet import PacketRepository
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet

#: Inclusive start of the window the analytics tests read over.
WINDOW_START = PACKET_BASE_TIME
#: Exclusive end of that window: ten minutes later, so it holds ten 60-second
#: buckets and dozens of whole-second insertion points.
WINDOW_END = PACKET_BASE_TIME + 600.0
#: The bucket size the tests use unless they are exercising the choice itself.
WINDOW_BUCKET_SECONDS = 60


def make_window(
    *,
    since: float = WINDOW_START,
    until: float = WINDOW_END,
    bucket_seconds: int = WINDOW_BUCKET_SECONDS,
    defaulted: bool = False,
) -> AnalyticsWindow:
    """Return a resolved window over the test's base instant."""
    return AnalyticsWindow(
        since=since,
        until=until,
        bucket_seconds=bucket_seconds,
        defaulted=defaulted,
    )


def utc(epoch: float) -> datetime:
    """Return the naive UTC datetime a store column holds for ``epoch``.

    SQLite keeps a ``DateTime`` column as a UTC wall-clock value with no offset,
    which is what every M16 query filters against.
    """
    return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)


def seed_packet(session: Session, *, offset: float = 0.0, **overrides: Any) -> None:
    """Store one normalized packet ``offset`` seconds into the test window."""
    packet = make_normalized_packet(timestamp=PACKET_BASE_TIME + offset, **overrides)
    values = to_packet_values(packet)
    assert values is not None
    PacketRepository(session).write_batch([values])


def seed_connection(
    session: Session, *, offset: float = 0.0, **overrides: Any
) -> NetworkConnection:
    """Store one conversation that *began* ``offset`` seconds into the window.

    A row with no ``end_time`` is the default, because that is what M9 writes for
    a conversation it is still observing — the case the duration statistics have
    to exclude rather than count as zero.
    """
    values: dict[str, Any] = {
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "packets_sent": 3,
        "packets_received": 2,
        "bytes_sent": 300,
        "bytes_received": 200,
        "start_time": utc(PACKET_BASE_TIME + offset),
        "end_time": None,
        "status": "active",
    }
    values.update(overrides)
    connection = NetworkConnection(**values)
    session.add(connection)
    session.commit()
    return connection


def seed_alert(session: Session, *, offset: float = 0.0, **overrides: Any) -> Alert:
    """Store one alert *observed* ``offset`` seconds into the window (M11.3).

    ``created_at`` is set explicitly because the M16 window filters on it: the
    column is the observation instant M11 writes, not the row's insert time, and
    the server default would place every seeded row at "now" and put them all
    outside any deliberate window.
    """
    values: dict[str, Any] = {
        "title": "Seeded alert",
        "severity": "high",
        "status": "open",
        "risk_score": 0,
        "confidence": 80,
        "correlation_key": "port_scan|192.168.1.10|8.8.8.8",
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "created_at": utc(PACKET_BASE_TIME + offset),
        "updated_at": utc(PACKET_BASE_TIME + offset),
    }
    values.update(overrides)
    alert = Alert(**values)
    session.add(alert)
    session.commit()
    return alert


__all__ = [
    "WINDOW_BUCKET_SECONDS",
    "WINDOW_END",
    "WINDOW_START",
    "make_window",
    "seed_alert",
    "seed_connection",
    "seed_packet",
    "utc",
]
