"""Epoch ⇄ datetime conversion for the alert engine (M11).

An alert is the one M11 entity that is *both* timed in epoch seconds (a
detection finding carries epoch seconds, exactly like a packet) and stored in
SQLite through ``DateTime`` columns. This module is the single place that
conversion happens, so the two representations cannot drift apart.

The stored value is deliberately a **naive UTC** datetime. That is precisely
what SQLite hands back for a ``DateTime`` column — it stores the wall time and
drops the offset, as :mod:`app.services.packet_query` already documents for
packets — so a datetime written through here round-trips unchanged and a test
can compare it for equality rather than approximately.
"""

from __future__ import annotations

from datetime import datetime, timezone


def to_utc_datetime(epoch_seconds: float) -> datetime:
    """Convert epoch seconds to the naive UTC datetime SQLite stores.

    Args:
        epoch_seconds: Seconds since the Unix epoch, as a finding reports them.

    Returns:
        A timezone-naive ``datetime`` whose wall time is UTC, which is the value
        a ``DateTime`` column returns after a round trip.
    """
    return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).replace(
        tzinfo=None
    )


def now_utc_datetime() -> datetime:
    """Return the current UTC time, as the naive datetime SQLite stores."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_epoch_seconds(value: datetime | None) -> float | None:
    """Convert a stored datetime back to epoch seconds, or ``None``.

    A naive datetime is read as UTC, which is how every datetime in this
    application is written (see :func:`to_utc_datetime`).
    """
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def to_iso_timestamp(value: datetime | None) -> str | None:
    """Render a stored datetime as an ISO-8601 UTC string, or ``None``.

    The API speaks ISO-8601 (like devices, connections and findings), so the
    wire projection needs this and nothing else.
    """
    epoch = to_epoch_seconds(value)
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
