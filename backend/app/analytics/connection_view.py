"""Stored conversations, read for the connection analytics block (M16.5).

M9 writes one row per *conversation* into ``connections``, and this builder
turns that table into the ``stored`` block of ``/analytics/connections``. It
reads; it never writes, retires or re-states a conversation, because M9 owns the
tracking logic and M16 only counts what M9 already recorded (M16.5).

Three decisions worth stating:

**The window selects on ``start_time``.** That is M9's own rule for the same
filter, so ``/connections`` and ``/analytics/connections`` cannot disagree about
which rows a window names. Filtering on ``end_time`` instead would silently drop
every conversation still in progress, which is the one thing a live view must not
do.

**Statuses are named in full, protocols are not.** The three persisted statuses
are a closed vocabulary M9 defines, so each is reported even at zero and a client
renders fixed rows. A protocol list cannot be enumerated — it is whatever the
wire carried — so only protocols present in the window appear, and a missing key
means "none seen", not "not measured" (M16.5).

**A duration describes only the conversations that ended.** A row with no
``end_time`` is still running, so it is excluded from the statistics and counted
separately as ``samples`` rather than contributing a zero. Zero-filling it would
report a lifetime nobody observed (M16.5/M16.8).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.analytics.connection_queries import (
    PERSISTED_STATUSES,
    ConnectionAnalytics,
    RankedTraffic,
)
from app.analytics.metrics import RankMetric
from app.analytics.window import AnalyticsWindow, iso_from_epoch
from app.schemas.analytics import (
    ConnectionSeriesPoint,
    DurationStats,
    StoredConnectionsData,
)
from app.schemas.statistics import TopEntry


def build_stored_connections(
    db: Session,
    window: AnalyticsWindow,
    *,
    limit: int,
    by: RankMetric,
) -> StoredConnectionsData:
    """Return the stored-conversation block for one window (M16.5).

    Args:
        db: A session the caller owns and closes.
        window: The resolved, bounded window.
        limit: How many endpoints each ranking carries.
        by: The metric the endpoint rankings are ordered by.
    """
    analytics = ConnectionAnalytics(db)
    totals = analytics.totals(window)
    duration = analytics.duration_stats(window)
    return StoredConnectionsData(
        total=totals.connections,
        active=totals.active,
        first_timestamp=_iso(totals.first_epoch),
        last_timestamp=_iso(totals.last_epoch),
        by_protocol=analytics.count_by_protocol(window),
        by_status=_status_counts(analytics, window),
        duration=DurationStats(
            samples=duration.samples,
            min_seconds=duration.min_seconds,
            mean_seconds=duration.mean_seconds,
            max_seconds=duration.max_seconds,
        ),
        series=_series(analytics, window),
        top_sources=_entries(analytics.top_sources(window, limit=limit, by=by)),
        top_destinations=_entries(
            analytics.top_destinations(window, limit=limit, by=by)
        ),
    )


def _status_counts(
    analytics: ConnectionAnalytics, window: AnalyticsWindow
) -> dict[str, int]:
    """Return every persisted status, zero-filled for those the window lacks.

    The vocabulary comes from M9's own record rather than being re-spelled here,
    so the breakdown cannot drift from the statuses the tracker actually writes.
    """
    counted = analytics.count_by_status(window)
    return {
        status: int(counted.get(status, 0))
        for status in PERSISTED_STATUSES
    }


def _series(
    analytics: ConnectionAnalytics, window: AnalyticsWindow
) -> list[ConnectionSeriesPoint]:
    """Return the window's buckets, each with its conversation count.

    Zero-filled over the window's own buckets for the same reason the traffic
    series is: a bucket with no stored row plots as a gap, and "no conversation
    began then" is a statement about the store rather than about the network
    (M16.5). Bounded by the window's bucket count (M16.7).
    """
    counted = {row.bucket_start: row.connections for row in analytics.series(window)}
    starts = sorted(set(window.bucket_starts()) | set(counted))
    return [
        ConnectionSeriesPoint(
            start=iso_from_epoch(start), connections=int(counted.get(start, 0))
        )
        for start in starts
    ]


def _entries(rows: list[RankedTraffic]) -> list[TopEntry]:
    """Project a ranked endpoint onto the M6 ranking entry the API already uses."""
    return [
        TopEntry(key=row.key, packets=row.packets, bytes=row.bytes) for row in rows
    ]


def _iso(epoch: float | None) -> str | None:
    """Render an optional stored instant as ISO-8601 UTC, or ``None``."""
    return None if epoch is None else iso_from_epoch(epoch)


__all__ = [
    "build_stored_connections",
]
