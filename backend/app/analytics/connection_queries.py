"""Read-only aggregate queries over the persisted ``connections`` table (M16.5).

M9 writes one row per *conversation* — not one per packet (M7 owns per-packet
storage) — and this module asks that table the questions M16.5 lists: how many
conversations, in what states, over which protocols, how long they lasted, which
endpoints carried the most, and how the count moved over time.

Three boundaries it keeps:

**The window selects on ``start_time``**, exactly as
:meth:`~app.repositories.connection.ConnectionRepository.list` already does for
M9. A window therefore means "conversations that *began* inside it", which is the
only reading that gives a stable answer: filtering on ``end_time`` would silently
drop every conversation still in progress. The same rule M9 applies is restated
here rather than invented, so ``/connections`` and ``/analytics/connections``
cannot disagree about which rows a window names.

**Only whole seconds are reported as durations.** A duration is computed inside
SQLite from the two stored instants, so it is the stored pair — not a
recomputation in Python of numbers read separately — and it is whole-second
resolution because that is what ``strftime('%s', ...)`` yields.

**A conversation with no ``end_time`` has no duration**, and is excluded from the
statistics rather than counted as zero. ``end_time`` is written only once a
conversation ended (M9.17), so its absence is "still running", not "lasted no
time"; reporting a mean over rows that included it as ``0`` would report a
duration nobody observed.

Nothing here writes, retires or re-states a conversation. M9 owns the tracking
logic; this layer only counts what M9 already recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.analytics.metrics import MAX_GROUPS, RankMetric
from app.analytics.window import (
    MAX_SERIES_POINTS,
    AnalyticsWindow,
    bucket_expression,
    to_utc_datetime,
)
from app.connections.connection import (
    STATUS_ACTIVE,
    STATUS_COMPLETED,
    STATUS_TIMEOUT,
)
from app.models.connection import NetworkConnection

#: Every status M9 can write into ``connections.status`` (M9.17), in the order a
#: client should render them. Taken from the M9 record rather than re-spelled, so
#: the breakdown cannot drift from the vocabulary the tracker actually persists.
PERSISTED_STATUSES: tuple[str, ...] = (
    STATUS_ACTIVE,
    STATUS_COMPLETED,
    STATUS_TIMEOUT,
)


@dataclass(frozen=True)
class ConnectionTotals:
    """Conversations that began inside a window (M16.5).

    Attributes:
        connections: How many conversation rows the window holds.
        active: How many of them are still ``active`` — the persisted status M9
            writes for a conversation it is still observing.
        first_epoch / last_epoch: The earliest and latest ``start_time`` in the
            window, or ``None`` when the window is empty.
    """

    connections: int = 0
    active: int = 0
    first_epoch: float | None = None
    last_epoch: float | None = None


@dataclass(frozen=True)
class BucketCount:
    """One time bucket's conversation count (M16.5)."""

    bucket_start: int
    connections: int


@dataclass(frozen=True)
class DurationStats:
    """Observed conversation lifetimes inside a window (M16.5).

    Attributes:
        samples: How many conversations in the window have an ``end_time``, and so
            a measurable lifetime. ``0`` means none did.
        min_seconds / mean_seconds / max_seconds: The shortest, mean and longest
            of those lifetimes, or ``None`` when ``samples`` is ``0``. They are
            ``None`` rather than ``0.0`` because no observation was made, and a
            zero would be a claim that a conversation lasted no time at all.
    """

    samples: int = 0
    min_seconds: float | None = None
    mean_seconds: float | None = None
    max_seconds: float | None = None


@dataclass(frozen=True)
class RankedTraffic:
    """One endpoint's aggregate traffic across the window's conversations."""

    key: str
    packets: int
    bytes: int


class ConnectionAnalytics:
    """Aggregate reads over ``connections``, scoped to one window (M16.5)."""

    def __init__(self, db: Session) -> None:
        """Bind the queries to a session the caller owns and closes."""
        self._db = db

    # -- counts ------------------------------------------------------------

    def totals(self, window: AnalyticsWindow) -> ConnectionTotals:
        """Return the window's conversation count, active count and bounds.

        One statement, so the count and the ``active`` share cannot come from two
        different reads of a table M9 keeps writing to while the request runs.
        """
        statement = select(
            func.count(),
            func.coalesce(
                func.sum(case((NetworkConnection.status == STATUS_ACTIVE, 1), else_=0)),
                0,
            ),
            func.min(NetworkConnection.start_time),
            func.max(NetworkConnection.start_time),
        ).where(*self._bounds(window))
        row = self._db.execute(statement).one()
        return ConnectionTotals(
            connections=int(row[0] or 0),
            active=int(row[1] or 0),
            first_epoch=_epoch(row[2]),
            last_epoch=_epoch(row[3]),
        )

    def count_by_status(self, window: AnalyticsWindow) -> dict[str, int]:
        """Return how many conversations are in each persisted status."""
        return self._grouped(NetworkConnection.status, window)

    def count_by_protocol(self, window: AnalyticsWindow) -> dict[str, int]:
        """Return how many conversations used each transport protocol."""
        return self._grouped(NetworkConnection.protocol, window)

    # -- series ------------------------------------------------------------

    def series(self, window: AnalyticsWindow) -> list[BucketCount]:
        """Return per-bucket conversation counts, oldest bucket first.

        Bucketed by ``start_time``, like every other windowed read here, so a
        bucket contains the conversations that began inside it.
        """
        bucket = bucket_expression(NetworkConnection.start_time, window.bucket_seconds)
        statement = (
            select(bucket.label("bucket"), func.count().label("connections"))
            .where(*self._bounds(window))
            .group_by(bucket)
            .order_by(bucket)
            .limit(MAX_SERIES_POINTS)
        )
        return [
            BucketCount(bucket_start=int(row.bucket), connections=int(row.connections or 0))
            for row in self._db.execute(statement)
        ]

    # -- durations (M16.5) -------------------------------------------------

    def duration_stats(self, window: AnalyticsWindow) -> DurationStats:
        """Return lifetime statistics over the conversations that have ended.

        The subtraction happens in SQL against the two stored instants, so the
        figure describes the row rather than a pair of values carried into Python.
        A row with a ``NULL`` ``end_time`` is excluded before the aggregates run,
        which is why ``samples`` is reported beside them: a mean over three
        conversations out of a hundred is a different statement from a mean over
        all of them, and the caller is given what it needs to say which it is.
        """
        seconds = func.strftime("%s", NetworkConnection.end_time) - func.strftime(
            "%s", NetworkConnection.start_time
        )
        statement = select(
            func.count(NetworkConnection.end_time),
            func.min(seconds),
            func.avg(seconds),
            func.max(seconds),
        ).where(*self._bounds(window), NetworkConnection.end_time.is_not(None))
        row = self._db.execute(statement).one()
        samples = int(row[0] or 0)
        if samples == 0:
            return DurationStats()
        return DurationStats(
            samples=samples,
            min_seconds=_number(row[1]),
            mean_seconds=_number(row[2]),
            max_seconds=_number(row[3]),
        )

    # -- rankings ----------------------------------------------------------

    def top_sources(
        self, window: AnalyticsWindow, *, limit: int, by: RankMetric
    ) -> list[RankedTraffic]:
        """Rank the endpoints that originated the window's conversations."""
        return self._ranked(NetworkConnection.source_ip, window, limit=limit, by=by)

    def top_destinations(
        self, window: AnalyticsWindow, *, limit: int, by: RankMetric
    ) -> list[RankedTraffic]:
        """Rank the endpoints the window's conversations were directed at."""
        return self._ranked(NetworkConnection.destination_ip, window, limit=limit, by=by)

    # -- internals ---------------------------------------------------------

    def _grouped(self, column, window: AnalyticsWindow) -> dict[str, int]:
        """Return ``{value: count}`` for one column inside the window.

        Only values present in the window are returned. Zero-filling the rest is
        the caller's decision, because the vocabulary a value comes from belongs
        to the milestone that owns it — the status list is M9's, and a protocol
        list cannot be enumerated at all (M16.5).
        """
        statement = (
            select(column, func.count())
            .where(*self._bounds(window))
            .group_by(column)
        )
        return {
            str(value): int(count or 0) for value, count in self._db.execute(statement)
        }

    def _ranked(
        self,
        column,
        window: AnalyticsWindow,
        *,
        limit: int,
        by: RankMetric,
    ) -> list[RankedTraffic]:
        """Group by an endpoint column and return the busiest ``limit`` groups.

        A conversation's traffic is both directions: ``bytes`` is sent plus
        received and ``packets`` is the same for counts, because an endpoint's
        traffic is not a one-way property and reporting only what it sent would
        understate every server. The tie-break is the address itself, so equal
        traffic always orders the same way (M13.24).
        """
        capped = max(1, min(int(limit), MAX_GROUPS))
        packets = NetworkConnection.packets_sent + NetworkConnection.packets_received
        total_bytes = NetworkConnection.bytes_sent + NetworkConnection.bytes_received
        metric = total_bytes if by == "bytes" else packets
        statement = (
            select(
                column.label("key"),
                func.coalesce(func.sum(packets), 0).label("packets"),
                func.coalesce(func.sum(total_bytes), 0).label("bytes"),
            )
            .where(*self._bounds(window))
            .where(column.is_not(None))
            .group_by(column)
            .order_by(metric.desc(), column.asc())
            .limit(capped)
        )
        return [
            RankedTraffic(
                key=str(row.key), packets=int(row.packets or 0), bytes=int(row.bytes or 0)
            )
            for row in self._db.execute(statement)
        ]

    @staticmethod
    def _bounds(window: AnalyticsWindow) -> tuple:
        """Return the window predicate on ``start_time``, ``until`` exclusive."""
        return (
            NetworkConnection.start_time >= to_utc_datetime(window.since),
            NetworkConnection.start_time < to_utc_datetime(window.until),
        )


def _epoch(value: object) -> float | None:
    """Return a stored ``start_time`` as epoch seconds, or ``None``.

    The column holds a naive UTC wall-clock value, so UTC is attached before the
    conversion: a naive ``timestamp()`` would read it as local time and shift
    every reported instant by the host's offset.
    """
    if not isinstance(value, datetime):
        return None
    return float(value.replace(tzinfo=timezone.utc).timestamp())


def _number(value: object) -> float | None:
    """Return an aggregate as a float, or ``None`` when SQLite produced none."""
    if value is None:
        return None
    return float(value)  # type: ignore[arg-type]


__all__ = [
    "PERSISTED_STATUSES",
    "BucketCount",
    "ConnectionAnalytics",
    "ConnectionTotals",
    "DurationStats",
    "RankedTraffic",
]
