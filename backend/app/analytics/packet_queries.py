"""Read-only aggregate queries over the persisted ``packets`` table (M16.2/M16.3).

Why this is not :class:`~app.repositories.packet.PacketRepository`. That repository
is the owner of M7's *per-record* access to ``packets``: it writes batches, pages a
listing, and answers "give me this row". M16 asks a different question of the same
table — "over this window, how many packets and bytes per protocol, per address,
per port, per time bucket" — and every one of those is a ``GROUP BY`` whose answer
is a small aggregate rather than a row. Keeping them apart means the per-record
repository does not grow a second, unrelated API, and all of M16's aggregation SQL
sits in one auditable place, which is what M16.9 asks a reviewer to be able to do.

**Nothing here loads a table into Python.** Every figure is produced by SQLite:
``COUNT``, ``SUM``, ``MIN``, ``MAX`` and ``GROUP BY``. A window over a million
stored packets returns at most :data:`MAX_GROUPS` grouped rows and at most
:data:`MAX_SERIES_POINTS` bucket rows, and the packet rows themselves are never
materialised.

**Every query is bounded twice.** Once by the window — which M16.7 caps at thirty
days — and once by an explicit ``LIMIT``, so no statement's row count depends on
what happens to be in the table.

**Values that are genuinely absent stay absent.** ``MIN(timestamp)`` over an empty
window is ``NULL`` and is returned as ``None``, never as ``0`` (epoch zero is
1970, not "no data"). ``SUM`` over no rows is likewise ``NULL``, and is coalesced
to ``0`` only where zero is the true answer: no packets stored in the window
really is zero packets.
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
from app.models.packet import Packet

#: Most protocol groups returned in one breakdown (M16.3). The classification M5
#: assigns is a closed vocabulary, so this is a guarantee rather than a filter.
MAX_PROTOCOLS = 50


@dataclass(frozen=True)
class TrafficTotals:
    """Traffic stored inside a window (M16.2).

    Attributes:
        packets: Packets stored in the window.
        bytes: Sum of their lengths.
        first_epoch / last_epoch: The oldest and newest stored packet instants, or
            ``None`` when the window is empty. ``None`` means "nothing stored",
            which is a different answer from "stored at epoch 0".
        packets_without_source_port / packets_without_destination_port: How many
            stored packets carry no port on that side — ICMP and ARP genuinely do
            not, so a port ranking cannot account for the whole window without
            saying how much of it it left out (M16.3).
    """

    packets: int = 0
    bytes: int = 0
    first_epoch: float | None = None
    last_epoch: float | None = None
    packets_without_source_port: int = 0
    packets_without_destination_port: int = 0


@dataclass(frozen=True)
class BucketTotals:
    """One time bucket's traffic (M16.2)."""

    bucket_start: int
    packets: int
    bytes: int


@dataclass(frozen=True)
class RankedTotal:
    """One row of a traffic ranking (M16.2).

    ``key`` is a string because that is what the M6 rankings already use
    (:class:`~app.schemas.statistics.TopEntry`), so a port ranking and an address
    ranking render the same way on the wire.
    """

    key: str
    packets: int
    bytes: int


@dataclass(frozen=True)
class ProtocolTotal:
    """One protocol's traffic inside a window (M16.3)."""

    protocol: str
    packets: int
    bytes: int


class PacketAnalytics:
    """Aggregate reads over ``packets``, scoped to one window (M16.2/M16.3)."""

    def __init__(self, db: Session) -> None:
        """Bind the queries to a session the caller owns and closes."""
        self._db = db

    # -- totals ------------------------------------------------------------

    def totals(self, window: AnalyticsWindow) -> TrafficTotals:
        """Return window totals and the window's first and last stored instant.

        One statement produces all six values, so the totals and the bounds cannot
        describe two different instants — the same reasoning the M6 manager uses
        when it reads its snapshot in one pass.
        """
        statement = select(
            func.count(),
            func.coalesce(func.sum(Packet.packet_length), 0),
            func.min(Packet.timestamp),
            func.max(Packet.timestamp),
            func.coalesce(
                func.sum(case((Packet.source_port.is_(None), 1), else_=0)), 0
            ),
            func.coalesce(
                func.sum(case((Packet.destination_port.is_(None), 1), else_=0)), 0
            ),
        ).where(*self._bounds(window))
        row = self._db.execute(statement).one()
        return TrafficTotals(
            packets=int(row[0] or 0),
            bytes=int(row[1] or 0),
            first_epoch=_epoch(row[2]),
            last_epoch=_epoch(row[3]),
            packets_without_source_port=int(row[4] or 0),
            packets_without_destination_port=int(row[5] or 0),
        )

    def stored_count(self) -> int:
        """Return how many packet rows the table holds in total (M13.18).

        Unwindowed on purpose: this is the figure the M13 response already
        reports beside the M6 live total, and it answers "how much is stored",
        not "how much was stored in the window".
        """
        return int(self._db.scalar(select(func.count()).select_from(Packet)) or 0)

    # -- series ------------------------------------------------------------

    def series(self, window: AnalyticsWindow) -> list[BucketTotals]:
        """Return per-bucket packet and byte totals, oldest bucket first.

        Only buckets that hold at least one stored packet are returned; the caller
        decides how to present a bucket the store has nothing for, because filling
        it with zero is a statement about the stored data and belongs in the layer
        that documents it.
        """
        bucket = bucket_expression(Packet.timestamp, window.bucket_seconds)
        statement = (
            select(
                bucket.label("bucket"),
                func.count().label("packets"),
                func.coalesce(func.sum(Packet.packet_length), 0).label("bytes"),
            )
            .where(*self._bounds(window))
            .group_by(bucket)
            .order_by(bucket)
            .limit(MAX_SERIES_POINTS)
        )
        return [
            BucketTotals(
                bucket_start=int(row.bucket),
                packets=int(row.packets or 0),
                bytes=int(row.bytes or 0),
            )
            for row in self._db.execute(statement)
        ]

    # -- protocol breakdown (M16.3) ---------------------------------------

    def protocols(self, window: AnalyticsWindow) -> list[ProtocolTotal]:
        """Return per-protocol totals, ordered by protocol name.

        One row per distinct classification, capped at :data:`MAX_PROTOCOLS` + 1
        so the caller can tell "this is everything" from "this was cut off"
        without a second counting query (M16.3). Ordering by name here is
        ordering for determinism, not for display: the caller ranks.
        """
        statement = (
            select(
                Packet.protocol,
                func.count(),
                func.coalesce(func.sum(Packet.packet_length), 0),
            )
            .where(*self._bounds(window))
            .group_by(Packet.protocol)
            .order_by(Packet.protocol.asc())
            .limit(MAX_PROTOCOLS + 1)
        )
        return [
            ProtocolTotal(
                protocol=str(row[0]), packets=int(row[1] or 0), bytes=int(row[2] or 0)
            )
            for row in self._db.execute(statement)
        ]

    def distinct_protocols(self, window: AnalyticsWindow) -> int:
        """Return how many distinct protocol classifications the window holds.

        :meth:`protocols` returns the breakdown itself, capped so its row count
        never depends on the table's contents. This answers the *other* half of
        the question — "how many are there altogether" — with one indexed
        aggregate, so a breakdown that was cut off can still report an exact
        distinct total instead of reporting the size of its own truncation
        (M16.3).
        """
        statement = select(func.count(func.distinct(Packet.protocol))).where(
            *self._bounds(window)
        )
        return int(self._db.scalar(statement) or 0)

    # -- rankings (M16.2) --------------------------------------------------

    def top_sources(
        self, window: AnalyticsWindow, *, limit: int, by: RankMetric
    ) -> list[RankedTotal]:
        """Rank the window's source addresses."""
        return self._ranked(Packet.source_ip, window, limit=limit, by=by)

    def top_destinations(
        self, window: AnalyticsWindow, *, limit: int, by: RankMetric
    ) -> list[RankedTotal]:
        """Rank the window's destination addresses."""
        return self._ranked(Packet.destination_ip, window, limit=limit, by=by)

    def top_destination_ports(
        self, window: AnalyticsWindow, *, limit: int, by: RankMetric
    ) -> list[RankedTotal]:
        """Rank the window's destination ports (M16.2).

        Packets with no destination port are excluded from the ranking because
        they have no port to rank; how many there are is reported separately by
        :meth:`totals`, so the exclusion is visible rather than silent.
        """
        return self._ranked(Packet.destination_port, window, limit=limit, by=by)

    # -- internals ---------------------------------------------------------

    def _ranked(
        self,
        column,
        window: AnalyticsWindow,
        *,
        limit: int,
        by: RankMetric,
    ) -> list[RankedTotal]:
        """Group by one column and return the highest ``limit`` groups.

        The tie-break is the group's own key, so two groups with equal traffic
        always come back in the same order and a page boundary cannot shuffle them
        (M13.24). ``NULL`` keys are dropped: an absent address is not an address,
        and ranking it would invent one.
        """
        capped = max(1, min(int(limit), MAX_GROUPS))
        packets = func.count()
        total_bytes = func.coalesce(func.sum(Packet.packet_length), 0)
        metric = total_bytes if by == "bytes" else packets
        statement = (
            select(
                column.label("key"),
                packets.label("packets"),
                total_bytes.label("bytes"),
            )
            .where(*self._bounds(window))
            .where(column.is_not(None))
            .group_by(column)
            .order_by(metric.desc(), column.asc())
            .limit(capped)
        )
        return [
            RankedTotal(
                key=str(row.key), packets=int(row.packets or 0), bytes=int(row.bytes or 0)
            )
            for row in self._db.execute(statement)
        ]

    @staticmethod
    def _bounds(window: AnalyticsWindow) -> tuple:
        """Return the window predicate: ``since`` inclusive, ``until`` exclusive.

        Comparing bound *values* rather than wrapping the column in a function is
        what lets SQLite use ``idx_packets_timestamp``; a ``strftime`` on the
        column would force a table scan (M16.9).
        """
        return (
            Packet.timestamp >= to_utc_datetime(window.since),
            Packet.timestamp < to_utc_datetime(window.until),
        )


def _epoch(value: object) -> float | None:
    """Return a stored timestamp as epoch seconds, or ``None``.

    SQLite hands a ``DateTime`` column back as the naive UTC datetime it stored,
    which is read as UTC here. ``None`` stays ``None``: an empty window has no
    first packet, and reporting epoch zero would claim one from 1970.
    """
    if not isinstance(value, datetime):
        return None
    return float(value.replace(tzinfo=timezone.utc).timestamp())


__all__ = [
    "MAX_PROTOCOLS",
    "BucketTotals",
    "PacketAnalytics",
    "ProtocolTotal",
    "RankedTotal",
    "TrafficTotals",
]
