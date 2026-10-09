"""The persisted traffic and protocol blocks of the analytics responses (M16.2/M16.3).

Two response fields hold these blocks — ``traffic.stored`` and
``protocols.stored`` — and both ask the same question of the same table: "over
this window, what did the stored packets amount to, broken down by protocol?"
Factoring them here rather than in a route is what stops the two blocks from
answering it differently.

Three rules the builders keep:

**Percentages are shares of the window, not of the returned rows.** The
denominator is the window's stored packet count, so a truncated breakdown's
shares deliberately do not sum to ``100``: they describe the window, and the
window was not truncated. Reporting shares of the *rows* would make two
different windows' breakdowns look alike whenever both were cut off (M16.3).

**A series is zero-filled over the window's own buckets.** :class:`PacketAnalytics`
returns only buckets that hold a stored packet, because a query has no business
asserting what a bucket with no rows means. A series *chart* does: a bucket with
nothing stored plots as a gap, and the documented reading of zero stored packets
is "the store holds none in this interval" — not "no traffic occurred", which is
a claim about the network rather than about the store. Filling the window's
buckets is bounded by :data:`~app.analytics.window.MAX_BUCKETS`, so it cannot
grow with the data (M16.7).

**An absent instant stays absent.** ``first_timestamp`` and
``last_timestamp`` are ``None`` for an empty window, never epoch zero:
``MIN(timestamp)`` over no rows is ``NULL``, and 1970 is not "no data" (M16.8).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.analytics.metrics import RankMetric
from app.analytics.packet_queries import (
    MAX_PROTOCOLS,
    PacketAnalytics,
    RankedTotal,
)
from app.analytics.window import AnalyticsWindow, iso_from_epoch
from app.schemas.analytics import SeriesPoint, StoredProtocolsData, StoredTrafficData
from app.schemas.statistics import ProtocolStat, TopEntry


def build_stored_traffic(
    db: Session,
    window: AnalyticsWindow,
    *,
    limit: int,
    by: RankMetric,
) -> StoredTrafficData:
    """Return the persisted traffic block for one window (M16.2).

    The unwindowed row count M13 reports is read here, inside the same call, so
    that a packet table which cannot be read yields one unavailable section rather
    than an exception escaping beside the guard (M16.8).

    Args:
        db: A session the caller owns and closes.
        window: The resolved, bounded window.
        limit: How many rows each ranking carries.
        by: The metric the rankings are ordered by.
    """
    analytics = PacketAnalytics(db)
    totals = analytics.totals(window)
    protocols, distinct, _truncated = protocol_breakdown(
        analytics, window, by=by, total_packets=totals.packets
    )
    return StoredTrafficData(
        total_packets=totals.packets,
        total_bytes=totals.bytes,
        packets_per_second=_rate(totals.packets, window.seconds),
        bytes_per_second=_rate(totals.bytes, window.seconds),
        average_packet_bytes=_mean(totals.bytes, totals.packets),
        first_timestamp=_iso(totals.first_epoch),
        last_timestamp=_iso(totals.last_epoch),
        distinct_protocols=distinct,
        packets_without_source_port=totals.packets_without_source_port,
        packets_without_destination_port=totals.packets_without_destination_port,
        stored_packet_count=analytics.stored_count(),
        series=_series(analytics, window),
        top_sources=_entries(analytics.top_sources(window, limit=limit, by=by)),
        top_destinations=_entries(
            analytics.top_destinations(window, limit=limit, by=by)
        ),
        top_ports=_entries(
            analytics.top_destination_ports(window, limit=limit, by=by)
        ),
        protocols=protocols,
    )


def build_stored_protocols(
    db: Session, window: AnalyticsWindow, *, by: RankMetric
) -> StoredProtocolsData:
    """Return the persisted protocol block for one window (M16.3).

    When the breakdown fits ``MAX_PROTOCOLS``, the window's totals are the sum of
    the rows themselves — every stored packet carries a non-null classification —
    so one statement answers the whole question. Only a breakdown that was cut
    off pays for the two extra aggregates that make its totals exact.
    """
    analytics = PacketAnalytics(db)
    rows = analytics.protocols(window)
    truncated = len(rows) > MAX_PROTOCOLS
    total_packets = sum(row.packets for row in rows)
    total_bytes = sum(row.bytes for row in rows)
    if truncated:
        totals = analytics.totals(window)
        total_packets = totals.packets
        total_bytes = totals.bytes
    stats, distinct, _truncated = protocol_breakdown(
        analytics, window, by=by, total_packets=total_packets
    )
    return StoredProtocolsData(
        count=len(stats),
        distinct_protocols=distinct,
        truncated=distinct > len(stats),
        total_packets=total_packets,
        total_bytes=total_bytes,
        rank_by=by,
        protocols=stats,
    )


def protocol_breakdown(
    analytics: PacketAnalytics,
    window: AnalyticsWindow,
    *,
    by: RankMetric,
    total_packets: int,
) -> tuple[list[ProtocolStat], int, bool]:
    """Return the ranked protocol entries, the distinct count and the cut-off flag.

    The entries are ranked here rather than in SQL because the ordering is a
    *presentation* choice — the same rows are reported under either metric — and
    because a ranking's tie-break has to be total to be stable (M13.24). The
    query orders by name purely for determinism.
    """
    rows = analytics.protocols(window)
    truncated = len(rows) > MAX_PROTOCOLS
    distinct = (
        analytics.distinct_protocols(window) if truncated else len(rows)
    )
    stats = [
        ProtocolStat(
            protocol=row.protocol,
            packets=row.packets,
            bytes=row.bytes,
            percentage=_share(row.packets, total_packets),
        )
        for row in rows[:MAX_PROTOCOLS]
    ]
    stats.sort(key=lambda entry: _rank_key(entry, by))
    return stats, distinct, truncated


def _rank_key(entry: ProtocolStat, by: RankMetric) -> tuple[float, str]:
    """Return the sort key a ranked protocol entry orders by.

    Negating the metric sorts descending; the name makes the order total, so two
    protocols with equal traffic always come back the same way.
    """
    metric = entry.bytes if by == "bytes" else entry.packets
    return (-float(metric), entry.protocol)


def _series(analytics: PacketAnalytics, window: AnalyticsWindow) -> list[SeriesPoint]:
    """Return the window's buckets, each with its stored totals.

    Every bucket the window lists is present — the store's own buckets first,
    then any the query reported that the listing did not anticipate, so a bucket
    is never silently dropped. Zero-filled buckets mean the store held nothing in
    that interval, and are bounded by the window's bucket count (M16.7).
    """
    counted = {row.bucket_start: row for row in analytics.series(window)}
    starts = sorted(set(window.bucket_starts()) | set(counted))
    return [
        SeriesPoint(
            start=iso_from_epoch(start),
            packets=counted[start].packets if start in counted else 0,
            bytes=counted[start].bytes if start in counted else 0,
        )
        for start in starts
    ]


def _entries(rows: list[RankedTotal]) -> list[TopEntry]:
    """Project ranked aggregates onto the M6 ranking entry the API already uses.

    Reusing M6's ``TopEntry`` rather than inventing an analytics one is what lets
    a client render a persisted ranking and a live one with the same component
    (M16.2).
    """
    return [
        TopEntry(key=row.key, packets=row.packets, bytes=row.bytes) for row in rows
    ]


def _rate(total: float, seconds: float) -> float:
    """Return a per-second rate, or ``0.0`` when the window has no length.

    A resolved window is never empty (:func:`resolve_window` refuses one), so the
    guard exists to keep the arithmetic total rather than to describe a case a
    request can reach.
    """
    if seconds <= 0:
        return 0.0
    return float(total) / float(seconds)


def _mean(total_bytes: int, packets: int) -> float | None:
    """Return the mean packet size, or ``None`` when nothing was stored.

    ``None`` rather than ``0.0``: no stored packet means no size was observed,
    and zero would claim every packet was empty (M16.8).
    """
    if packets <= 0:
        return None
    return float(total_bytes) / float(packets)


def _share(count: int, total: int) -> float:
    """Return ``count`` as a percentage of ``total``, or ``0.0`` when empty."""
    if total <= 0:
        return 0.0
    return 100.0 * float(count) / float(total)


def _iso(epoch: float | None) -> str | None:
    """Render an optional stored instant as ISO-8601 UTC, or ``None``."""
    return None if epoch is None else iso_from_epoch(epoch)


__all__ = [
    "build_stored_protocols",
    "build_stored_traffic",
    "protocol_breakdown",
]
