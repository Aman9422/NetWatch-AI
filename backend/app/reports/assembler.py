"""Filling the report content model from the analytics layer that already exists (M17.3).

The reporting layer does not query the packet table. It asks
:class:`~app.analytics.service.AnalyticsService` the five questions M16 already
answers -- traffic, protocols, devices, connections, threats -- and writes the
answers down. That is the whole job of this module, and it is deliberately the
whole job: M17.2 asks the reports layer to **reuse** the analytics layer rather
than become a second one, so there is exactly one implementation of "what was the
top protocol in this window" and this module is not it.

**Why reuse rather than re-query.** Every figure in a report has to agree with the
figure the dashboard shows for the same instants. Two implementations of the same
aggregation drift apart; one cannot. So a report is the analytics view, written
down: same window convention (half-open, UTC), same ranking metric, same
availability semantics, same distinction between a measured zero and a value that
could not be read.

**The window is a report period.** A report covers
:class:`~app.reports.period.ReportPeriod`, whose bounds are the same half-open
instants an :class:`~app.analytics.window.AnalyticsWindow` uses. This module
converts one into the other and hands it to the service, so a report and an
analytics request for the same day select exactly the same rows.

**Availability is inherited, not re-invented.** The analytics service already
reports a database-derived block that could not be read as an unavailable section
(M16.8), and this module carries that through unchanged: an unavailable block
becomes a :class:`~app.reports.content.ReportSection` with ``available=False`` and
a safe sentence, never a table of zeroes. A block that *was* read and simply holds
nothing becomes an available section holding an empty table with an explicit "no
rows" notice -- the same two states, spelled the same way.

**Nothing here scores anything.** Risk bands, severities and confidence ranges are
read from M11 and M12 as M16 reports them. No report adds a judgement of its own
(M17 non-goals).
"""

from __future__ import annotations

from app.alerts.status import STORED_STATUS_VALUES
from app.analytics.alert_view import RISK_BAND_KEYS, SEVERITY_KEYS
from app.analytics.distributions import CONFIDENCE_RANGE_LABELS
from app.analytics.metrics import MAX_GROUPS, RankMetric
from app.analytics.sections import read_section
from app.analytics.service import AnalyticsService
from app.analytics.window import AnalyticsWindow, resolve_window
from app.reports.content import (
    NOT_REPORTED,
    Metric,
    ReportContent,
    ReportSection,
    ReportTable,
)
from app.reports.period import ReportPeriod

#: Ranking metric a report's rankings use. ``bytes`` rather than ``packets``,
#: because a report is read after the fact and a reader comparing two days cares
#: more about how much moved than about how many frames carried it. It is the
#: documented choice, not an implicit one: the ranking tables say which metric
#: they are ordered by in their column header.
REPORT_RANK_METRIC: RankMetric = "bytes"

#: How many rows a report's rankings carry. Bounded by the analytics layer's own
#: group cap rather than by a second number, so a report cannot become a dump of
#: the packet table (M17.13).
REPORT_ROW_LIMIT: int = MAX_GROUPS

#: The sentence a readable-but-empty table carries, so an empty report says why
#: rather than presenting an unlabelled blank (M17.7/M17.8).
NO_ROWS_NOTICE = "No data was recorded in this period."

#: The sentence an unreadable section carries. One constant, so the two renderers
#: cannot word it differently.
UNAVAILABLE_NOTICE = "This section could not be read and is not included."


def analytics_window_for(period: ReportPeriod) -> AnalyticsWindow:
    """Convert a report period into the analytics window covering the same instants.

    The conversion is a translation, not a re-derivation: the bounds are passed
    through unchanged and the bucket size is left to the analytics layer's own
    rule, so a report's series has exactly the resolution an analytics request for
    the same period would have had (M17.6).

    ``now`` is the period's exclusive upper bound. It is only used by
    :func:`~app.analytics.window.resolve_window` to default a bound the caller did
    not name, and both bounds *are* named here, so the value cannot affect the
    result -- passing the period's own end keeps the call honest about which
    instant the report describes rather than reading the wall clock.
    """
    return resolve_window(
        since=period.since,
        until=period.until,
        bucket_seconds=None,
        now=period.until,
    )


def _count(value: int) -> str:
    """Render a whole count, with thousands separators for a human reader."""
    return f"{int(value):,}"


def _bytes(value: int) -> str:
    """Render a byte total in the unit a report reader thinks in.

    The raw total is always reported beside this, so the scaled figure is a
    convenience rather than a lossy replacement: a reader can check the arithmetic
    against the byte count in the same row.
    """
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TiB"


def _rate(value: float, unit: str) -> str:
    """Render a per-second rate with a fixed precision and its unit."""
    return f"{float(value):.2f} {unit}"


def _share(count: int, total: int) -> str:
    """Render ``count`` as a percentage of ``total``.

    A zero total yields the documented not-reported text rather than ``0.0%``: a
    share of nothing is undefined, and printing zero would claim the value was
    measured and found to be nothing.
    """
    if total <= 0:
        return "n/a"
    return f"{100.0 * float(count) / float(total):.2f}%"


def _text(value: object | None) -> str:
    """Render an optional value as text, using the model's not-reported constant.

    ``None`` becomes the documented not-reported text rather than an empty cell,
    so a reader can tell "the backend has no value here" from "the value is an
    empty string" (M17.3).
    """
    if value is None:
        return NOT_REPORTED
    text = str(value).strip()
    return text if text else NOT_REPORTED


def _table(
    *, key: str, title: str, columns: tuple[str, ...], rows: list[tuple[str, ...]]
) -> ReportTable:
    """Build a table, attaching the standard empty notice when it has no rows."""
    rendered = tuple(rows)
    return ReportTable(
        key=key,
        title=title,
        columns=columns,
        rows=rendered,
        notice=None if rendered else NO_ROWS_NOTICE,
    )


__all__ = [
    "NO_ROWS_NOTICE",
    "REPORT_RANK_METRIC",
    "REPORT_ROW_LIMIT",
    "UNAVAILABLE_NOTICE",
    "analytics_window_for",
]


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _unavailable_section(*, key: str, title: str) -> ReportSection:
    """Build the section a block that could not be read produces.

    No metrics and no tables are attached. That is the point: a block that could
    not be read has *no* values, and reporting zeroes for it would present an
    unmeasured figure as a measurement (M16.8). The section carries one safe
    sentence and its own ``available`` flag, and the renderers print the sentence
    where the tables would have been.
    """
    return ReportSection(
        key=key,
        title=title,
        available=False,
        notice=UNAVAILABLE_NOTICE,
    )


def _ranking_rows(entries) -> list[tuple[str, ...]]:
    """Render ranked ``(key, packets, bytes)`` entries as table rows.

    The label column's header is supplied by the caller, because "Source",
    "Destination" and "Port" are the same shape with a different meaning -- and a
    report that called them all "Key" would make a reader guess which is which.
    """
    return [
        (str(getattr(entry, "key", "") or "unknown"), _count(entry.packets), _count(entry.bytes))
        for entry in entries
    ]


def build_traffic_section(
    *, analytics: AnalyticsService, window: AnalyticsWindow, limit: int
) -> ReportSection:
    """Build the traffic section from M16's traffic view (M17.3).

    Both halves of the M16 view are reported, and they are reported separately
    because they answer different questions. The live half is M6's in-process
    snapshot: it resets with the process and describes "since capture started".
    The stored half is the packet table read over the report's period. A report is
    a historical document, so the stored half is the one that matters -- but the
    live half is printed beside it rather than dropped, because a reader comparing
    a report against a running dashboard needs to see why the two numbers differ.
    """
    outcome = read_section(
        lambda: analytics.traffic(window=window, limit=limit, by=REPORT_RANK_METRIC),
        name="report_traffic",
    )
    if not outcome.available or outcome.data is None:
        return _unavailable_section(key="traffic", title="Traffic")

    view = outcome.data
    stored = view.stored.data if view.stored.available else None

    metrics: list[Metric] = [
        Metric("Packets captured in this session", _count(view.total_packets)),
        Metric("Bytes captured in this session", _count(view.total_bytes)),
        Metric("Packets per second (live)", _rate(view.packets_per_second, "pkt/s")),
        Metric("Bytes per second (live)", _rate(view.bytes_per_second, "B/s")),
        Metric("Average packet size (live)", f"{view.average_packet_bytes:.2f} bytes"),
        Metric("Rows in the packet table (all time)", _count(view.stored_packet_count)),
    ]

    tables: list[ReportTable] = []

    if stored is None:
        metrics.extend(
            [
                Metric("Packets stored in period", NOT_REPORTED),
                Metric("Bytes stored in period", NOT_REPORTED),
            ]
        )
        tables.append(
            ReportTable(
                key="stored_traffic",
                title="Stored traffic in period",
                columns=("Measure",),
                rows=(),
                notice=UNAVAILABLE_NOTICE,
            )
        )
        return ReportSection(
            key="traffic", title="Traffic", metrics=tuple(metrics), tables=tuple(tables)
        )

    metrics.extend(
        [
            Metric("Packets stored in period", _count(stored.total_packets)),
            Metric("Bytes stored in period", _count(stored.total_bytes)),
            Metric("Bytes stored in period (scaled)", _bytes(stored.total_bytes)),
            Metric("Packets per second (period)", _rate(stored.packets_per_second, "pkt/s")),
            Metric("Bytes per second (period)", _rate(stored.bytes_per_second, "B/s")),
            Metric(
                "Average packet size (period)",
                "n/a"
                if stored.average_packet_bytes is None
                else f"{stored.average_packet_bytes:.2f} bytes",
            ),
            Metric("Distinct protocols in period", _count(stored.distinct_protocols)),
            Metric("Packets with no source port", _count(stored.packets_without_source_port)),
            Metric(
                "Packets with no destination port",
                _count(stored.packets_without_destination_port),
            ),
            Metric("First stored packet in period", _text(stored.first_timestamp)),
            Metric("Last stored packet in period", _text(stored.last_timestamp)),
        ]
    )

    tables.append(
        _table(
            key="traffic_series",
            title="Traffic over time",
            columns=("Bucket start (UTC)", "Packets", "Bytes"),
            rows=[
                (str(point.start), _count(point.packets), _count(point.bytes))
                for point in stored.series
            ],
        )
    )
    tables.append(
        _table(
            key="top_sources",
            title=f"Busiest sources (by {REPORT_RANK_METRIC})",
            columns=("Source", "Packets", "Bytes"),
            rows=_ranking_rows(stored.top_sources),
        )
    )
    tables.append(
        _table(
            key="top_destinations",
            title=f"Busiest destinations (by {REPORT_RANK_METRIC})",
            columns=("Destination", "Packets", "Bytes"),
            rows=_ranking_rows(stored.top_destinations),
        )
    )
    tables.append(
        _table(
            key="top_ports",
            title=f"Busiest destination ports (by {REPORT_RANK_METRIC})",
            columns=("Port", "Packets", "Bytes"),
            rows=_ranking_rows(stored.top_ports),
        )
    )
    tables.append(
        _table(
            key="protocols",
            title="Protocol distribution in period",
            columns=("Protocol", "Packets", "Bytes", "Share of period packets"),
            rows=[
                (
                    str(entry.protocol),
                    _count(entry.packets),
                    _count(entry.bytes),
                    _share(entry.packets, stored.total_packets),
                )
                for entry in stored.protocols
            ],
        )
    )

    return ReportSection(
        key="traffic", title="Traffic", metrics=tuple(metrics), tables=tuple(tables)
    )


def build_protocols_section(
    *, analytics: AnalyticsService, window: AnalyticsWindow
) -> ReportSection:
    """Build the protocol section from M16's protocol view (M17.3).

    The live distribution is M6's, ordered by the report's ranking metric; the
    stored distribution is the packet table read over the period, with shares
    taken against *that period's* packet count. The two can differ -- a protocol
    seen before capture started is absent from the live list but present in the
    stored one -- and both are printed for exactly that reason (M16.3).
    """
    outcome = read_section(
        lambda: analytics.protocols(window=window, by=REPORT_RANK_METRIC),
        name="report_protocols",
    )
    if not outcome.available or outcome.data is None:
        return _unavailable_section(key="protocols", title="Protocols")

    view = outcome.data
    stored = view.stored.data if view.stored.available else None

    metrics: list[Metric] = [
        Metric("Protocols seen in this session", _count(view.count)),
        Metric("Packets counted in this session", _count(view.total_packets)),
        Metric("Bytes counted in this session", _count(view.total_bytes)),
        Metric("Ordered by", REPORT_RANK_METRIC),
    ]

    tables: list[ReportTable] = [
        _table(
            key="live_protocols",
            title=f"Protocol distribution this session (by {REPORT_RANK_METRIC})",
            columns=("Protocol", "Packets", "Bytes", "Share of session packets"),
            rows=[
                (
                    str(entry.protocol),
                    _count(entry.packets),
                    _count(entry.bytes),
                    _share(entry.packets, view.total_packets),
                )
                for entry in view.protocols
            ],
        )
    ]

    if stored is None:
        metrics.append(Metric("Protocols recorded in period", NOT_REPORTED))
        metrics.append(Metric("Packets recorded in period", NOT_REPORTED))
        tables.append(
            ReportTable(
                key="stored_protocols",
                title="Protocol distribution in period",
                columns=("Measure",),
                rows=(),
                notice=UNAVAILABLE_NOTICE,
            )
        )
        return ReportSection(
            key="protocols", title="Protocols", metrics=tuple(metrics), tables=tuple(tables)
        )

    metrics.extend(
        [
            Metric("Protocols recorded in period", _count(stored.distinct_protocols)),
            Metric("Protocols listed in period", _count(stored.count)),
            Metric("Packets recorded in period", _count(stored.total_packets)),
            Metric("Bytes recorded in period", _count(stored.total_bytes)),
            Metric("Protocol list truncated", "yes" if stored.truncated else "no"),
        ]
    )
    tables.append(
        _table(
            key="stored_protocols",
            title=f"Protocol distribution in period (by {REPORT_RANK_METRIC})",
            columns=("Protocol", "Packets", "Bytes", "Share of period packets"),
            rows=[
                (
                    str(entry.protocol),
                    _count(entry.packets),
                    _count(entry.bytes),
                    _share(entry.packets, stored.total_packets),
                )
                for entry in stored.protocols
            ],
        )
    )

    return ReportSection(
        key="protocols", title="Protocols", metrics=tuple(metrics), tables=tuple(tables)
    )


#: The identities a status breakdown is rendered under, in a fixed order, so a
#: report reads the same whichever statuses happen to be non-zero. The keys are
#: M8's own vocabulary; a status M8 adds later and this tuple does not name is
#: still rendered, appended after the named ones, rather than dropped.
KNOWN_STATUSES: tuple[str, ...] = ("active", "inactive", "unknown")


def _breakdown_rows(counts, *, order: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    """Render a ``{key: count}`` map as ``(key, count)`` rows in a stable order.

    Named keys come first, in the order given, so two reports of the same type
    line up for comparison. Keys the caller did not name follow, sorted by name,
    so a vocabulary extension is *included* rather than silently omitted -- the
    alternative would let a new status vanish from every future report.
    """
    rendered: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for key in order:
        if key in counts:
            rendered.append((str(key), _count(counts[key])))
            seen.add(str(key))
    for key in sorted(counts):
        if str(key) not in seen:
            rendered.append((str(key), _count(counts[key])))
    return rendered


def _device_rows(devices) -> list[tuple[str, ...]]:
    """Render ranked device views as table rows (M16.4)."""
    rows: list[tuple[str, ...]] = []
    for device in devices:
        addresses = ", ".join(str(address) for address in device.ip_addresses)
        rows.append(
            (
                str(device.device_id),
                _text(device.mac_address),
                addresses or NOT_REPORTED,
                _text(device.hostname),
                str(device.status),
                _text(device.first_seen),
                _text(device.last_seen),
                _count(device.packets),
                _count(device.bytes),
            )
        )
    return rows


DEVICE_COLUMNS: tuple[str, ...] = (
    "Device",
    "MAC address",
    "IP addresses",
    "Hostname",
    "Status",
    "First seen",
    "Last seen",
    "Packets",
    "Bytes",
)


def build_devices_section(
    *, analytics: AnalyticsService, window: AnalyticsWindow, limit: int
) -> ReportSection:
    """Build the device section from M16's device view (M17.3).

    Only the M8 registry is read here: what it holds now, and which of those
    records were last seen inside the period. The registry keeps no history of
    what it held when, so a report says which devices were *observed in* the
    period rather than reconstructing them -- claiming otherwise would be the same
    limitation M16.4 documents, restated in a document that looks authoritative
    (M17.11).

    No risk score appears, because M8 computes none, and a report is not the place
    to start (M17 non-goals).
    """
    outcome = read_section(
        lambda: analytics.devices(window=window, limit=limit, by=REPORT_RANK_METRIC),
        name="report_devices",
    )
    if not outcome.available or outcome.data is None:
        return _unavailable_section(key="devices", title="Devices")

    view = outcome.data
    windowed = view.windowed.data if view.windowed.available else None

    metrics: list[Metric] = [
        Metric("Devices known to the registry", _count(view.total)),
        Metric("Ranked by", REPORT_RANK_METRIC),
    ]
    metrics.extend(
        Metric(f"Devices {status}", count)
        for status, count in _breakdown_rows(view.by_status, order=KNOWN_STATUSES)
    )

    tables: list[ReportTable] = [
        _table(
            key="devices_by_status",
            title="Devices by activity state",
            columns=("State", "Devices"),
            rows=_breakdown_rows(view.by_status, order=KNOWN_STATUSES),
        ),
        _table(
            key="top_devices",
            title=f"Busiest devices (by {REPORT_RANK_METRIC})",
            columns=DEVICE_COLUMNS,
            rows=_device_rows(view.top),
        ),
    ]

    if windowed is None:
        metrics.append(Metric("Devices observed in period", NOT_REPORTED))
        tables.append(
            ReportTable(
                key="devices_in_period_by_status",
                title="Devices observed in period, by state",
                columns=("Measure",),
                rows=(),
                notice=UNAVAILABLE_NOTICE,
            )
        )
        return ReportSection(
            key="devices", title="Devices", metrics=tuple(metrics), tables=tuple(tables)
        )

    metrics.append(Metric("Devices observed in period", _count(windowed.total)))
    metrics.extend(
        Metric(f"Devices observed in period, {status}", count)
        for status, count in _breakdown_rows(windowed.by_status, order=KNOWN_STATUSES)
    )
    tables.append(
        _table(
            key="devices_in_period_by_status",
            title="Devices observed in period, by state",
            columns=("State", "Devices"),
            rows=_breakdown_rows(windowed.by_status, order=KNOWN_STATUSES),
        )
    )
    tables.append(
        _table(
            key="top_devices_in_period",
            title=f"Busiest devices observed in period (by {REPORT_RANK_METRIC})",
            columns=DEVICE_COLUMNS,
            rows=_device_rows(windowed.top),
        )
    )

    return ReportSection(
        key="devices", title="Devices", metrics=tuple(metrics), tables=tuple(tables)
    )


CONNECTION_COLUMNS: tuple[str, ...] = (
    "Conversation",
    "Protocol",
    "Source",
    "Source port",
    "Destination",
    "Destination port",
    "State",
    "Packets",
    "Bytes",
)


def _connection_rows(connections) -> list[tuple[str, ...]]:
    """Render ranked conversation views as table rows (M16.5)."""
    rows: list[tuple[str, ...]] = []
    for connection in connections:
        rows.append(
            (
                str(connection.connection_id),
                str(connection.protocol),
                str(connection.source_ip),
                NOT_REPORTED
                if connection.source_port is None
                else str(connection.source_port),
                str(connection.destination_ip),
                NOT_REPORTED
                if connection.destination_port is None
                else str(connection.destination_port),
                str(connection.state),
                _count(connection.packets),
                _count(connection.bytes),
            )
        )
    return rows


def build_connections_section(
    *, analytics: AnalyticsService, window: AnalyticsWindow, limit: int
) -> ReportSection:
    """Build the connection section from M16's connection view (M17.3).

    Two populations are reported and they are not the same population. The live
    counters and the live ranking are M9's tracker: what it holds in memory right
    now, including retired conversations. The stored block is the ``connections``
    table read over the period: the conversations M9 *persisted* that began inside
    it. A report is a historical document, so the stored block is the record; the
    live block is printed beside it because a reader comparing the two needs to
    see that they describe different things (M16.5).

    A conversation's duration is reported only over the conversations that have
    ended, and ``samples`` says how many that is. A conversation still running has
    no duration yet, so counting it as zero would pull the mean down and make the
    report wrong rather than merely incomplete.
    """
    outcome = read_section(
        lambda: analytics.connections(window=window, limit=limit, by=REPORT_RANK_METRIC),
        name="report_connections",
    )
    if not outcome.available or outcome.data is None:
        return _unavailable_section(key="connections", title="Connections")

    view = outcome.data
    stored = view.stored.data if view.stored.available else None

    metrics: list[Metric] = [
        Metric("Conversations tracked now", _count(view.tracked)),
        Metric("Conversations active now", _count(view.active)),
        Metric("Conversations retired now", _count(view.historical)),
        Metric("Ranked by", REPORT_RANK_METRIC),
    ]

    tables: list[ReportTable] = [
        _table(
            key="top_conversations",
            title=f"Busiest conversations, tracked (by {REPORT_RANK_METRIC})",
            columns=CONNECTION_COLUMNS,
            rows=_connection_rows(view.top),
        )
    ]

    if stored is None:
        metrics.append(Metric("Conversations recorded in period", NOT_REPORTED))
        metrics.append(Metric("Conversations active in period", NOT_REPORTED))
        tables.append(
            ReportTable(
                key="stored_connections",
                title="Conversations recorded in period",
                columns=("Measure",),
                rows=(),
                notice=UNAVAILABLE_NOTICE,
            )
        )
        return ReportSection(
            key="connections",
            title="Connections",
            metrics=tuple(metrics),
            tables=tuple(tables),
        )

    metrics.extend(
        [
            Metric("Conversations recorded in period", _count(stored.total)),
            Metric("Conversations active in period", _count(stored.active)),
            Metric("First conversation in period", _text(stored.first_timestamp)),
            Metric("Last conversation in period", _text(stored.last_timestamp)),
            Metric("Ended conversations sampled", _count(stored.duration.samples)),
            Metric(
                "Shortest conversation",
                _text(
                    None
                    if stored.duration.min_seconds is None
                    else f"{stored.duration.min_seconds:.3f} s"
                ),
            ),
            Metric(
                "Mean conversation",
                _text(
                    None
                    if stored.duration.mean_seconds is None
                    else f"{stored.duration.mean_seconds:.3f} s"
                ),
            ),
            Metric(
                "Longest conversation",
                _text(
                    None
                    if stored.duration.max_seconds is None
                    else f"{stored.duration.max_seconds:.3f} s"
                ),
            ),
        ]
    )

    tables.extend(
        [
            _table(
                key="stored_connections_by_protocol",
                title="Conversations in period, by protocol",
                columns=("Protocol", "Conversations"),
                rows=_breakdown_rows(stored.by_protocol),
            ),
            _table(
                key="stored_connections_by_status",
                title="Conversations in period, by state",
                columns=("State", "Conversations"),
                rows=_breakdown_rows(stored.by_status),
            ),
            _table(
                key="stored_connection_series",
                title="Conversations over time",
                columns=("Bucket start (UTC)", "Conversations"),
                rows=[
                    (str(point.start), _count(point.connections))
                    for point in stored.series
                ],
            ),
            _table(
                key="stored_connection_sources",
                title=f"Conversation sources in period (by {REPORT_RANK_METRIC})",
                columns=("Source", "Packets", "Bytes"),
                rows=_ranking_rows(stored.top_sources),
            ),
            _table(
                key="stored_connection_destinations",
                title=f"Conversation destinations in period (by {REPORT_RANK_METRIC})",
                columns=("Destination", "Packets", "Bytes"),
                rows=_ranking_rows(stored.top_destinations),
            ),
        ]
    )

    return ReportSection(
        key="connections", title="Connections", metrics=tuple(metrics), tables=tuple(tables)
    )
#: The severities, statuses, confidence ranges and risk bands a threat section
#: renders, each taken from the milestone that owns the vocabulary rather than
#: re-spelled here. Reusing them is what stops a report from naming a severity
#: the alert engine never produces (M16.6).
THREAT_SEVERITIES: tuple[str, ...] = SEVERITY_KEYS
THREAT_STATUSES: tuple[str, ...] = tuple(STORED_STATUS_VALUES)
THREAT_CONFIDENCE_RANGES: tuple[str, ...] = tuple(CONFIDENCE_RANGE_LABELS)
THREAT_RISK_BANDS: tuple[str, ...] = RISK_BAND_KEYS


def _rule_rows(rules) -> list[tuple[str, ...]]:
    """Render M10's per-detector execution counters as table rows (M16.6)."""
    return [
        (
            str(rule.rule_id),
            str(rule.rule_name or ""),
            "yes" if rule.enabled else "no",
            _count(rule.evaluations),
            _count(rule.findings),
            _count(rule.errors),
        )
        for rule in rules
    ]


def _finding_rule_rows(rows) -> list[tuple[str, ...]]:
    """Render windowed per-rule finding counts as table rows (M16.6)."""
    return [
        (str(row.rule_id), str(row.rule_name or ""), _count(row.findings))
        for row in rows
    ]


def _alert_rule_rows(rows) -> list[tuple[str, ...]]:
    """Render windowed per-detector alert counts as table rows (M16.6)."""
    return [(str(row.rule_key), _count(row.alerts)) for row in rows]


def build_threats_section(
    *, analytics: AnalyticsService, window: AnalyticsWindow
) -> ReportSection:
    """Build the threat section from M16's threat view (M17.3).

    Four layers are reported and they stay four layers, because collapsing them
    would invent a single "threat" number that no milestone produces:

    * **Findings** -- what M10's detectors observed, with no judgement attached.
    * **Alerts by severity and status** -- M11's evidence-based judgement.
    * **Incidents by state and risk band** -- M12's bounded prioritisation metric.
    * **Stored alerts over the period** -- the same M11 table read historically.

    Severity, confidence and risk are kept in three different fields. They answer
    three different questions -- how serious the behaviour is, how strongly the
    engine believed its own evidence, and how much attention the incident deserves
    -- and a report that merged them would misstate all three (M17.9).

    No score is computed here. ``risk_score`` is the column M12 wrote, banded by
    the one table M12 defines.
    """
    outcome = read_section(
        lambda: analytics.threats(window=window),
        name="report_threats",
    )
    if not outcome.available or outcome.data is None:
        return _unavailable_section(key="threats", title="Threats")

    view = outcome.data
    stored = view.stored.data if view.stored.available else None
    findings = view.findings
    links = view.incident_links

    metrics: list[Metric] = [
        Metric("Alerts stored (all time)", _count(view.alerts_total)),
        Metric("Alerts still open", _count(view.alerts_open)),
        Metric("Findings retained by the engine", _count(view.findings_retained)),
        Metric("Detections evaluated this session", _count(view.detections_evaluated)),
        Metric("Findings raised this session", _count(view.detections_findings)),
        Metric("Detection errors this session", _count(view.detections_errors)),
        Metric("Incidents held", _count(view.incidents_total)),
        Metric("Incidents active", _count(view.incidents_active)),
        Metric("Highest incident risk score", _count(view.highest_risk_score)),
        Metric("Findings inside the period", _count(findings.in_window)),
        Metric(
            "Mean finding confidence (0-100 scale)",
            _text(
                None
                if findings.mean_confidence is None
                else f"{findings.mean_confidence:.2f}"
            ),
        ),
        Metric("Incidents referencing alerts", _count(links.incidents_with_alerts)),
        Metric("Distinct alerts referenced by incidents", _count(links.alerts_in_incidents)),
    ]

    tables: list[ReportTable] = [
        _table(
            key="alerts_by_severity",
            title="Alerts by severity (all time)",
            columns=("Severity", "Alerts"),
            rows=_breakdown_rows(view.alerts_by_severity, order=THREAT_SEVERITIES),
        ),
        _table(
            key="alerts_by_status",
            title="Alerts by lifecycle status (all time)",
            columns=("Status", "Alerts"),
            rows=_breakdown_rows(view.alerts_by_status, order=THREAT_STATUSES),
        ),
        _table(
            key="detection_rules",
            title="Detector execution counters this session",
            columns=("Rule", "Name", "Enabled", "Evaluations", "Findings", "Errors"),
            rows=_rule_rows(view.rules),
        ),
        _table(
            key="incidents_by_status",
            title="Incidents by lifecycle status",
            columns=("Status", "Incidents"),
            rows=_breakdown_rows(view.incidents_by_status),
        ),
        _table(
            key="incidents_by_risk_band",
            title="Incidents by risk band",
            columns=("Risk band", "Incidents"),
            rows=_breakdown_rows(view.incidents_by_risk_band, order=THREAT_RISK_BANDS),
        ),
        _table(
            key="findings_by_rule",
            title="Findings in period, by detector",
            columns=("Rule", "Name", "Findings"),
            rows=_finding_rule_rows(findings.by_rule),
        ),
        _table(
            key="findings_by_confidence",
            title="Findings in period, by confidence range",
            columns=("Confidence range", "Findings"),
            rows=_breakdown_rows(
                findings.by_confidence_range, order=THREAT_CONFIDENCE_RANGES
            ),
        ),
    ]

    if stored is None:
        metrics.append(Metric("Alerts recorded in period", NOT_REPORTED))
        tables.append(
            ReportTable(
                key="stored_alerts",
                title="Alerts recorded in period",
                columns=("Measure",),
                rows=(),
                notice=UNAVAILABLE_NOTICE,
            )
        )
        return ReportSection(
            key="threats", title="Threats", metrics=tuple(metrics), tables=tuple(tables)
        )

    metrics.extend(
        [
            Metric("Alerts recorded in period", _count(stored.total)),
            Metric("Alerts in period with no rule key", _count(stored.without_rule_key)),
            Metric("First alert in period", _text(stored.first_timestamp)),
            Metric("Last alert in period", _text(stored.last_timestamp)),
        ]
    )
    tables.extend(
        [
            _table(
                key="stored_alerts_by_severity",
                title="Alerts in period, by severity",
                columns=("Severity", "Alerts"),
                rows=_breakdown_rows(stored.by_severity, order=THREAT_SEVERITIES),
            ),
            _table(
                key="stored_alerts_by_status",
                title="Alerts in period, by lifecycle status",
                columns=("Status", "Alerts"),
                rows=_breakdown_rows(stored.by_status, order=THREAT_STATUSES),
            ),
            _table(
                key="stored_alerts_by_risk_band",
                title="Alerts in period, by risk band",
                columns=("Risk band", "Alerts"),
                rows=_breakdown_rows(stored.by_risk_band, order=THREAT_RISK_BANDS),
            ),
            _table(
                key="stored_alerts_by_confidence",
                title="Alerts in period, by confidence range",
                columns=("Confidence range", "Alerts"),
                rows=_breakdown_rows(
                    stored.by_confidence_range, order=THREAT_CONFIDENCE_RANGES
                ),
            ),
            _table(
                key="stored_alert_rules",
                title="Alerts in period, by detector",
                columns=("Rule", "Alerts"),
                rows=_alert_rule_rows(stored.rules),
            ),
            _table(
                key="stored_alert_series",
                title="Alerts over time",
                columns=("Bucket start (UTC)", "Alerts"),
                rows=[
                    (str(point.start), _count(point.alerts)) for point in stored.series
                ],
            ),
        ]
    )

    return ReportSection(
        key="threats", title="Threats", metrics=tuple(metrics), tables=tuple(tables)
    )
# ---------------------------------------------------------------------------
# The executive summary and the whole-content builder
# ---------------------------------------------------------------------------

#: The headline figures the summary lifts out of the body, as
#: ``(section key, metric label)`` pairs. Naming them explicitly is what makes the
#: summary *checkable*: a test asserts each pair resolves, so renaming a section's
#: metric without updating the summary fails the suite rather than silently
#: dropping a headline figure from every future report.
HEADLINE_METRICS: tuple[tuple[str, str], ...] = (
    ("traffic", "Packets stored in period"),
    ("traffic", "Bytes stored in period (scaled)"),
    ("protocols", "Protocols recorded in period"),
    ("devices", "Devices known to the registry"),
    ("devices", "Devices observed in period"),
    ("connections", "Conversations recorded in period"),
    ("threats", "Alerts recorded in period"),
    ("threats", "Findings inside the period"),
    ("threats", "Highest incident risk score"),
)


def _metric_value(section: ReportSection | None, label: str) -> str:
    """Return one metric's rendered value from a section, or the not-reported text.

    A missing metric is reported as not-reported rather than omitted: a summary
    with a silently absent line would look complete while saying less.
    """
    if section is None or not section.available:
        return NOT_REPORTED
    for metric in section.metrics:
        if metric.label == label:
            return metric.value
    return NOT_REPORTED


def build_summary(
    *,
    title: str,
    period: ReportPeriod,
    output_format: str,
    generated_at: str,
    sections: tuple[ReportSection, ...],
) -> tuple[Metric, ...]:
    """Build the executive summary: the report's identity plus its headline figures.

    The identity block comes first and is not negotiable -- which report, which
    format, which period -- because every later number is meaningless without it.
    A reader who picks up one file out of a sequence must be able to tell which day
    it covers without consulting anything else, and a file that carried only tables
    would not say (M17.3).

    The headline figures are lifted from the sections by name rather than
    recomputed, so a summary can never disagree with the body it summarises.
    """
    by_key = {section.key: section for section in sections}
    metrics: list[Metric] = [
        Metric("Report title", title),
        Metric("Report type", period.report_type),
        Metric("Output format", output_format),
        Metric("Generated at (UTC)", generated_at),
        Metric("Period start (inclusive, UTC)", period.iso_since()),
        Metric("Period end (exclusive, UTC)", period.iso_until()),
        Metric("Period length (seconds)", f"{period.seconds:.0f}"),
        Metric("Period described as", period.label()),
    ]
    metrics.extend(
        Metric(label, _metric_value(by_key.get(section_key), label))
        for section_key, label in HEADLINE_METRICS
    )
    return tuple(metrics)


def build_report_content(
    *,
    analytics: AnalyticsService,
    period: ReportPeriod,
    output_format: str,
    generated_at: str,
    report_id: int | None = None,
    title: str | None = None,
    row_limit: int = REPORT_ROW_LIMIT,
) -> ReportContent:
    """Assemble one complete report from the analytics layer (M17.3).

    This is the single entry point the service and the renderers use. It resolves
    the analytics window, builds the five body sections and the summary and returns
    them as one :class:`~app.reports.content.ReportContent`. It reads nothing else
    and writes nothing: persistence is the service's job, so this function is
    testable without a database write and a renderer is testable without a service.

    Args:
        analytics: The M16 analytics service, bound to this request's session.
        period: The resolved, bounded reporting period.
        output_format: ``CSV`` or ``PDF``, recorded in the content so a reader of
            the file can see which format was asked for.
        generated_at: The generation instant, ISO-8601 UTC.
        report_id: The stored metadata id, when one already exists.
        title: The report title. Defaults to a name derived from the period, so a
            caller that has no preference still gets a report that identifies
            itself.
        row_limit: How many rows each ranking carries. Defaults to the analytics
            layer's own group cap (M17.13).

    Returns:
        The assembled content, ready to render.
    """
    window = analytics_window_for(period)
    resolved_title = title or default_title(period, output_format)

    sections: tuple[ReportSection, ...] = (
        build_traffic_section(analytics=analytics, window=window, limit=row_limit),
        build_protocols_section(analytics=analytics, window=window),
        build_devices_section(analytics=analytics, window=window, limit=row_limit),
        build_connections_section(analytics=analytics, window=window, limit=row_limit),
        build_threats_section(analytics=analytics, window=window),
    )

    return ReportContent(
        report_id=report_id,
        title=resolved_title,
        report_type=period.report_type,
        output_format=output_format,
        generated_at=generated_at,
        period_start=period.iso_since(),
        period_end=period.iso_until(),
        period_seconds=period.seconds,
        summary=build_summary(
            title=resolved_title,
            period=period,
            output_format=output_format,
            generated_at=generated_at,
            sections=sections,
        ),
        sections=sections,
    )


def default_title(period: ReportPeriod, output_format: str) -> str:
    """Return the title a report carries when the caller names none.

    The title names the period rather than the moment of generation, because the
    period is what distinguishes one report from the next: five daily reports
    generated in the same hour must have five different names, and a name built
    from the generation time would not give them one (M17.6).
    """
    kind = period.report_type.capitalize()
    return f"{kind} network report {period.label()} ({output_format.upper()})"


__all__ = [
    "DEVICE_COLUMNS",
    "CONNECTION_COLUMNS",
    "HEADLINE_METRICS",
    "KNOWN_STATUSES",
    "NO_ROWS_NOTICE",
    "REPORT_RANK_METRIC",
    "REPORT_ROW_LIMIT",
    "THREAT_CONFIDENCE_RANGES",
    "THREAT_RISK_BANDS",
    "THREAT_SEVERITIES",
    "THREAT_STATUSES",
    "UNAVAILABLE_NOTICE",
    "analytics_window_for",
    "build_connections_section",
    "build_devices_section",
    "build_protocols_section",
    "build_report_content",
    "build_summary",
    "build_threats_section",
    "build_traffic_section",
    "default_title",
]
