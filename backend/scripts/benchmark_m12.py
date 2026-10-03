"""M12 performance baseline - correlation and risk scoring cost (M12.34).

Measures what M12 adds on top of the M10/M11 layers that already ran:

  * findings correlated per second and alerts correlated per second,
  * the correlation lookup cost, split into the three paths that actually
    differ: opening a new incident (no candidate matches), joining one (a
    candidate matches), and deduplicating (the event was already folded in),
  * risk calculation time per score, plus the cost of building the scorer's
    input from an incident,
  * Python memory held while incidents accumulate (``tracemalloc``),
  * active incident count and the store's bounded behaviour under its cap,
  * internal incident-query response time (M12.26). M12 ships no REST API yet,
    so these are the engine's own read paths, not wire response times.

This is a local, single-machine baseline for the M12 correlation and risk code
only. It is NOT a production-capacity claim: it excludes real capture
(Scapy/Npcap), M5 normalization, the M6-M11 consumers, the network stack and
JSON serialization at the wire. The incident store is memory-resident, so unlike
M11 these figures are not dominated by SQLite; the database appears only in the
optional risk-persistence path, which this baseline deliberately leaves unwired
so that what is measured is correlation itself.

The clock is fixed for the run, so scoring is deterministic and the retention
sweep runs once rather than on every event. No database is created and nothing
on disk is touched.

The defaults are small on purpose, and the reason is the baseline's main finding:
with no match, every held incident is *evaluated* against the incoming event
before the engine can conclude there is none. That is O(held incidents) per
event, so N distinct incidents cost O(N^2) relationship evaluations in total. At
2000 held incidents the default measures roughly 12 ms per finding, and it is
this term, not normalization or scoring, that dominates correlation cost. The
defaults keep a full run well under a minute; ``--max-incidents`` bounds how far
the term can grow. The tracemalloc phase uses a smaller count for the same
reason, because tracing every allocation multiplies it further.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m12.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m12.py --findings 8000
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m12.py --alerts 5000 --per-group 8
"""

from __future__ import annotations

import argparse
import logging
import statistics as stats
import sys
import time
import tracemalloc
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.alerts.alert import Alert  # noqa: E402
from app.alerts.severity import AlertSeverity  # noqa: E402
from app.alerts.timestamps import to_utc_datetime  # noqa: E402
from app.correlation.engine import CorrelationEngine  # noqa: E402
from app.correlation.event import (  # noqa: E402
    CorrelationEvent,
    EventKind,
    finding_event_id,
)
from app.correlation.incident import CorrelatedIncident  # noqa: E402
from app.correlation.registry import (  # noqa: E402
    IncidentOrder,
    IncidentQuery,
    IncidentRegistry,
)
from app.correlation.relationship import DEFAULT_ANCHOR_THRESHOLD  # noqa: E402
from app.correlation.window import CorrelationWindow  # noqa: E402
from app.detection.finding import DetectionFinding  # noqa: E402
from app.risk.contributions import ScoringBounds  # noqa: E402
from app.risk.engine import RiskScoringEngine  # noqa: E402
from app.risk.inputs import RiskInputs  # noqa: E402

_BANNER_WIDTH = 66

# A fixed observation time, so every synthetic event shares one window and the
# run is comparable between invocations.
_PAST_TIMESTAMP = 1_000_000.0

#: How far the fixed clock sits after the observation time. Small, positive and
#: constant, so the recency term is exercised (an age of zero would make the term
#: constant at its maximum) without letting retention expire anything mid-run.
_CLOCK_SKEW_SECONDS = 5.0

#: The two detectors used. Alternating them inside a group lets the scan-sequence
#: rule match as well as the same-source rule, which is the realistic mix.
_RULES = ("port_scan", "internal_scan")

#: The two rules the risk phase scores, so the model sees more than one detector.
_BENCH_RULE_IDS = ("port_scan", "internal_scan")

# Correlation model under test. Mirrors the documented defaults, stated
# explicitly so the printed configuration is what actually ran (M12.5/M12.7).
_WINDOW_SECONDS = 900.0
_PROXIMITY_SECONDS = 300.0
_RETENTION_SECONDS = 3600.0
_MIN_CONFIDENCE = 0.5
_MAX_MEMBERS = 32
_MAX_REASONS = 16

# Risk model under test (M12.15). Bounded so the formula's terms are normalized
# against fixed references rather than against whatever the run happened to see.
_VOLUME_ALERTS = 5
_HISTORICAL_OCCURRENCES = 5
_RECENCY_SECONDS = 3600.0
_ML_ENABLED = False


class FixedClock:
    """A clock the benchmark drives, so scoring and sweeping are deterministic.

    Correlation expires context by age and scores recency by age. Pinning the
    clock makes a score a pure function of its inputs and stops the retention
    sweep from running on every event, which would otherwise be charged to the
    ingestion path it is not really part of (M12.22).
    """

    def __init__(self, now: float = _PAST_TIMESTAMP + _CLOCK_SKEW_SECONDS) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        """Return the current epoch seconds."""
        return self.now

    def advance(self, seconds: float) -> float:
        """Move the clock forward and return the new time."""
        self.now += float(seconds)
        return self.now


def _source_ip(index: int) -> str:
    """Return a unique private address for event ``index``.

    Unique so each event is genuinely unrelated to the ones before it: the
    distinct-incident phase measures the cost of finding *no* match, and a shared
    address would quietly turn it into a correlation benchmark instead.
    """
    return f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"


def _group_ip(group: int) -> str:
    """Return one source address per related group.

    Every event in a group shares this address, which is what makes the group
    correlate; two groups never share one, so groups stay separate incidents.
    """
    return f"192.168.{group // 256}.{group % 256}"


def _incident_destination(group: int) -> str:
    """Return the destination address of incident group ``group``.

    198.18.0.0/15 is the block reserved for benchmarking (RFC 2544), which is the
    honest place for a synthetic destination. It is unique per group because a
    shared destination *anchors* correlation (M12.6): with one fixed destination
    every synthetic event related to every other, and the no-match phase then
    measured the join path instead of the no-match one.
    """
    return f"198.18.{group // 256}.{group % 256}"


def _finding(
    *, source_ip: str, destination_ip: str, rule_id: str
) -> DetectionFinding:
    """Build one synthetic M10 finding, shaped as a detector would emit it."""
    return DetectionFinding(
        rule_id=rule_id,
        rule_name=rule_id.replace("_", " ").title(),
        timestamp=_PAST_TIMESTAMP,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        description=f"Benchmark {rule_id} observation",
        evidence={"rule_id": rule_id, "source": "benchmark_m12"},
        confidence=0.8,
    )


def _alert(
    index: int, *, source_ip: str, destination_ip: str, rule_id: str
) -> Alert:
    """Build one synthetic M11 alert, shaped as the alert layer would emit it.

    Built directly rather than through the alert service: the question is what
    correlating an alert costs, and routing these through M11's SQLite writes
    would bury that under the database cost M11's own baseline already reports.
    A unique ``alert_id`` is what makes each one a distinct correlation event.
    """
    return Alert(
        alert_id=index + 1,
        rule_id=rule_id,
        title=rule_id.replace("_", " ").title(),
        description=f"Benchmark {rule_id} alert",
        severity=AlertSeverity.HIGH,
        confidence=0.8,
        # Set, or the alert carries no observation time and correlation cannot
        # date it at all: ``from_alert`` refuses an untimed alert rather than
        # guessing, which is exactly what the first run of this script did.
        created_at=to_utc_datetime(_PAST_TIMESTAMP),
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        finding_id=f"bench-finding-{index}",
        correlation_key=f"{rule_id}|{source_ip}|203.0.113.9|TCP|-",
    )


def _event(index: int, *, source_ip: str, rule_id: str) -> CorrelationEvent:
    """Build one normalized correlation event, bypassing the source models.

    The cheapest legitimate input, used by the deduplication phase, where the
    cost being measured is the store's identity lookup rather than normalization.
    """
    return CorrelationEvent(
        event_id=finding_event_id(f"bench-{index}"),
        kind=EventKind.FINDING,
        timestamp=_PAST_TIMESTAMP,
        rule_id=rule_id,
        title=rule_id.replace("_", " ").title(),
        confidence=0.8,
        source_ip=source_ip,
        destination_ip="203.0.113.9",
        protocol="TCP",
    )


def _build_engine(
    *,
    max_incidents: int,
    retention_seconds: float = _RETENTION_SECONDS,
    clock: FixedClock | None = None,
) -> CorrelationEngine:
    """Build a correlation engine over an explicit, documented configuration.

    Every bound is stated rather than defaulted, so the printed configuration is
    what actually ran: the window (M12.5), the anchor threshold (M12.4/M12.6),
    the confidence floor (M12.7), the store's caps (M12.22) and the scoring
    bounds (M12.15). No risk-persistence writer is wired, so the figures measure
    correlation itself and not a database round trip (M12.24).
    """
    source = clock if clock is not None else FixedClock()
    return CorrelationEngine(
        window=CorrelationWindow(
            seconds=_WINDOW_SECONDS,
            proximity_seconds=_PROXIMITY_SECONDS,
            max_span_seconds=_WINDOW_SECONDS,
        ),
        registry=IncidentRegistry(
            max_incidents=max_incidents,
            retention_seconds=retention_seconds,
            max_members=_MAX_MEMBERS,
            max_reasons=_MAX_REASONS,
            clock=source,
        ),
        risk=RiskScoringEngine(
            ScoringBounds(
                volume_alerts=_VOLUME_ALERTS,
                historical_occurrences=_HISTORICAL_OCCURRENCES,
                recency_seconds=_RECENCY_SECONDS,
                ml_enabled=_ML_ENABLED,
            )
        ),
        anchor_threshold=DEFAULT_ANCHOR_THRESHOLD,
        min_confidence=_MIN_CONFIDENCE,
        clock=source,
    )


def _incident_counters(engine: CorrelationEngine) -> dict[str, object]:
    """Return the incident store's counters, which every phase reports (M12.34)."""
    snapshot = engine.stats()
    counters = snapshot["incidents"]
    assert isinstance(counters, dict)
    return counters


def _int_counter(counters: dict[str, object], key: str) -> int:
    """Return one counter as an int, or ``0`` when it is absent or not an int.

    The store reports its counters as a mapping of ``str`` to ``object``, so this
    is the one place that narrowing happens. A diagnostic must not be able to
    fail a measurement, so a missing or non-integer counter reads as ``0`` rather
    than raising.
    """
    value = counters.get(key)
    return int(value) if isinstance(value, int) else 0


def _rate(count: int, elapsed: float) -> float:
    """Return ``count`` per second, or ``0.0`` for a zero-length measurement."""
    return count / elapsed if elapsed > 0 else 0.0


def _micros(count: int, elapsed: float) -> float:
    """Return microseconds per item, or ``0.0`` for an empty measurement."""
    return (elapsed / count) * 1_000_000 if count else 0.0


def benchmark_findings(
    findings: int, *, max_incidents: int
) -> tuple[CorrelationEngine, list[CorrelatedIncident]]:
    """Time the distinct-incident path: one M10 finding, one incident each.

    Each finding comes from a different source, so no candidate ever matches and
    this measures the *no-match* lookup cost - the path every genuinely new
    observation takes (M12.34).
    """
    engine = _build_engine(max_incidents=max_incidents)
    # Built outside the timed region: this is synthetic input construction, not
    # correlation work, and it would otherwise be charged to the figures.
    batch = [
        _finding(
            source_ip=_source_ip(index),
            destination_ip=_incident_destination(index),
            rule_id=_RULES[index % len(_RULES)],
        )
        for index in range(findings)
    ]

    start = time.perf_counter()
    for item in batch:
        engine.correlate_finding(item)
    elapsed = time.perf_counter() - start

    counters = _incident_counters(engine)
    created = _int_counter(counters, "incidents_created")
    engine_errors = _int_counter(engine.stats(), "errors")
    store_errors = _int_counter(counters, "errors")

    print("=" * _BANNER_WIDTH)
    print("M12 PERFORMANCE BASELINE - correlation and risk scoring (M12.34)")
    print("=" * _BANNER_WIDTH)
    print("--- Findings correlated: one distinct incident per finding ---")
    print(f"  findings correlated   : {findings:,}")
    print(f"  incidents created     : {created:,}")
    print(f"  wall time             : {elapsed:.3f} s")
    print(f"  findings/sec          : {_rate(findings, elapsed):,.0f}")
    print(f"  per finding           : {_micros(findings, elapsed):.1f} us")
    print(f"  errors                : {engine_errors + store_errors:,}")
    print(
        "  note                  : every held incident is scanned and rejected "
        "per event,\n"
        "                          so this is the no-match lookup cost and it "
        "grows with the\n"
        "                          number of held incidents (bounded by the cap, "
        "M12.22)"
    )
    return engine, engine.get_incidents(IncidentQuery(limit=200))


def benchmark_alerts(alerts: int, *, per_group: int, max_incidents: int) -> None:
    """Time the join path: many alerts folding into few incidents.

    Alerts are grouped by source, ``per_group`` at a time, so the first alert of
    each group opens an incident and the rest join it. That is the shape real
    traffic produces - one actor doing several things - and it exercises the
    match path rather than the no-match one (M12.10/M12.34).
    """
    engine = _build_engine(max_incidents=max_incidents)
    batch = [
        _alert(
            index,
            source_ip=_group_ip(index // per_group),
            destination_ip=_incident_destination(index // per_group),
            rule_id=_RULES[index % len(_RULES)],
        )
        for index in range(alerts)
    ]

    start = time.perf_counter()
    for item in batch:
        engine.correlate_alert(item)
    elapsed = time.perf_counter() - start

    counters = _incident_counters(engine)
    created = _int_counter(counters, "incidents_created")
    joined = _int_counter(counters, "correlations_matched")
    errors = _int_counter(counters, "errors") + _int_counter(engine.stats(), "errors")
    groups = max((alerts + per_group - 1) // per_group, 1)
    # Measured from the incidents that were actually built, not derived from the
    # input grouping: a derived figure would still read 5.0 per incident even if
    # every alert had failed, which is precisely what the first run did.
    held = engine.get_incidents()
    members = (
        sum(incident.alert_count() for incident in held) / len(held) if held else 0.0
    )

    print("\n--- Alerts correlated: many alerts folding into few incidents ---")
    print(f"  alerts correlated     : {alerts:,}")
    print(f"  correlation groups    : {groups:,} (up to {per_group} alerts each)")
    print(f"  incidents created     : {created:,}")
    print(f"  alerts matched into one: {joined:,}")
    print(f"  alerts per incident   : {members:.1f} (measured)")
    print(f"  wall time             : {elapsed:.3f} s")
    print(f"  alerts/sec            : {_rate(alerts, elapsed):,.0f}")
    print(f"  per alert             : {_micros(alerts, elapsed):.1f} us")
    print(f"  errors                : {errors:,}")
    print(
        "  note                  : the matching incident is the most recently "
        "active one,\n"
        "                          so it is found early in the candidate scan"
    )


def benchmark_dedup(repeats: int, *, max_incidents: int) -> None:
    """Time the deduplication path: one event identity observed repeatedly.

    Correlation deduplication answers "has this event already been folded in?"
    rather than M11's "is this the same alert?" (M12.11), and it is an O(1)
    identity lookup. Measuring it separately is what keeps that claim checkable
    rather than asserted.
    """
    engine = _build_engine(max_incidents=max_incidents)
    event = _event(0, source_ip=_source_ip(0), rule_id=_RULES[0])
    engine.correlate_event(event)  # untimed: the first observation creates

    start = time.perf_counter()
    for _ in range(repeats):
        engine.correlate_event(event)
    elapsed = time.perf_counter() - start

    counters = _incident_counters(engine)
    skipped = _int_counter(counters, "duplicates_skipped")

    print("\n--- Deduplication: one event identity observed repeatedly ---")
    print(f"  repeats               : {repeats:,}")
    print(f"  duplicates reported   : {skipped:,}")
    print(f"  incidents held        : {_int_counter(counters, 'incidents'):,}")
    print(f"  wall time             : {elapsed:.3f} s")
    print(f"  dedup lookups/sec     : {_rate(repeats, elapsed):,.0f}")
    print(f"  per lookup            : {_micros(repeats, elapsed):.2f} us")
    print(
        "  note                  : incident membership did not grow, which is "
        "the point of\n"
        "                          M12.11 - a repeat must not inflate the "
        "incident or its score"
    )
#: A source address space reserved for the query phase, so its seeded incidents
#: never overlap the ones the throughput phases built.
_QUERY_SOURCE_PREFIX = "10.77"


def _query_event(
    index: int,
    *,
    source_ip: str,
    destination_ip: str,
    rule_id: str,
    device_id: str,
    destination_device_id: str,
    connection_id: str,
) -> CorrelationEvent:
    """Build a fully-populated event, so every M12.26 query has something to find.

    The throughput phases deliberately carry addresses only. A query benchmark
    needs the other dimensions present too - a device and a conversation - or the
    device and connection reads would time an empty result and the figure would
    be meaningless.
    """
    return CorrelationEvent(
        event_id=finding_event_id(f"query-{index}"),
        kind=EventKind.FINDING,
        timestamp=_PAST_TIMESTAMP,
        rule_id=rule_id,
        title=rule_id.replace("_", " ").title(),
        confidence=0.8,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_device_id=device_id,
        destination_device_id=destination_device_id,
        protocol="TCP",
        connection_id=connection_id,
    )


def benchmark_risk(
    incidents: list[CorrelatedIncident], *, iterations: int
) -> None:
    """Time the risk formula, and the bridge from an incident into it.

    Two different costs, measured separately because they belong to different
    layers: scoring a set of inputs is the formula (M12.17), while building those
    inputs from an incident is the one bridge between correlation and scoring
    (M12.15). A low-context and a high-context input are alternated so the
    figures cover both ends of the model rather than one convenient case.
    """
    engine = RiskScoringEngine(
        ScoringBounds(
            volume_alerts=_VOLUME_ALERTS,
            historical_occurrences=_HISTORICAL_OCCURRENCES,
            recency_seconds=_RECENCY_SECONDS,
            ml_enabled=_ML_ENABLED,
        )
    )
    low = RiskInputs(
        severity="low",
        confidences=(0.25,),
        rule_ids=("port_scan",),
        last_seen=_PAST_TIMESTAMP,
        now=_PAST_TIMESTAMP + _CLOCK_SKEW_SECONDS,
    )
    high = RiskInputs.from_parts(
        severity="high",
        confidences=(0.9, 0.9, 0.9, 0.9, 0.85, 0.8, 0.8, 0.75),
        alert_count=8,
        rule_ids=_BENCH_RULE_IDS,
        device_ids=tuple(f"mac:RISK-{index}" for index in range(4)),
        connection_ids=tuple(f"conn-{index}" for index in range(4)),
        last_seen=_PAST_TIMESTAMP,
        now=_PAST_TIMESTAMP + _CLOCK_SKEW_SECONDS,
        historical_occurrences=3,
        correlation_confidence=0.9,
    )

    low_score = engine.score(low)
    high_score = engine.score(high)

    start = time.perf_counter()
    for index in range(iterations):
        engine.score(low if index % 2 == 0 else high)
    elapsed = time.perf_counter() - start

    print("\n--- Risk calculation: the scoring formula ---")
    print(f"  scores computed       : {iterations:,}")
    print(f"  wall time             : {elapsed:.3f} s")
    print(f"  scores/sec            : {_rate(iterations, elapsed):,.0f}")
    print(f"  per score             : {_micros(iterations, elapsed):.2f} us")
    print(
        f"  low-context sample    : score={low_score.score} "
        f"band={low_score.band.value} "
        f"alert_confidence={low_score.alert_confidence:.2f}"
    )
    print(
        f"  high-context sample   : score={high_score.score} "
        f"band={high_score.band.value} "
        f"alert_confidence={high_score.alert_confidence:.2f} "
        f"correlation_confidence={high_score.correlation_confidence:.2f}"
    )
    print(f"  ml_available          : {low_score.ml_available} (M12.18)")

    if not incidents:
        print("  incident bridge       : skipped (no incident to build inputs from)")
        return

    sample = incidents[0]
    now = _PAST_TIMESTAMP + _CLOCK_SKEW_SECONDS
    start = time.perf_counter()
    for _ in range(iterations):
        sample.to_risk_inputs(now=now)
    bridge_elapsed = time.perf_counter() - start
    print(
        f"  incident -> inputs    : "
        f"{_micros(iterations, bridge_elapsed):.2f} us "
        f"({_rate(iterations, bridge_elapsed):,.0f}/s, M12.15)"
    )


def _time_reads(
    label: str, read, *, iterations: int
) -> tuple[float, float]:
    """Time one read path and return ``(mean, max)`` in milliseconds.

    The result is consumed (its length is taken) so the interpreter cannot discard
    the call, which would time nothing at all.
    """
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = read()
        samples.append((time.perf_counter() - start) * 1000.0)
        len(result)
    print(f"  {label:<40} avg {stats.mean(samples):7.3f} ms  max {max(samples):7.3f} ms")
    return stats.mean(samples), max(samples)


def benchmark_queries(*, incidents: int, per_group: int, iterations: int) -> None:
    """Time every M12.26 read path over a populated store.

    M12 ships no REST API yet, so these are the engine's own reads rather than
    wire response times; they are still the number an API layer would be built
    on, which is why the baseline records them (M12.26/M12.34).
    """
    engine = _build_engine(max_incidents=max(incidents, 1024))
    groups = max(incidents // per_group, 1)
    for index in range(incidents):
        group = index // per_group
        engine.correlate_event(
            _query_event(
                index,
                source_ip=f"{_QUERY_SOURCE_PREFIX}.{group // 256}.{group % 256}",
                # TEST-NET-2 (RFC 5737), unique per group for the same reason as
                # the source address: a shared destination would anchor every
                # seeded event together and collapse the store into one incident.
                destination_ip=f"198.51.{group // 256}.{group % 256}",
                rule_id=_RULES[index % len(_RULES)],
                device_id=f"mac:QUERY-SRC-{group}",
                # Unique per group. A single shared destination device would make
                # every seeded event correlate with every other - same_device is
                # an anchoring relationship (M12.6) - and collapse the store into
                # one incident, which is what the first run of this script did.
                destination_device_id=f"mac:QUERY-DST-{group}",
                connection_id=f"conn-query-{group}",
            )
        )

    held = engine.count_incidents()
    first = engine.get_incidents(IncidentQuery(limit=1))
    print("\n--- Incident query response time (M12.26) ---")
    print(f"  store size            : {held:,} incident(s) from {incidents:,} events")
    if not first:
        print("  skipped               : no incident was available to query by")
        return

    sample = first[0]
    device_id = next(iter(sorted(sample.identity.devices)), "mac:QUERY-0")
    source_ip = next(
        iter(sorted(sample.identity.source_addresses)),
        f"{_QUERY_SOURCE_PREFIX}.0.0",
    )
    rule_id = next(iter(sorted(sample.rule_ids)), _RULES[0])

    _time_reads(
        "recent_incidents(100)", lambda: engine.recent_incidents(limit=100), iterations=iterations
    )
    _time_reads(
        "open_incidents(100)", lambda: engine.open_incidents(limit=100), iterations=iterations
    )
    _time_reads(
        "incidents_by_risk(100)", lambda: engine.incidents_by_risk(limit=100), iterations=iterations
    )
    _time_reads(
        "incidents_for_source(100)",
        lambda: engine.incidents_for_source(source_ip, limit=100),
        iterations=iterations,
    )
    _time_reads(
        "incidents_for_device(100)",
        lambda: engine.incidents_for_device(device_id, limit=100),
        iterations=iterations,
    )
    _time_reads(
        "incidents_for_rule(100)",
        lambda: engine.incidents_for_rule(rule_id, limit=100),
        iterations=iterations,
    )
    _time_reads(
        "incidents_in_range(100)",
        lambda: engine.incidents_in_range(
            since=_PAST_TIMESTAMP - 60.0, until=_PAST_TIMESTAMP + 60.0, limit=100
        ),
        iterations=iterations,
    )
    _time_reads(
        "get_incidents(RISK order, 100)",
        lambda: engine.get_incidents(
            IncidentQuery(limit=100, order=IncidentOrder.RISK)
        ),
        iterations=iterations,
    )
    _time_reads(
        "get_incidents(CONFIDENCE order, 100)",
        lambda: engine.get_incidents(
            IncidentQuery(limit=100, order=IncidentOrder.CONFIDENCE)
        ),
        iterations=iterations,
    )
    _time_reads(
        "count_incidents()", lambda: [engine.count_incidents()], iterations=iterations
    )
    _time_reads(
        "get_incident(id)",
        lambda: [engine.get_incident(sample.incident_id)],
        iterations=iterations,
    )

    correlation_rules = sorted(sample.correlation_rule_ids)
    if correlation_rules:
        _time_reads(
            "incidents_for_rule(correlation, 100)",
            lambda: engine.incidents_for_rule(
                correlation_rules[0], correlation=True, limit=100
            ),
            iterations=iterations,
        )


def benchmark_memory(count: int, *, max_incidents: int) -> None:
    """Measure the Python heap held while incidents accumulate (M12.34).

    ``tracemalloc`` adds substantial overhead, so this runs separately from the
    throughput measurement and only its memory figures should be read. The batch
    of input findings is built before tracing starts, so the growth reported is
    the incidents the store holds and not the synthetic input that produced them.
    """
    engine = _build_engine(max_incidents=max_incidents)
    batch = [
        _finding(
            source_ip=_source_ip(index),
            destination_ip=_incident_destination(index),
            rule_id=_RULES[index % len(_RULES)],
        )
        for index in range(count)
    ]

    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    for item in batch:
        engine.correlate_finding(item)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    held = engine.count_incidents()
    growth = max(current - before, 0)
    per_incident = growth / held if held else 0.0

    print("\n--- Memory (tracemalloc, incident store) ---")
    print(f"  events ingested       : {count:,}")
    print(f"  incidents held        : {held:,}")
    print(f"  heap before           : {before / 1024 / 1024:.2f} MiB")
    print(f"  heap after            : {current / 1024 / 1024:.2f} MiB")
    print(f"  peak heap             : {peak / 1024 / 1024:.2f} MiB")
    print(f"  per held incident     : {per_incident:.0f} bytes")
    print(
        "  note                  : the input findings were built before tracing "
        "started, so\n"
        "                          this is the store's own footprint; it is "
        "bounded by the\n"
        "                          incident cap (M12.22)"
    )


def benchmark_bounded(events: int, *, cap: int) -> None:
    """Push past the store's cap and prove the bound holds (M12.22).

    The throughput phases size the cap to the workload so eviction does not
    dominate their figures. This phase does the opposite on purpose: a small cap
    and more distinct incidents than it can hold, which is what makes "bounded"
    measurable rather than asserted. It also times a full retention sweep, which
    is the other half of bounded runtime state.
    """
    clock = FixedClock()
    engine = _build_engine(max_incidents=cap, clock=clock)
    batch = [
        _finding(
            source_ip=_source_ip(index),
            destination_ip=_incident_destination(index),
            rule_id=_RULES[index % len(_RULES)],
        )
        for index in range(events)
    ]

    start = time.perf_counter()
    for item in batch:
        engine.correlate_finding(item)
    elapsed = time.perf_counter() - start

    counters = _incident_counters(engine)
    held = _int_counter(counters, "incidents")
    active = _int_counter(counters, "active_incidents")
    evicted = _int_counter(counters, "evicted_incidents")
    seen = _int_counter(counters, "seen_events")

    print("\n--- Bounded state: the store's cap and a retention sweep (M12.22) ---")
    print(f"  cap on held incidents : {cap:,}")
    print(f"  distinct incidents fed: {events:,}")
    print(f"  incidents held after  : {held:,}")
    print(f"  active incidents      : {active:,}")
    print(f"  incidents evicted     : {evicted:,}")
    print(f"  event identities seen : {seen:,}")
    print(f"  ingest wall time      : {elapsed:.3f} s")
    print(f"  events/sec            : {_rate(events, elapsed):,.0f}")
    print(f"  per event             : {_micros(events, elapsed):.1f} us")
    print(f"  cap held              : {'yes' if held <= cap else 'NO'}")

    # A full sweep, forced by moving the clock past the retention age. Nothing is
    # dropped until this point because the clock was pinned, which is what makes
    # the sweep a single measurable pass rather than a per-event cost.
    clock.advance(_RETENTION_SECONDS + 60.0)
    start = time.perf_counter()
    expired = engine.expire_old_context()
    sweep_elapsed = time.perf_counter() - start
    remaining = engine.count_incidents()
    print(
        f"  retention sweep       : expired {expired:,} in "
        f"{sweep_elapsed * 1000.0:.3f} ms"
    )
    print(f"  incidents remaining   : {remaining:,}")
    print(f"  sweep cleared all     : {'yes' if remaining == 0 else 'NO'}")


def _mute_library_loggers() -> None:
    """Silence the per-event INFO lines the correlation engine logs.

    Over thousands of events those lines bury the measurements. Applied at the
    start of the run and again after any import that reconfigures logging.
    """
    logging.getLogger().setLevel(logging.WARNING)


def _positive(value: int, *, name: str) -> bool:
    """Return True when ``value`` is usable, printing why when it is not."""
    if value < 1:
        print(f"{name} must be at least 1")
        return False
    return True


def main() -> int:
    """Parse arguments and run every baseline phase (M12.34)."""
    _mute_library_loggers()

    parser = argparse.ArgumentParser(
        description="Measure the M12 correlation and risk scoring baseline."
    )
    parser.add_argument(
        "--findings",
        type=int,
        default=2_000,
        help=(
            "Distinct findings for the no-match correlation phase. Its cost "
            "grows with the store size, so raising this raises the run time "
            "faster than linearly"
        ),
    )
    parser.add_argument(
        "--alerts", type=int, default=2_000, help="Alerts for the join phase"
    )
    parser.add_argument(
        "--per-group", type=int, default=5, help="Alerts per correlated group"
    )
    parser.add_argument(
        "--dedup", type=int, default=20_000, help="Repeats of one event identity"
    )
    parser.add_argument(
        "--risk-iterations", type=int, default=20_000, help="Scores computed"
    )
    parser.add_argument(
        "--query-incidents",
        type=int,
        default=1_000,
        help="Events seeding the incident store the query phase reads",
    )
    parser.add_argument(
        "--query-iterations", type=int, default=50, help="Reads timed per query path"
    )
    parser.add_argument(
        "--memory-findings",
        type=int,
        default=1_000,
        help="Findings used by the tracemalloc phase",
    )
    parser.add_argument(
        "--bounded-events",
        type=int,
        default=2_048,
        help="Distinct findings fed past the small cap in the bounded phase",
    )
    parser.add_argument(
        "--bounded-cap", type=int, default=256, help="Cap used by the bounded phase"
    )
    parser.add_argument(
        "--max-incidents",
        type=int,
        default=8_192,
        help=(
            "Cap on held incidents for the throughput phases. Sized above the "
            "workload so eviction does not dominate the figures; the bound "
            "itself is measured in the bounded phase"
        ),
    )
    args = parser.parse_args()

    checks = (
        ("--findings", args.findings),
        ("--alerts", args.alerts),
        ("--per-group", args.per_group),
        ("--dedup", args.dedup),
        ("--risk-iterations", args.risk_iterations),
        ("--query-incidents", args.query_incidents),
        ("--query-iterations", args.query_iterations),
        ("--memory-findings", args.memory_findings),
        ("--bounded-events", args.bounded_events),
        ("--bounded-cap", args.bounded_cap),
        ("--max-incidents", args.max_incidents),
    )
    for name, value in checks:
        if not _positive(value, name=name):
            return 1
    if args.bounded_cap > args.bounded_events:
        print("--bounded-cap must not exceed --bounded-events")
        return 1

    # The engine itself is not needed after this: the query phase populates its
    # own store so the read paths are timed over a known, uniform set.
    _engine, incidents = benchmark_findings(
        args.findings, max_incidents=args.max_incidents
    )
    benchmark_alerts(
        args.alerts, per_group=args.per_group, max_incidents=args.max_incidents
    )
    benchmark_dedup(args.dedup, max_incidents=args.max_incidents)
    benchmark_risk(incidents, iterations=args.risk_iterations)
    benchmark_queries(
        incidents=args.query_incidents,
        per_group=args.per_group,
        iterations=args.query_iterations,
    )
    benchmark_memory(args.memory_findings, max_incidents=args.max_incidents)
    benchmark_bounded(args.bounded_events, cap=args.bounded_cap)

    print("\n" + "=" * _BANNER_WIDTH)
    print("Configuration in use (M12.5/M12.7/M12.15)")
    print("=" * _BANNER_WIDTH)
    print(
        f"  window={_WINDOW_SECONDS:.0f}s proximity={_PROXIMITY_SECONDS:.0f}s "
        f"retention={_RETENTION_SECONDS:.0f}s"
    )
    print(
        f"  anchor threshold={DEFAULT_ANCHOR_THRESHOLD:.2f} "
        f"min confidence={_MIN_CONFIDENCE:.2f}"
    )
    print(
        f"  scoring bounds: volume_alerts={_VOLUME_ALERTS} "
        f"historical_occurrences={_HISTORICAL_OCCURRENCES} "
        f"recency={_RECENCY_SECONDS:.0f}s ml_enabled={_ML_ENABLED}"
    )
    print("  single-machine, in-process figures for the M12 code alone.")
    print("  This is a local baseline, not a production-capacity claim (M12.34).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
