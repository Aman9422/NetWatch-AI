"""The correlation engine over its own public surface (M12.2, M12.28-M12.29).

This is the layer's behaviour test rather than a unit test: every case here goes
through :meth:`CorrelationEngine.correlate_alert` or ``correlate_finding`` and
reads the result back through the engine's own query methods, so what is proved
is the *flow* M12.25 describes — alert in, correlated incident out, underlying
alert intact.

Three things are being established, in order of how easy they are to get wrong:

1. **Each identity dimension correlates on its own** (M12.6/M12.28) — same
   source, same destination, same device, same connection. Each test is built so
   that exactly one dimension is shared, so a pass cannot be explained by a
   different relationship than the one named in the test.
2. **The window is a real bound** (M12.5/M12.29) — the same pair correlates at the
   boundary and splits one step beyond it.
3. **A repeated event does not join twice** (M12.11), and unrelated activity is
   never merged (M12.4).
"""

from __future__ import annotations

import threading
from typing import cast

import pytest

from app.alerts.alert import Alert
from app.alerts.timestamps import to_epoch_seconds, to_utc_datetime
from app.correlation.engine import CorrelationEngine
from app.correlation.event import from_alert
from app.correlation.registry import (
    DEFAULT_MAX_PAGE_SIZE,
    IncidentOrder,
    IncidentQuery,
    IncidentRegistry,
)
from app.correlation.rules import RULE_REASON_PREFIX
from app.correlation.status import IncidentStatus, InvalidIncidentTransition
from app.risk.bands import MIN_RISK_SCORE, RiskBand
from app.risk.engine import RiskResult, RiskScoringEngine
from tests.correlation_fakes import (
    CONNECTION_ID,
    CORRELATION_BASE_TIME,
    DESTINATION_DEVICE_ID,
    DESTINATION_IP,
    FixedClock,
    OTHER_CONNECTION_ID,
    OTHER_DESTINATION_IP,
    OTHER_SOURCE_IP,
    SOURCE_DEVICE_ID,
    SOURCE_IP,
    THIRD_DEVICE_ID,
    THIRD_SOURCE_IP,
    make_alert,
    make_engine,
    make_finding,
    make_registry,
)

DEVICE_A = "mac:0a:0a:0a:0a:0a:0a"
DEVICE_B = "mac:0b:0b:0b:0b:0b:0b"
DEVICE_C = "mac:0c:0c:0c:0c:0c:0c"
DEVICE_D = "mac:0d:0d:0d:0d:0d:0d"


# --------------------------------------------------------------------------
# Fixtures: one shared dimension per pair, so a pass names its own reason
# --------------------------------------------------------------------------


def _same_source_pair() -> tuple[Alert, Alert]:
    """Two alerts sharing a source device, and nothing at the far end."""
    return (
        make_alert(alert_id=1),
        make_alert(
            alert_id=2,
            rule_id="high_bandwidth",
            title="High Bandwidth",
            destination_ip=OTHER_DESTINATION_IP,
            destination_device_id=None,
        ),
    )


def _same_destination_pair() -> tuple[Alert, Alert]:
    """Two alerts sharing only a destination *address*.

    Neither endpoint resolved to a device, which is the case that can only be
    expressed as ``same_destination`` — the reason the rule set needs a rule that
    consumes that relationship at all.
    """
    return (
        make_alert(alert_id=1, destination_device_id=None),
        make_alert(
            alert_id=2,
            rule_id="high_bandwidth",
            title="High Bandwidth",
            source_ip=THIRD_SOURCE_IP,
            source_device_id=THIRD_DEVICE_ID,
            destination_device_id=None,
        ),
    )


def _same_device_pair() -> tuple[Alert, Alert]:
    """Two alerts whose only shared identity is a device at one of the ends."""
    return (
        make_alert(
            alert_id=1,
            source_ip="10.1.0.1",
            source_device_id=DEVICE_A,
            destination_ip="10.2.0.1",
            destination_device_id=DEVICE_B,
        ),
        make_alert(
            alert_id=2,
            rule_id="high_bandwidth",
            title="High Bandwidth",
            source_ip="10.3.0.1",
            source_device_id=DEVICE_B,
            destination_ip="10.4.0.1",
            destination_device_id=DEVICE_C,
        ),
    )


def _same_connection_pair() -> tuple[Alert, Alert]:
    """Two alerts over one M9 conversation, sharing nothing else."""
    return (
        make_alert(
            alert_id=1,
            connection_id=CONNECTION_ID,
            source_ip="10.1.0.1",
            source_device_id=DEVICE_A,
            destination_ip="10.2.0.1",
            destination_device_id=DEVICE_B,
        ),
        make_alert(
            alert_id=2,
            rule_id="high_bandwidth",
            title="High Bandwidth",
            connection_id=CONNECTION_ID,
            source_ip="10.3.0.1",
            source_device_id=DEVICE_C,
            destination_ip="10.4.0.1",
            destination_device_id=DEVICE_D,
        ),
    )


UNRELATED_DEVICE_A = "mac:05:05:05:05:05:05"
UNRELATED_DEVICE_B = "mac:06:06:06:06:06:06"
UNRELATED_SOURCE_A = "198.51.100.1"
UNRELATED_SOURCE_B = "198.51.100.2"


def _unrelated() -> tuple[Alert, Alert]:
    """Return two alerts sharing no identity with each other or with the pairs.

    Deliberately disjoint from every other fixture in this module, so a query
    test can add one of these to an engine already holding the shared-dimension
    incidents and be certain it matches none of them.
    """
    return (
        make_alert(
            alert_id=1,
            source_ip=UNRELATED_SOURCE_A,
            source_device_id=UNRELATED_DEVICE_A,
            destination_ip="203.0.113.1",
            destination_device_id=None,
        ),
        make_alert(
            alert_id=2,
            rule_id="high_bandwidth",
            title="High Bandwidth",
            source_ip=UNRELATED_SOURCE_B,
            source_device_id=UNRELATED_DEVICE_B,
            destination_ip="203.0.113.2",
            destination_device_id=None,
        ),
    )


# --------------------------------------------------------------------------
# Opening an incident (M12.8/M12.10)
# --------------------------------------------------------------------------


def test_the_first_event_opens_an_incident_carrying_only_itself() -> None:
    """A seed incident holds the seeding event, and nothing was correlated."""
    engine = make_engine()
    alert = make_alert(alert_id=1)

    outcome = engine.correlate_alert(alert)

    assert outcome.ok is True
    assert outcome.created is True
    assert outcome.joined is False
    assert outcome.duplicate is False
    assert outcome.incident_id == "inc:alert:1"
    assert outcome.error is None

    incident = engine.get_incident("inc:alert:1")
    assert incident is not None
    assert incident.event_count == 1
    assert incident.dropped_events == 0
    assert incident.alert_ids == (1,)
    # The alert's own origin is carried, not invented: M11 alerts record the M10
    # finding they were raised from, so the trail back to the observation stays
    # walkable from the incident (M12.10).
    assert incident.finding_ids == (alert.finding_id,)
    assert incident.rule_ids == ("port_scan",)
    # Nothing was correlated to open it, so there is no rule and no reason.
    assert incident.correlation_rule_ids == ()
    assert incident.correlation_reasons == ()
    assert incident.correlation_confidence == 0.0
    # The alert's own confidence is recorded separately (M12.16).
    assert incident.alert_confidences == (alert.confidence,)
    assert incident.worst_severity() == alert.severity
    assert incident.normalized_status is IncidentStatus.OPEN


def test_a_seed_incident_is_timed_through_the_m11_converters() -> None:
    """Alert times reach correlation on one epoch-seconds timeline (M12.3).

    M11 stores a naive UTC datetime; correlation reasons in epoch seconds. The
    conversion is asserted against M11's own converter rather than against a
    literal, so the two layers cannot drift apart unnoticed.
    """
    engine = make_engine()
    expected = to_epoch_seconds(to_utc_datetime(CORRELATION_BASE_TIME))

    incident = engine.correlate_alert(make_alert(alert_id=1)).incident

    assert incident is not None
    assert incident.start_time == pytest.approx(expected)
    assert incident.last_seen == pytest.approx(expected)
    assert incident.created_at == pytest.approx(expected)
    assert incident.span_seconds() == pytest.approx(0.0)


def test_a_finding_opens_an_incident_without_inventing_a_severity() -> None:
    """M10 findings carry no severity, and correlation must not add one."""
    engine = make_engine()
    finding = make_finding()

    outcome = engine.correlate_finding(finding)

    assert outcome.ok is True
    assert outcome.created is True
    incident = engine.get_incident(outcome.incident_id or "")
    assert incident is not None
    assert incident.finding_ids == (finding.finding_id,)
    assert incident.alert_ids == ()
    # "Unmeasured", not "low" (M12.15).
    assert incident.severities == ()
    assert incident.worst_severity() is None
    assert incident.alert_confidences == ()


def test_correlating_a_batch_returns_one_outcome_per_event() -> None:
    """``correlate_alerts`` preserves order and reports each step (M12.2)."""
    engine = make_engine()
    alerts = [make_alert(alert_id=index) for index in (1, 2, 3)]

    outcomes = engine.correlate_alerts(alerts)

    assert [item.event_id for item in outcomes] == ["alert:1", "alert:2", "alert:3"]
    # All three share a source device, so they form one incident, not three.
    assert len({item.incident_id for item in outcomes}) == 1
    assert engine.registry.incident_count() == 1
    assert engine.count_incidents() == 1


# --------------------------------------------------------------------------
# Each identity dimension correlates on its own (M12.6/M12.28)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("builder", "expected_rule"),
    [
        (_same_source_pair, "same_source_activity"),
        (_same_destination_pair, "same_destination_activity"),
        (_same_device_pair, "device_centric_activity"),
        (_same_connection_pair, "same_connection"),
    ],
    ids=["same_source", "same_destination", "same_device", "same_connection"],
)
def test_each_identity_dimension_correlates_on_its_own(
    builder, expected_rule: str
) -> None:
    """One shared dimension is enough, and the reason names which one (M12.6)."""
    engine = make_engine()
    first, second = builder()

    opened = engine.correlate_alert(first)
    joined = engine.correlate_alert(second)

    assert opened.created is True
    assert joined.joined is True
    assert joined.duplicate is False
    assert joined.incident_id == opened.incident_id
    assert joined.correlation_rule_id == expected_rule

    incident = engine.get_incident(opened.incident_id or "")
    assert incident is not None
    assert incident.event_count == 2
    assert incident.alert_ids == (1, 2)
    assert expected_rule in incident.correlation_rule_ids
    assert f"{RULE_REASON_PREFIX}{expected_rule}" in incident.correlation_reasons
    assert 0.0 < incident.correlation_confidence < 1.0


def test_a_scan_sequence_is_attributed_to_the_most_specific_rule() -> None:
    """An internal scan followed by a port scan is a sequence, not "same source"."""
    engine = make_engine()
    engine.correlate_alert(make_alert(alert_id=1, rule_id="internal_scan"))

    joined = engine.correlate_alert(
        make_alert(
            alert_id=2,
            rule_id="port_scan",
            destination_ip=OTHER_DESTINATION_IP,
            destination_device_id=None,
        )
    )

    assert joined.joined is True
    assert joined.correlation_rule_id == "scan_sequence"


# --------------------------------------------------------------------------
# Unrelated activity stays apart (M12.4/M12.29)
# --------------------------------------------------------------------------


def test_unrelated_alerts_open_separate_incidents() -> None:
    """Sharing nothing means correlating with nothing (M12.29)."""
    engine = make_engine()
    first, second = _unrelated()

    opened = engine.correlate_alert(first)
    other = engine.correlate_alert(second)

    assert opened.created is True
    assert other.created is True
    assert other.joined is False
    assert other.incident_id != opened.incident_id
    assert engine.registry.incident_count() == 2


def test_proximity_alone_never_merges_two_events() -> None:
    """Two events at the same instant but otherwise unrelated stay apart (M12.4).

    Correlation is not "close in time": this pair is separated by nothing at all
    on the clock, and it is still two incidents.
    """
    engine = make_engine()
    first, second = _unrelated()

    engine.correlate_alert(first, timestamp=1_000.0)
    other = engine.correlate_alert(second, timestamp=1_000.0)

    assert other.created is True
    assert engine.registry.incident_count() == 2


def test_a_stronger_shared_dimension_wins_attribution() -> None:
    """A pair sharing a source and a destination is named by the source.

    Both rules are satisfied, so the order of the rule set decides — and it must
    decide the *same* way every run, which is why the ordering is data (M12.12).
    """
    engine = make_engine()
    engine.correlate_alert(make_alert(alert_id=1))

    joined = engine.correlate_alert(
        make_alert(alert_id=2, rule_id="high_bandwidth", title="High Bandwidth")
    )

    assert joined.correlation_rule_id == "same_source_activity"


# --------------------------------------------------------------------------
# The correlation window (M12.5/M12.29)
# --------------------------------------------------------------------------


def test_the_window_boundary_is_inclusive() -> None:
    """Exactly one window apart still correlates; one step further does not."""
    engine = make_engine()
    window = engine.window.seconds
    first, second = _same_source_pair()

    engine.correlate_alert(first, timestamp=1_000.0)

    inside = engine.correlate_alert(second, timestamp=1_000.0 + window)
    assert inside.joined is True

    beyond = engine.correlate_alert(
        make_alert(
            alert_id=3,
            destination_ip=OTHER_DESTINATION_IP,
            destination_device_id=None,
        ),
        timestamp=1_000.0 + window + 0.001,
    )
    assert beyond.created is True
    assert beyond.joined is False


def test_an_event_outside_the_window_starts_a_new_incident() -> None:
    """History does not correlate across unlimited time (M12.5)."""
    engine = make_engine()
    first, second = _same_source_pair()

    engine.correlate_alert(first, timestamp=10_000.0)
    late = engine.correlate_alert(second, timestamp=10_000.0 + 86_400.0)

    assert late.created is True
    assert engine.registry.incident_count() == 2


# --------------------------------------------------------------------------
# Deduplication (M12.11)
# --------------------------------------------------------------------------


def test_a_repeated_event_does_not_join_twice() -> None:
    """Re-seeing an event reports the incident without inflating it (M12.11)."""
    engine = make_engine()
    alert = make_alert(alert_id=1)

    first = engine.correlate_alert(alert)
    again = engine.correlate_alert(alert)

    assert first.created is True
    assert again.duplicate is True
    assert again.joined is False
    assert again.created is False
    assert again.ok is True
    assert again.incident_id == first.incident_id
    assert again.risk_score == first.risk_score

    incident = engine.get_incident(first.incident_id or "")
    assert incident is not None
    assert incident.event_count == 1
    assert incident.alert_ids == (1,)
    assert engine.registry.incident_count() == 1
    assert engine.registry.has_seen_event("alert:1") is True
    assert engine.registry.incident_for_event("alert:1") == first.incident_id


def test_deduplication_is_by_event_identity_not_by_alert_content() -> None:
    """Two genuinely different alerts are two events, however similar (M12.11)."""
    engine = make_engine()
    first, second = _same_source_pair()

    engine.correlate_alert(first)
    engine.correlate_alert(second)
    third = engine.correlate_alert(
        make_alert(
            alert_id=3,
            destination_ip=OTHER_DESTINATION_IP,
            destination_device_id=None,
        )
    )

    assert third.joined is True
    incident = engine.get_incident(third.incident_id or "")
    assert incident is not None
    assert incident.event_count == 3
    assert incident.alert_ids == (1, 2, 3)


# --------------------------------------------------------------------------
# Lifecycle (M12.9)
# --------------------------------------------------------------------------


def _open_incident(engine: CorrelationEngine, alert_id: int = 1) -> str:
    """Correlate one alert and return the incident id it opened."""
    return engine.correlate_alert(make_alert(alert_id=alert_id)).incident_id or ""


def test_the_lifecycle_moves_through_the_documented_states() -> None:
    """``open`` → ``investigating`` → ``resolved`` is the M12.9 path."""
    engine = make_engine()
    incident_id = _open_incident(engine)

    investigating = engine.set_status(incident_id, IncidentStatus.INVESTIGATING)
    assert investigating is not None
    assert investigating.normalized_status is IncidentStatus.INVESTIGATING

    resolved = engine.set_status(incident_id, IncidentStatus.RESOLVED)
    assert resolved is not None
    assert resolved.normalized_status is IncidentStatus.RESOLVED

    stored = engine.get_incident(incident_id)
    assert stored is not None
    assert stored.normalized_status is IncidentStatus.RESOLVED


def test_a_terminal_incident_cannot_be_reopened() -> None:
    """M12 asks for no reopen, and the refusal is explicit rather than silent."""
    engine = make_engine()
    incident_id = _open_incident(engine)
    engine.set_status(incident_id, IncidentStatus.DISMISSED)

    with pytest.raises(InvalidIncidentTransition):
        engine.set_status(incident_id, IncidentStatus.OPEN)

    with pytest.raises(InvalidIncidentTransition):
        engine.set_status(incident_id, IncidentStatus.INVESTIGATING)


def test_an_invalid_transition_leaves_the_incident_unchanged() -> None:
    """Validation happens before the write, so a refusal is not a half-update."""
    engine = make_engine()
    incident_id = _open_incident(engine)
    engine.set_status(incident_id, IncidentStatus.RESOLVED)

    with pytest.raises(InvalidIncidentTransition):
        engine.set_status(incident_id, IncidentStatus.INVESTIGATING)

    stored = engine.get_incident(incident_id)
    assert stored is not None
    assert stored.normalized_status is IncidentStatus.RESOLVED


def test_a_closed_incident_takes_no_new_members() -> None:
    """Activity after a person closed an incident opens a new one (M12.9).

    Correlation must not silently undo a decision someone made, so a terminal
    incident is not a candidate however well the event matches it.
    """
    engine = make_engine()
    first, second = _same_source_pair()
    opened = engine.correlate_alert(first)
    engine.set_status(opened.incident_id or "", IncidentStatus.RESOLVED)

    later = engine.correlate_alert(second)

    assert later.created is True
    assert later.joined is False
    assert later.incident_id != opened.incident_id
    assert engine.registry.incident_count() == 2


def test_status_on_an_unknown_incident_returns_nothing() -> None:
    """An unknown id is a normal ``None``, not an exception."""
    engine = make_engine()
    assert engine.set_status("inc:does-not-exist", IncidentStatus.INVESTIGATING) is None


def test_moving_to_the_state_an_incident_is_already_in_is_a_no_op() -> None:
    """Re-marking a state changes nothing and is not an error."""
    engine = make_engine()
    incident_id = _open_incident(engine)

    same = engine.set_status(incident_id, IncidentStatus.OPEN)

    assert same is not None
    assert same.normalized_status is IncidentStatus.OPEN


def test_an_unknown_status_is_rejected_at_the_boundary() -> None:
    """A misspelled status is a caller bug, so it surfaces as one."""
    engine = make_engine()
    incident_id = _open_incident(engine)

    with pytest.raises(ValueError):
        engine.set_status(incident_id, "not-a-status")


# --------------------------------------------------------------------------
# Queries (M12.26)
# --------------------------------------------------------------------------


def _seeded_engine() -> tuple[CorrelationEngine, str]:
    """Return an engine holding one correlated two-alert incident."""
    engine = make_engine()
    first, second = _same_source_pair()
    engine.correlate_alert(first)
    joined = engine.correlate_alert(second)
    return engine, joined.incident_id or ""


def test_queries_find_the_incident_by_its_identity_dimensions() -> None:
    """Source, device, detector rule and correlation rule all locate it."""
    engine, incident_id = _seeded_engine()

    assert [item.incident_id for item in engine.incidents_for_source(SOURCE_IP)] == [
        incident_id
    ]
    assert [item.incident_id for item in engine.incidents_for_device(SOURCE_DEVICE_ID)] == [
        incident_id
    ]
    assert incident_id in {
        item.incident_id for item in engine.incidents_for_rule("port_scan")
    }
    assert incident_id in {
        item.incident_id
        for item in engine.incidents_for_rule("same_source_activity", correlation=True)
    }


def test_queries_do_not_return_unrelated_incidents() -> None:
    """A filter selects what matches and nothing else (M12.26)."""
    engine, incident_id = _seeded_engine()
    unrelated, unrelated_id = _unrelated()
    engine.correlate_alert(unrelated)

    assert [item.incident_id for item in engine.incidents_for_source(SOURCE_IP)] == [
        incident_id
    ]
    assert unrelated_id not in {
        item.incident_id for item in engine.incidents_for_source(SOURCE_IP)
    }
    assert incident_id not in {
        item.incident_id for item in engine.incidents_for_source(UNRELATED_SOURCE_A)
    }


def test_recent_incidents_are_ordered_newest_first() -> None:
    """Ordering is total and deterministic, not dictionary order (M12.26)."""
    engine = make_engine()
    first, second = _unrelated()
    engine.correlate_alert(first, timestamp=1_000.0)
    engine.correlate_alert(second, timestamp=2_000.0)

    recent = engine.recent_incidents()

    assert [item.incident_id for item in recent] == ["inc:alert:2", "inc:alert:1"]
    assert engine.count_incidents() == 2


def test_open_incidents_exclude_closed_ones() -> None:
    """``open_incidents`` answers "what still needs attention?" (M12.26)."""
    engine = make_engine()
    first, second = _unrelated()
    closed = engine.correlate_alert(first)
    live = engine.correlate_alert(second)
    engine.set_status(closed.incident_id or "", IncidentStatus.RESOLVED)

    open_ids = {item.incident_id for item in engine.open_incidents()}

    assert open_ids == {live.incident_id}
    assert closed.incident_id not in open_ids


def test_incidents_by_risk_selects_a_bounded_range() -> None:
    """The risk filter is inclusive on both edges (M12.26)."""
    engine, incident_id = _seeded_engine()
    incident = engine.get_incident(incident_id)
    assert incident is not None
    score = incident.risk_score
    assert MIN_RISK_SCORE <= score <= 100

    assert incident_id in {
        item.incident_id
        for item in engine.incidents_by_risk(min_risk_score=score, max_risk_score=score)
    }
    if score < 100:
        assert incident_id not in {
            item.incident_id for item in engine.incidents_by_risk(min_risk_score=score + 1)
        }


def test_incidents_in_range_select_by_temporal_overlap() -> None:
    """A time-range query selects an incident that overlaps it (M12.26)."""
    engine, incident_id = _seeded_engine()
    incident = engine.get_incident(incident_id)
    assert incident is not None

    inside = engine.incidents_in_range(
        since=incident.start_time - 1.0, until=incident.last_seen + 1.0
    )
    assert incident_id in {item.incident_id for item in inside}

    after = engine.incidents_in_range(since=incident.last_seen + 10.0)
    assert incident_id not in {item.incident_id for item in after}


def test_a_query_returns_a_bounded_number_of_results() -> None:
    """``limit`` bounds the page, so a read can never be unbounded (M12.26)."""
    engine = make_engine()
    for index in range(1, 6):
        engine.correlate_alert(
            make_alert(
                alert_id=index,
                rule_id=f"rule_{index}",
                source_ip=f"10.20.0.{index}",
                source_device_id=None,
                destination_ip=f"10.21.0.{index}",
                destination_device_id=None,
            )
        )

    assert engine.count_incidents() == 5
    assert len(engine.recent_incidents(limit=2)) == 2
    assert len(engine.recent_incidents(limit=DEFAULT_MAX_PAGE_SIZE)) == 5


def test_a_count_agrees_with_the_listing_it_accompanies() -> None:
    """A count that disagreed with its listing would make paging a lie."""
    engine, _ = _seeded_engine()
    query = IncidentQuery(active_only=True, limit=DEFAULT_MAX_PAGE_SIZE)

    listed = engine.registry.list_incidents(query)

    assert engine.count_incidents(query) == len(listed)


def test_highest_risk_incidents_are_ordered_by_score() -> None:
    """The risk ordering is descending and total (M12.26)."""
    engine, _ = _seeded_engine()
    first, second = _unrelated()
    engine.correlate_alert(first)
    engine.correlate_alert(second)

    scores = [item.risk_score for item in engine.highest_risk_incidents()]

    assert scores == sorted(scores, reverse=True)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"limit": DEFAULT_MAX_PAGE_SIZE + 1},
        {"offset": -1},
        {"min_risk_score": -1},
        {"max_risk_score": 101},
        {"min_risk_score": 80, "max_risk_score": 20},
        {"since": 100.0, "until": 50.0},
        {"order": "not-an-order"},
        {"statuses": ("not-a-status",)},
    ],
)
def test_an_unusable_query_is_rejected_before_it_reaches_the_store(
    kwargs: dict[str, object],
) -> None:
    """An inverted or unbounded query fails loudly rather than silently.

    An empty result would look like "no incidents" when the query was simply
    wrong, so the bounds are validated at construction (M12.26).
    """
    with pytest.raises(ValueError):
        IncidentQuery(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Bounded state and expiration (M12.22)
# --------------------------------------------------------------------------


def test_expiring_correlation_context_releases_only_the_relationship() -> None:
    """Expiration drops the grouping, never the alerts it grouped (M12.22)."""
    clock = FixedClock()
    engine = make_engine(clock=clock)
    opened = engine.correlate_alert(make_alert(alert_id=1))

    clock.advance(engine.registry.retention_seconds * 2 + 1.0)
    dropped = engine.expire_old_context()

    assert dropped == 1
    assert engine.get_incident(opened.incident_id or "") is None
    assert engine.registry.incident_count() == 0
    assert engine.registry.stats()["expired_incidents"] == 1


def test_expiration_within_the_retention_age_keeps_the_incident() -> None:
    """Context is not dropped while it is still recent (M12.22)."""
    clock = FixedClock()
    engine = make_engine(clock=clock)
    opened = engine.correlate_alert(make_alert(alert_id=1))

    clock.advance(engine.registry.retention_seconds / 2.0)
    dropped = engine.expire_old_context()

    assert dropped == 0
    assert engine.get_incident(opened.incident_id or "") is not None


def test_expiration_rejects_an_unbounded_retention() -> None:
    """An unbounded retention would defeat the whole method (M12.22)."""
    engine = make_engine()
    with pytest.raises(ValueError):
        engine.expire_old_context(retention_seconds=0)


def test_the_incident_store_is_capped_and_evicts_the_least_recent() -> None:
    """A burst cannot grow runtime state without limit (M12.22)."""
    clock = FixedClock()
    registry = make_registry(clock, max_incidents=2)
    engine = make_engine(registry=registry, clock=clock)

    for index in (1, 2, 3):
        engine.correlate_alert(
            make_alert(
                alert_id=index,
                rule_id=f"rule_{index}",
                source_ip=f"10.30.0.{index}",
                source_device_id=None,
                destination_ip=f"10.31.0.{index}",
                destination_device_id=None,
            )
        )

    assert registry.incident_count() == 2
    assert registry.stats()["evicted_incidents"] == 1
    # The incident given up is the least recently active one.
    assert engine.get_incident("inc:alert:1") is None


def test_correlation_does_not_grow_state_beyond_its_bounds() -> None:
    """Every accumulating structure has a documented cap (M12.22)."""
    clock = FixedClock()
    registry = make_registry(clock, seen_event_capacity=2)
    engine = make_engine(registry=registry, clock=clock)

    for index in (1, 2, 3):
        engine.correlate_alert(
            make_alert(
                alert_id=index,
                rule_id=f"rule_{index}",
                source_ip=f"10.40.0.{index}",
                source_device_id=None,
                destination_ip=f"10.41.0.{index}",
                destination_device_id=None,
            )
        )

    assert registry.seen_event_count() == 2


def test_reset_clears_runtime_state_and_counters() -> None:
    """``reset`` clears correlation state and touches no stored record (M12.22)."""
    engine, _ = _seeded_engine()
    assert engine.registry.incident_count() == 1

    engine.reset()

    assert engine.registry.incident_count() == 0
    assert engine.registry.seen_event_count() == 0
    assert engine.count_incidents() == 0
    stats = engine.stats()
    assert stats["errors"] == 0
    # ``stats`` is a heterogeneous report; narrow the nested block to index it.
    incidents = cast("dict[str, object]", stats["incidents"])
    assert incidents["incidents"] == 0


# --------------------------------------------------------------------------
# Thread safety (M12.23)
# --------------------------------------------------------------------------


def test_concurrent_ingestion_loses_nothing_and_merges_nothing() -> None:
    """The read-decide-write step is atomic, so parallel events all land.

    Not a proof of correctness — a smoke test that the store's lock covers the
    whole step. If it covered only the write, two threads deciding to fold into
    the same incident would lose one fold, and unrelated events would be counted
    below the number submitted.
    """
    engine = make_engine()
    submitted = 32
    failures: list[BaseException] = []

    def ingest(index: int) -> None:
        try:
            engine.correlate_alert(
                make_alert(
                    alert_id=index,
                    rule_id=f"rule_{index}",
                    source_ip=f"10.60.0.{index}",
                    source_device_id=None,
                    destination_ip=f"10.61.0.{index}",
                    destination_device_id=None,
                )
            )
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            failures.append(exc)

    threads = [
        threading.Thread(target=ingest, args=(index,)) for index in range(submitted)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert engine.registry.incident_count() == submitted
    assert engine.stats()["errors"] == 0


# --------------------------------------------------------------------------
# Failure isolation (M12.25)
# --------------------------------------------------------------------------


class _ExplodingRisk(RiskScoringEngine):
    """A scorer that fails, to prove an incident outlives a scoring fault."""

    def score(self, inputs):  # type: ignore[override]
        raise RuntimeError("scoring failed")


class _ExplodingWindow:
    """A window that fails on use, to prove a correlation fault is contained."""

    seconds = 900.0
    proximity_seconds = 300.0
    max_span_seconds = 900.0

    def incident_accepts(self, **kwargs: float) -> bool:
        raise RuntimeError("window failed")


class _UntimedAlert:
    """A stand-in alert with no observation time at all (M12.25)."""

    alert_id = 7
    rule_id = "port_scan"
    created_at = None


def test_a_scoring_failure_does_not_lose_the_incident() -> None:
    """A scoring problem must not destroy what was correlated (M12.25)."""
    engine = make_engine(risk=_ExplodingRisk())

    outcome = engine.correlate_alert(make_alert(alert_id=1))

    assert outcome.ok is True
    assert outcome.created is True
    incident = engine.get_incident(outcome.incident_id or "")
    assert incident is not None
    # The incident is kept, unscored rather than absent.
    assert incident.risk_score == MIN_RISK_SCORE
    assert engine.registry.stats()["score_errors"] == 1


def test_a_correlation_failure_is_contained_and_the_store_survives() -> None:
    """An unexpected fault is reported, counted, and does not stop the next event."""
    registry = make_registry()

    def never_matches(incident: object) -> None:
        return None

    first = registry.ingest(
        from_alert(make_alert(alert_id=1)),
        window=_ExplodingWindow(),  # type: ignore[arg-type]
        evaluator=never_matches,
    )
    second = registry.ingest(
        from_alert(make_alert(alert_id=2)),
        window=_ExplodingWindow(),  # type: ignore[arg-type]
        evaluator=never_matches,
    )

    assert first.ok is True
    assert first.created is True
    assert second.ok is False
    assert second.error is not None
    # The incident the first event opened outlives the second event's failure.
    assert registry.get(first.incident_id or "") is not None
    assert registry.incident_count() == 1
    assert registry.stats()["errors"] == 1


def test_an_alert_with_no_observation_time_is_reported_not_raised() -> None:
    """Correlation is about time, so an untimed alert is not correlated (M12.3).

    The event is *skipped*, and the alert itself is left exactly as it was: the
    capture path must not fail because one alert could not be timed.
    """
    engine = make_engine()

    outcome = engine.correlate_alert(_UntimedAlert())  # type: ignore[arg-type]

    assert outcome.ok is False
    assert outcome.error is not None
    assert engine.count_incidents() == 0
    assert cast(int, engine.stats()["errors"]) >= 1
