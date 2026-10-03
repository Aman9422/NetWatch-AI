"""Correlation identity, relationships and the time window (M12.4-M12.6, M12.28-M12.29).

Two things are proved here.

**Identity (M12.4).** Which shared dimension turns two events into a candidate
relationship, and — the requirement the milestone is most insistent about —
that two events which merely happened at the same time are *not* related.
``time_proximity`` is established, and it still anchors nothing.

**The window (M12.5).** Both of its comparisons, at their exact boundaries,
because an inclusive edge is a decision that has to be pinned rather than
approximated: two events exactly one window apart are correlated, one
microsecond more and they are not.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from app.correlation.confidence import (
    MAX_CORRELATION_CONFIDENCE,
    combine_relationships,
    describe_confidence,
    meets_threshold,
)
from app.correlation.identity import (
    IdentityIndex,
    anchor_relationships,
    has_anchor,
    identity_relationships,
    relationships_between,
    relationships_with_identity,
)
from app.correlation.relationship import (
    ANCHOR_RELATIONSHIPS,
    DEFAULT_ANCHOR_THRESHOLD,
    RELATIONSHIP_WEIGHTS,
    Relationship,
    RelationshipKind,
    describe_relationships,
)
from app.correlation.window import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    MAX_CORRELATION_WINDOW_SECONDS,
    MAX_INCIDENT_SPAN_SECONDS,
    CorrelationWindow,
)
from tests.correlation_fakes import (
    CONNECTION_ID,
    SOURCE_DEVICE_ID,
    SOURCE_IP,
    THIRD_DEVICE_ID,
    THIRD_SOURCE_IP,
    make_event,
    make_window,
)

# --------------------------------------------------------------------------
# The documented relationship table (M12.6)
# --------------------------------------------------------------------------


def test_relationship_weights_are_the_documented_table() -> None:
    """The weights in code are the weights in the docs (M12.6)."""
    assert RELATIONSHIP_WEIGHTS == {
        "same_connection": 0.90,
        "same_device": 0.75,
        "same_source": 0.70,
        "same_destination": 0.55,
        "same_rule": 0.35,
        "time_proximity": 0.25,
    }
    for kind in RelationshipKind:
        assert 0.0 <= kind.weight <= 1.0
        assert kind.label and kind.description


def test_only_identity_relationships_anchor_at_the_default_threshold() -> None:
    """The four identity relationships anchor; rule identity and time do not."""
    assert ANCHOR_RELATIONSHIPS == {
        RelationshipKind.SAME_CONNECTION,
        RelationshipKind.SAME_DEVICE,
        RelationshipKind.SAME_SOURCE,
        RelationshipKind.SAME_DESTINATION,
    }
    assert not RelationshipKind.SAME_RULE.is_anchor(DEFAULT_ANCHOR_THRESHOLD)
    assert not RelationshipKind.TIME_PROXIMITY.is_anchor(DEFAULT_ANCHOR_THRESHOLD)


def test_raising_the_anchor_threshold_reclassifies_relationships() -> None:
    """The anchor boundary follows configuration rather than being hard-coded."""
    # Above same_destination's 0.55, only connection and device still anchor.
    assert not RelationshipKind.SAME_DESTINATION.is_anchor(0.60)
    assert RelationshipKind.SAME_DEVICE.is_anchor(0.60)
    assert RelationshipKind.SAME_CONNECTION.is_anchor(0.60)
    # Lowered far enough, even time proximity anchors — which is why the
    # default is documented rather than left to taste.
    assert RelationshipKind.TIME_PROXIMITY.is_anchor(0.20)


def test_describe_relationships_matches_the_enum() -> None:
    """The documented table is generated from the same definitions."""
    described = describe_relationships()
    assert [item["kind"] for item in described] == [
        kind.value for kind in RelationshipKind
    ]
    for item in described:
        assert item["weight"] == RelationshipKind(str(item["kind"])).weight
        assert item["anchors"] == RelationshipKind(str(item["kind"])).is_anchor()


# --------------------------------------------------------------------------
# Identity dimensions (M12.4)
# --------------------------------------------------------------------------


def test_identity_index_derives_the_device_union_from_both_ends() -> None:
    """``devices`` cannot contradict the source and destination device sets."""
    index = IdentityIndex.from_sets(
        source_devices=("dev-a",),
        destination_devices=("dev-b",),
    )
    assert index.devices == frozenset({"dev-a", "dev-b"})
    assert not index.is_empty()


def test_identity_index_ignores_blank_values() -> None:
    """An empty or whitespace identity is absent, never a value to match on."""
    index = IdentityIndex.from_sets(
        source_devices=("", "   "),
        source_addresses=(" 10.0.0.1 ",),
    )
    assert index.source_devices == frozenset()
    assert index.source_addresses == frozenset({"10.0.0.1"})
    assert IdentityIndex().is_empty()


def test_no_shared_dimension_produces_no_relationship() -> None:
    """Unrelated events share nothing, so nothing is established (M12.29)."""
    left = make_event(event_id="alert:1")
    right = make_event(
        event_id="alert:2",
        source_ip=THIRD_SOURCE_IP,
        source_device_id=THIRD_DEVICE_ID,
        destination_ip="203.0.113.9",
        destination_device_id=None,
        rule_id="high_bandwidth",
    )
    assert identity_relationships(
        IdentityIndex.from_event(left), IdentityIndex.from_event(right)
    ) == []


def test_same_source_address_is_a_relationship() -> None:
    """One shared source address establishes ``same_source`` (M12.6)."""
    left = IdentityIndex.from_sets(source_addresses=(SOURCE_IP,))
    right = IdentityIndex.from_sets(source_addresses=(SOURCE_IP,))
    kinds = {item.kind for item in identity_relationships(left, right)}
    assert kinds == {RelationshipKind.SAME_SOURCE}


def test_same_source_prefers_the_device_over_the_address() -> None:
    """A device overlap is reported in preference to an address overlap.

    The reason is what an operator reads, and ``same_source:mac:AA:...`` says
    more than ``same_source:192.168.1.10`` about the same relationship.
    """
    left = IdentityIndex.from_sets(
        source_devices=(SOURCE_DEVICE_ID,), source_addresses=(SOURCE_IP,)
    )
    right = IdentityIndex.from_sets(
        source_devices=(SOURCE_DEVICE_ID,), source_addresses=("10.0.0.9",)
    )
    source = [
        item
        for item in identity_relationships(left, right)
        if item.kind is RelationshipKind.SAME_SOURCE
    ]
    assert len(source) == 1
    assert source[0].detail == SOURCE_DEVICE_ID


def test_enriched_event_relates_to_unenriched_event_by_address() -> None:
    """A device match on one side and an address match on the other still relates.

    This is the common case, not the edge case: enrichment succeeds on one
    observation and not the next, and an implementation that compared one chosen
    representative per side would miss exactly this.
    """
    enriched = make_event(source_device_id=SOURCE_DEVICE_ID, source_ip=SOURCE_IP)
    unenriched = make_event(
        event_id="alert:2", source_device_id=None, source_ip=SOURCE_IP
    )
    kinds = {
        item.kind
        for item in relationships_between(
            enriched, unenriched, window=make_window()
        )
    }
    assert RelationshipKind.SAME_SOURCE in kinds


def test_same_destination_and_same_device_relationships() -> None:
    """Destination and cross-end device overlap each establish a relationship."""
    left = make_event()
    right = make_event(event_id="alert:2", source_ip=THIRD_SOURCE_IP, source_device_id=None)
    kinds = {
        item.kind for item in relationships_between(left, right, window=make_window())
    }
    # Same destination IP and the same destination device, plus a shared device
    # at either end (the destination device is in both ``devices`` sets).
    assert RelationshipKind.SAME_DESTINATION in kinds
    assert RelationshipKind.SAME_DEVICE in kinds


def test_same_connection_is_the_strongest_relationship() -> None:
    """A shared M9 conversation establishes ``same_connection`` (M12.6)."""
    left = make_event(connection_id=CONNECTION_ID, source_ip=SOURCE_IP)
    right = make_event(
        event_id="alert:2",
        connection_id=CONNECTION_ID,
        source_ip=THIRD_SOURCE_IP,
        source_device_id=None,
        destination_ip="203.0.113.9",
        destination_device_id=None,
    )
    relationships = relationships_between(left, right, window=make_window())
    connections = [
        item for item in relationships if item.kind is RelationshipKind.SAME_CONNECTION
    ]
    assert len(connections) == 1
    assert connections[0].detail == CONNECTION_ID
    assert connections[0].strength == 0.90


def test_same_rule_alone_does_not_anchor() -> None:
    """A detector repeating itself is expected and justifies nothing (M12.4)."""
    left = make_event(source_ip=SOURCE_IP)
    # Same rule id ("port_scan"), nothing else in common, and far enough apart
    # in time that proximity is not established either.
    apart = make_event(
        event_id="alert:2",
        timestamp=left.timestamp + 600.0,
        source_ip=THIRD_SOURCE_IP,
        source_device_id=None,
        destination_ip="203.0.113.9",
        destination_device_id=None,
    )
    relationships = relationships_between(
        left, apart, window=make_window(seconds=900, proximity_seconds=1)
    )
    assert [item.kind for item in relationships] == [RelationshipKind.SAME_RULE]
    assert not has_anchor(relationships, threshold=DEFAULT_ANCHOR_THRESHOLD)


def test_time_proximity_alone_never_correlates() -> None:
    """Two events close in time and different in every other way stay apart.

    This is M12.4's central prohibition, asserted directly: proximity is
    established as a relationship and it still anchors nothing.
    """
    left = make_event(source_ip=SOURCE_IP)
    right = make_event(
        event_id="alert:2",
        timestamp=left.timestamp + 10,
        source_ip=THIRD_SOURCE_IP,
        source_device_id=None,
        destination_ip="203.0.113.9",
        destination_device_id=None,
        rule_id="high_bandwidth",
    )
    relationships = relationships_between(left, right, window=make_window())
    assert RelationshipKind.TIME_PROXIMITY in {item.kind for item in relationships}
    assert not has_anchor(relationships, threshold=DEFAULT_ANCHOR_THRESHOLD)
    assert anchor_relationships(
        relationships, threshold=DEFAULT_ANCHOR_THRESHOLD
    ) == []


def test_relationships_between_two_events_on_one_timeline() -> None:
    """An event-to-incident comparison measures proximity against ``reference_time``."""
    event = make_event(event_id="alert:9", timestamp=1_000.0)
    identity = IdentityIndex.from_event(make_event())
    inside = relationships_with_identity(
        event,
        identity,
        reference_time=1_000.0 + 120.0,
        window=make_window(proximity_seconds=300),
    )
    assert RelationshipKind.TIME_PROXIMITY in {item.kind for item in inside}
    outside = relationships_with_identity(
        event,
        identity,
        reference_time=1_000.0 + 400.0,
        window=make_window(proximity_seconds=300),
    )
    assert RelationshipKind.TIME_PROXIMITY not in {item.kind for item in outside}
    # The identity relationships are unaffected by how far apart the times are.
    assert RelationshipKind.SAME_SOURCE in {item.kind for item in outside}


# --------------------------------------------------------------------------
# Correlation confidence (M12.7)
# --------------------------------------------------------------------------


def test_no_relationship_means_no_confidence() -> None:
    """Zero relationships is zero confidence, not a weak one."""
    assert combine_relationships([]) == 0.0


def test_confidence_is_the_documented_noisy_or() -> None:
    """``same_connection`` + ``same_source`` + proximity is the M12.7 example."""
    relationships = [
        Relationship(RelationshipKind.SAME_CONNECTION, CONNECTION_ID),
        Relationship(RelationshipKind.SAME_SOURCE, SOURCE_IP),
        Relationship(RelationshipKind.TIME_PROXIMITY),
    ]
    assert combine_relationships(relationships) == pytest.approx(0.9775, abs=1e-6)


def test_confidence_never_reaches_one() -> None:
    """Every relationship at once is still short of certainty (M12.7)."""
    everything = [Relationship(kind) for kind in RelationshipKind]
    confidence = combine_relationships(everything)
    assert confidence < 1.0
    assert confidence <= MAX_CORRELATION_CONFIDENCE


def test_confidence_is_monotonic_and_order_independent() -> None:
    """Adding a relationship cannot lower it, and order cannot change it."""
    weak = [Relationship(RelationshipKind.SAME_RULE, "port_scan")]
    stronger = weak + [Relationship(RelationshipKind.SAME_SOURCE, SOURCE_IP)]
    assert combine_relationships(stronger) > combine_relationships(weak)
    assert combine_relationships(stronger) == combine_relationships(
        list(reversed(stronger))
    )


def test_confidence_threshold_is_inclusive() -> None:
    """A confidence exactly at the floor joins (M12.7)."""
    assert meets_threshold(0.5, 0.5)
    assert not meets_threshold(0.499999, 0.5)
    assert not meets_threshold(float("nan"), 0.5)
    assert not meets_threshold("high", 0.5)  # type: ignore[arg-type]


def test_describe_confidence_reports_the_workings() -> None:
    """The reported confidence and its explanation come from one computation."""
    relationships = [Relationship(RelationshipKind.SAME_SOURCE, SOURCE_IP)]
    described = describe_confidence(relationships)
    assert described["confidence"] == pytest.approx(
        combine_relationships(relationships), abs=1e-6
    )
    assert described["relationship_count"] == 1
    # The report dict is heterogeneous by design; narrow it for indexing.
    reasons = cast("list[dict[str, Any]]", described["relationships"])
    assert reasons[0]["kind"] == "same_source"
    assert reasons[0]["detail"] == SOURCE_IP


# --------------------------------------------------------------------------
# Window boundaries (M12.5/M12.29)
# --------------------------------------------------------------------------


def test_default_window_matches_its_documented_values() -> None:
    """The defaults are the documented bounds and are internally consistent."""
    window = CorrelationWindow()
    assert window.seconds == DEFAULT_CORRELATION_WINDOW_SECONDS == 900.0
    assert window.proximity_seconds == 300.0
    # The span defaults to the window, so an incident may span one window at most.
    assert window.max_span_seconds == window.seconds


@pytest.mark.parametrize(
    "kwargs",
    [
        {"seconds": 0},
        {"seconds": -1},
        {"seconds": MAX_CORRELATION_WINDOW_SECONDS + 1},
        {"seconds": 600, "proximity_seconds": 900},
        {"proximity_seconds": 0},
        {"max_span_seconds": 0},
        {"max_span_seconds": MAX_INCIDENT_SPAN_SECONDS + 1},
    ],
)
def test_unusable_window_bounds_are_rejected(kwargs: dict[str, float]) -> None:
    """M12.5 requires a bounded window, so an unusable one fails at construction."""
    with pytest.raises(ValueError):
        CorrelationWindow(**kwargs)  # type: ignore[arg-type]


def test_pairwise_boundary_is_inclusive_at_exactly_one_window() -> None:
    """Exactly one window apart correlates; a hair more does not (M12.29)."""
    window = make_window(seconds=900, proximity_seconds=300)
    assert window.pairwise(1_000.0, 1_900.0) is True
    assert window.pairwise(1_000.0, 1_900.001) is False
    assert window.pairwise(1_900.0, 1_000.0) is True  # symmetric


def test_proximity_boundary_is_inclusive_and_tighter_than_the_window() -> None:
    """Just inside proximity strengthens; just outside does not (M12.29)."""
    window = make_window(seconds=900, proximity_seconds=300)
    assert window.are_proximal(1_000.0, 1_300.0) is True
    assert window.are_proximal(1_000.0, 1_300.001) is False
    # Still inside the correlation window, so still a candidate — just not a
    # time-proximal one.
    assert window.pairwise(1_000.0, 1_300.001) is True
    assert window.distance(1_000.0, 1_300.0) == 300.0


def test_contains_boundary() -> None:
    """An event exactly one window before the reference is inside (M12.29)."""
    window = make_window(seconds=900)
    assert window.contains(100.0, 1_000.0) is True
    assert window.contains(-800.0, 100.0) is True
    assert window.contains(-801.0, 100.0) is False
    # A timestamp after the reference means a clock moved backwards; the event
    # is kept rather than dropped.
    assert window.contains(1_100.0, 1_000.0) is True
    assert window.cutoff(1_000.0) == 100.0


def test_incident_accepts_an_event_just_inside_the_window() -> None:
    """An event one window from the incident's last activity joins (M12.29)."""
    window = make_window(seconds=900, proximity_seconds=300, max_span_seconds=3_600)
    assert (
        window.incident_accepts(start_time=1_000.0, last_seen=1_000.0, timestamp=1_900.0)
        is True
    )
    assert (
        window.incident_accepts(
            start_time=1_000.0, last_seen=1_000.0, timestamp=1_900.001
        )
        is False
    )


def test_incident_accepts_an_event_before_its_start() -> None:
    """An out-of-order observation is kept while it is close enough (M12.5)."""
    window = make_window(seconds=900, proximity_seconds=300, max_span_seconds=3_600)
    assert (
        window.incident_accepts(start_time=2_000.0, last_seen=2_000.0, timestamp=1_500.0)
        is True
    )
    assert (
        window.incident_accepts(start_time=2_000.0, last_seen=2_000.0, timestamp=1_000.0)
        is False
    )


def test_incident_span_is_bounded_against_chaining() -> None:
    """An incident cannot grow forever, one in-window step at a time (M12.5).

    This is the failure mode the span cap exists for, so it is asserted against
    the exact numbers rather than around them: every step below *would* pass the
    proximity condition on its own, and only the span condition rejects it.
    """
    window = make_window(seconds=900, proximity_seconds=300, max_span_seconds=900)

    # Within the span: 100s from the last member, 900s in total from the start.
    assert (
        window.incident_accepts(start_time=0.0, last_seen=800.0, timestamp=900.0)
        is True
    )
    # One second further out. Still 800s from the last member — comfortably
    # inside the correlation window — but the incident would now span 1,601s,
    # which the cap forbids. Proximity alone would have chained it on.
    assert (
        window.incident_accepts(start_time=0.0, last_seen=800.0, timestamp=1_601.0)
        is False
    )
    # A single event far beyond the incident's start-relative span is refused
    # even though it is coincident with the incident's last activity.
    assert (
        window.incident_accepts(start_time=0.0, last_seen=1_800.0, timestamp=1_800.0)
        is False
    )
