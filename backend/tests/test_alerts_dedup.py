"""Tests for alert deduplication: the key and the bounded window (M11.27).

Deduplication is what stops a detector that reports the same behaviour once per
packet from flooding the alert store. These tests pin both halves of it: the
*key* decides which observations belong to one incident, and the *window*
decides how long an incident stays open. The two are tested together because a
mistake in either produces the same failure — either an unusable pile of
near-identical alerts or a genuine second incident silently swallowed.

The window is anchored to the finding's observation time (not the wall clock),
so every case here is expressed with finding timestamps and needs no sleeping.
"""

from __future__ import annotations

import pytest

from app.alerts.dedup import (
    DeduplicationKey,
    DeduplicationWindow,
    MAX_DEDUP_WINDOW_SECONDS,
)
from tests.alert_fakes import (
    ALERT_BASE_TIME,
    OTHER_DESTINATION_IP,
    OTHER_SOURCE_IP,
    make_finding,
    make_service,
    stored_alert_count,
)

WINDOW = 300.0


# -- folding inside the window (M11.9/M11.10) -------------------------------


def test_identical_finding_inside_the_window_folds(session_factory) -> None:
    """A repeated observation inside the window creates no second alert."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    first = service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    second = service.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME + 100.0)
    )

    assert first.created is True
    assert second.created is False
    assert second.duplicate is True
    assert second.alert is not None
    assert second.alert.alert_id == first.alert.alert_id  # type: ignore[union-attr]
    assert stored_alert_count(session_factory) == 1


def test_many_observations_inside_the_window_still_fold_to_one(
    session_factory,
) -> None:
    """Ten observations inside the window produce exactly one alert."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    for offset in range(10):
        service.process_finding(
            make_finding(timestamp=ALERT_BASE_TIME + offset * 10.0)
        )

    assert stored_alert_count(session_factory) == 1
    assert service.get_counters().duplicates_folded == 9


def test_observation_exactly_at_the_window_edge_folds(session_factory) -> None:
    """The window is inclusive at its far edge, so the boundary is defined."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    edge = service.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME + WINDOW)
    )

    assert edge.duplicate is True
    assert stored_alert_count(session_factory) == 1


def test_repeat_folds_into_an_acknowledged_alert(session_factory) -> None:
    """An acknowledged alert still belongs to its incident and keeps folding."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)
    first = service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    assert first.alert is not None and first.alert.alert_id is not None

    service.set_status(first.alert.alert_id, "acknowledged")
    repeat = service.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME + 30.0)
    )

    assert repeat.duplicate is True
    assert stored_alert_count(session_factory) == 1


# -- a new alert once the window expires (M11.10) ---------------------------


def test_identical_finding_outside_the_window_creates_a_new_alert(
    session_factory,
) -> None:
    """After the window a repeated observation is a genuinely new incident."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    later = service.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME + WINDOW + 1.0)
    )

    assert later.created is True
    assert stored_alert_count(session_factory) == 2


def test_window_must_be_bounded() -> None:
    """M11.10 forbids an unlimited window; the ceiling is enforced."""
    with pytest.raises(ValueError):
        DeduplicationWindow(MAX_DEDUP_WINDOW_SECONDS + 1.0)
    with pytest.raises(ValueError):
        DeduplicationWindow(0.0)


# -- separate incidents are never merged (M11.9) ----------------------------


def test_different_source_creates_a_separate_alert(session_factory) -> None:
    """A second source scanning the same target is its own incident."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    other = service.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME + 5.0, source_ip=OTHER_SOURCE_IP)
    )

    assert other.created is True
    assert stored_alert_count(session_factory) == 2


def test_different_destination_creates_a_separate_alert(session_factory) -> None:
    """The same source behaving towards a different target is its own incident."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    other = service.process_finding(
        make_finding(
            timestamp=ALERT_BASE_TIME + 5.0, destination_ip=OTHER_DESTINATION_IP
        )
    )

    assert other.created is True
    assert stored_alert_count(session_factory) == 2


def test_different_rule_creates_a_separate_alert(session_factory) -> None:
    """A different detector reporting the same endpoints is a separate incident."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    other = service.process_finding(
        make_finding(
            timestamp=ALERT_BASE_TIME + 5.0,
            rule_id="syn_flood",
            rule_name="SYN Flood",
        )
    )

    assert other.created is True
    assert stored_alert_count(session_factory) == 2


def test_different_connection_is_a_different_key() -> None:
    """A supplied conversation id distinguishes otherwise-identical incidents.

    The service does not resolve a connection into the key (a finding carries
    none), so this is asserted at the key, which is where the component lives
    and which the service builds from.
    """
    finding = make_finding()
    plain = DeduplicationKey.from_finding(finding)
    withconn = DeduplicationKey.from_finding(finding, connection_id="conn-9")

    assert plain.value() != withconn.value()
    assert plain.components()["connection_id"] == "-"
    assert withconn.components()["connection_id"] == "conn-9"


def test_independent_alerts_coexist(session_factory) -> None:
    """Several distinct incidents are each stored as their own alert."""
    service = make_service(session_factory, dedup_window_seconds=WINDOW)

    service.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    service.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME, source_ip=OTHER_SOURCE_IP)
    )
    service.process_finding(
        make_finding(
            timestamp=ALERT_BASE_TIME,
            rule_id="icmp_flood",
            rule_name="ICMP Flood",
        )
    )

    assert stored_alert_count(session_factory) == 3
    assert service.get_counters().alerts_created == 3
    assert service.get_counters().duplicates_folded == 0


def test_deduplication_is_configurable_per_service(session_factory) -> None:
    """A shorter window lets the same incident raise a second alert sooner."""
    short = make_service(session_factory, dedup_window_seconds=10.0)

    short.process_finding(make_finding(timestamp=ALERT_BASE_TIME))
    later = short.process_finding(
        make_finding(timestamp=ALERT_BASE_TIME + 11.0)
    )

    assert later.created is True
    assert stored_alert_count(session_factory) == 2
