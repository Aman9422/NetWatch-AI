"""Behavioural tests for the ICMP flood detector (M10.26).

The detector keys on the *destination*: how many ICMP packets one host is
receiving per second, averaged over a configurable window. These tests cover the
rate boundary, window behaviour, the fact that ordinary ping traffic is never
reported, and the same distributed-source honesty as the SYN flood detector.
"""

from __future__ import annotations

from app.detection import IcmpFloodRule
from tests.detection_fakes import (
    DEFAULT_DESTINATION_IP,
    DEFAULT_SOURCE_IP,
    DETECTION_BASE_TIME,
    feed,
    make_context,
    make_icmp_packet,
    make_syn_packet,
    repeated_icmp,
)

# A one-second window with a ten-per-second threshold: ten packets reach it.
WINDOW_SECONDS = 1.0
RATE_THRESHOLD = 10.0


def icmp_rule(**overrides: object) -> IcmpFloodRule:
    """Build an ICMP flood rule with the test's small window and threshold."""
    values: dict[str, object] = {
        "window_seconds": WINDOW_SECONDS,
        "rate_threshold": RATE_THRESHOLD,
    }
    values.update(overrides)
    return IcmpFloodRule(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The rate boundary (M10.26)
# ---------------------------------------------------------------------------


def test_an_icmp_rate_below_the_threshold_stays_silent() -> None:
    """Nine ICMP packets in a one-second window are below a threshold of ten."""
    rule = icmp_rule()

    findings = feed(rule, repeated_icmp(count=9))

    assert findings == []


def test_an_icmp_rate_exactly_at_the_threshold_fires_once() -> None:
    """The condition is met at the configured rate (M10.26)."""
    rule = icmp_rule()

    findings = feed(rule, repeated_icmp(count=10))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "icmp_flood"
    assert finding.rule_name == "ICMP Flood"
    assert finding.destination_ip == DEFAULT_DESTINATION_IP
    assert finding.protocol == "ICMP"
    assert finding.evidence["icmp_packets"] == 10
    assert finding.evidence["icmp_packets_per_second"] == 10.0
    assert finding.evidence["icmp_rate_threshold"] == RATE_THRESHOLD


def test_an_icmp_rate_above_the_threshold_keeps_reporting() -> None:
    """A sustained flood is reported more than once (M10.26)."""
    rule = icmp_rule()

    findings = feed(rule, repeated_icmp(count=25))

    assert len(findings) == 2
    assert all(
        finding.destination_ip == DEFAULT_DESTINATION_IP for finding in findings
    )


def test_a_single_icmp_packet_is_never_a_flood() -> None:
    """A lone echo request is a ping, not a flood, whatever the threshold."""
    rule = icmp_rule(rate_threshold=0.5)

    findings = feed(rule, repeated_icmp(count=1))

    assert findings == []


# ---------------------------------------------------------------------------
# Ordinary ping traffic (M10.26)
# ---------------------------------------------------------------------------


def test_a_normal_ping_sequence_stays_silent() -> None:
    """A handful of echo requests over a second is not a flood (M10.10)."""
    rule = icmp_rule()

    findings = feed(rule, repeated_icmp(count=4, step=0.25))

    assert findings == []


# ---------------------------------------------------------------------------
# Destinations and windows (M10.26)
# ---------------------------------------------------------------------------


def test_destinations_are_measured_independently() -> None:
    """ICMP spread across two hosts floods neither one (M10.26)."""
    rule = icmp_rule()
    first = repeated_icmp(destination_ip="10.0.0.1", count=5)
    second = repeated_icmp(destination_ip="10.0.0.2", count=5)

    findings = feed(rule, first + second)

    assert findings == []


def test_icmp_in_a_new_window_does_not_accumulate() -> None:
    """A rate measured over an elapsed window does not carry forward (M10.13)."""
    rule = icmp_rule()
    first = repeated_icmp(count=6, start_time=DETECTION_BASE_TIME)
    second = repeated_icmp(count=6, start_time=DETECTION_BASE_TIME + 100.0)

    findings = feed(rule, first + second)

    assert findings == []


def test_icmp_is_accumulated_across_one_window() -> None:
    """Six packets now and six a fraction later flood one window (M10.26)."""
    rule = icmp_rule()
    first = repeated_icmp(count=6, start_time=DETECTION_BASE_TIME)
    second = repeated_icmp(count=6, start_time=DETECTION_BASE_TIME + 0.1)

    findings = feed(rule, first + second)

    assert len(findings) == 1
    assert findings[0].evidence["icmp_packets"] == 10


def test_the_finding_states_the_observed_window() -> None:
    """Evidence reports the window the rate was averaged over (M10.14)."""
    rule = icmp_rule(window_seconds=2.0, rate_threshold=5.0)

    findings = feed(rule, repeated_icmp(count=10))

    evidence = findings[0].evidence
    assert evidence["observation_window_seconds"] == 2.0
    assert evidence["icmp_packets_per_second"] == 5.0


# ---------------------------------------------------------------------------
# Sources and evidence (M10.26)
# ---------------------------------------------------------------------------


def test_a_single_source_flood_names_its_source() -> None:
    """When exactly one source was observed, it is reported (M10.14)."""
    rule = icmp_rule()

    findings = feed(rule, repeated_icmp(count=10))

    finding = findings[0]
    assert finding.source_ip == DEFAULT_SOURCE_IP
    assert finding.evidence["distinct_sources"] == 1


def test_a_distributed_flood_names_no_single_source() -> None:
    """Several observed sources are counted, not pinned on one (M10.14)."""
    rule = icmp_rule(rate_threshold=5.0)
    packets = [
        make_icmp_packet(source_ip="10.0.0.1", timestamp=DETECTION_BASE_TIME),
        make_icmp_packet(source_ip="10.0.0.2", timestamp=DETECTION_BASE_TIME),
        make_icmp_packet(source_ip="10.0.0.3", timestamp=DETECTION_BASE_TIME),
        make_icmp_packet(source_ip="10.0.0.1", timestamp=DETECTION_BASE_TIME),
        make_icmp_packet(source_ip="10.0.0.2", timestamp=DETECTION_BASE_TIME),
    ]

    findings = feed(rule, packets)

    finding = findings[0]
    assert finding.source_ip is None
    assert finding.evidence["distinct_sources"] == 3


# ---------------------------------------------------------------------------
# Inputs the rule must not count (M10.26)
# ---------------------------------------------------------------------------


def test_tcp_traffic_is_not_counted() -> None:
    """A SYN is not ICMP, so it contributes nothing to an ICMP rate."""
    rule = icmp_rule(rate_threshold=1.0)
    packets = [
        make_syn_packet(timestamp=DETECTION_BASE_TIME) for _ in range(50)
    ]

    findings = feed(rule, packets)

    assert findings == []


def test_a_context_without_a_packet_is_ignored() -> None:
    """A periodic pass with no packet reports nothing."""
    rule = icmp_rule()

    assert rule.evaluate(make_context()) is None


def test_a_packet_without_a_destination_is_ignored() -> None:
    """The detector names the flooded destination, so it needs one (M10.14)."""
    rule = icmp_rule()
    packet = make_icmp_packet(destination_ip=None)

    assert rule.evaluate(make_context(packet=packet)) is None


# ---------------------------------------------------------------------------
# Bounded state (M10.19)
# ---------------------------------------------------------------------------


def test_firing_clears_the_destination_state() -> None:
    """The suppression leaves nothing behind for the next window (M10.18)."""
    rule = icmp_rule()

    feed(rule, repeated_icmp(count=10))

    assert rule.state_size() == 0


def test_reset_discards_every_destination() -> None:
    """Reset returns the detector to an empty state (M10.19)."""
    rule = icmp_rule(rate_threshold=1000.0)
    feed(rule, repeated_icmp(destination_ip="10.0.0.1", count=3))
    feed(rule, repeated_icmp(destination_ip="10.0.0.2", count=3))
    assert rule.state_size() == 2

    rule.reset()

    assert rule.state_size() == 0
