"""Behavioural tests for the SYN flood detector (M10.25).

The detector keys on the *destination*: how many TCP SYNs one host is receiving
per second, averaged over a configurable window. These tests cover the rate
boundary, destination isolation, the window, the minimum-packet floor and the
fact that a distributed flood is not pinned on one arbitrary source.
"""

from __future__ import annotations

from app.detection import SynFloodRule
from tests.detection_fakes import (
    DEFAULT_DESTINATION_IP,
    DEFAULT_SOURCE_IP,
    DETECTION_BASE_TIME,
    feed,
    make_context,
    make_syn_packet,
    syn_packets,
)

# A one-second window with a ten-per-second threshold: the boundary is reached
# by ten SYNs, which keeps the tests small without changing the behaviour.
WINDOW_SECONDS = 1.0
RATE_THRESHOLD = 10.0


def flood_rule(**overrides: object) -> SynFloodRule:
    """Build a SYN flood rule with the test's small window and threshold."""
    values: dict[str, object] = {
        "window_seconds": WINDOW_SECONDS,
        "rate_threshold": RATE_THRESHOLD,
    }
    values.update(overrides)
    return SynFloodRule(**values)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The rate boundary (M10.25)
# ---------------------------------------------------------------------------


def test_a_syn_rate_below_the_threshold_stays_silent() -> None:
    """Nine SYNs in a one-second window are below a threshold of ten."""
    rule = flood_rule()

    findings = feed(rule, syn_packets(destination_port=443, count=9))

    assert findings == []


def test_a_syn_rate_exactly_at_the_threshold_fires_once() -> None:
    """The condition is met at the configured rate (M10.25)."""
    rule = flood_rule()

    findings = feed(rule, syn_packets(destination_port=443, count=10))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "syn_flood"
    assert finding.rule_name == "SYN Flood"
    assert finding.destination_ip == DEFAULT_DESTINATION_IP
    assert finding.protocol == "TCP"
    assert finding.evidence["syn_packets"] == 10
    assert finding.evidence["syn_packets_per_second"] == 10.0
    assert finding.evidence["syn_rate_threshold"] == RATE_THRESHOLD


def test_a_syn_rate_above_the_threshold_keeps_reporting() -> None:
    """A sustained flood is reported, not silently swallowed after one firing."""
    rule = flood_rule()

    findings = feed(rule, syn_packets(destination_port=443, count=25))

    assert len(findings) == 2
    assert all(finding.destination_ip == DEFAULT_DESTINATION_IP for finding in findings)


def test_a_single_syn_is_never_a_flood() -> None:
    """However low the threshold, one packet is not a flood (M10.9)."""
    rule = flood_rule(rate_threshold=0.5)

    findings = feed(rule, syn_packets(destination_port=443, count=1))

    assert findings == []


def test_two_syns_can_constitute_a_flood_when_the_threshold_allows() -> None:
    """The floor is two packets, and the threshold decides from there (M10.9)."""
    rule = flood_rule(rate_threshold=0.5)

    findings = feed(rule, syn_packets(destination_port=443, count=2))

    assert len(findings) == 1
    assert findings[0].evidence["syn_packets"] == 2


# ---------------------------------------------------------------------------
# Destinations and windows (M10.25)
# ---------------------------------------------------------------------------


def test_destinations_are_measured_independently() -> None:
    """SYNs spread across two hosts do not flood either one (M10.25)."""
    rule = flood_rule()
    first = syn_packets(destination_ip="10.0.0.1", destination_port=443, count=5)
    second = syn_packets(destination_ip="10.0.0.2", destination_port=443, count=5)

    findings = feed(rule, first + second)

    assert findings == []


def test_the_finding_names_the_flooded_destination() -> None:
    """The party being flooded is named, and only it (M10.9)."""
    rule = flood_rule()
    background = syn_packets(destination_ip="10.0.0.1", destination_port=443, count=5)
    flood = syn_packets(destination_ip="10.0.0.2", destination_port=443, count=10)

    findings = feed(rule, background + flood)

    assert len(findings) == 1
    assert findings[0].destination_ip == "10.0.0.2"


def test_syns_in_a_new_window_do_not_accumulate() -> None:
    """A rate measured over an elapsed window does not carry forward (M10.13)."""
    rule = flood_rule()
    first = syn_packets(
        destination_port=443, count=6, start_time=DETECTION_BASE_TIME
    )
    second = syn_packets(
        destination_port=443, count=6, start_time=DETECTION_BASE_TIME + 100.0
    )

    findings = feed(rule, first + second)

    assert findings == []


def test_syns_are_accumulated_across_one_window() -> None:
    """Six SYNs now and six a fraction later flood one window (M10.25)."""
    rule = flood_rule()
    first = syn_packets(
        destination_port=443, count=6, start_time=DETECTION_BASE_TIME
    )
    second = syn_packets(
        destination_port=443, count=6, start_time=DETECTION_BASE_TIME + 0.1
    )

    findings = feed(rule, first + second)

    assert len(findings) == 1
    assert findings[0].evidence["syn_packets"] == 10


# ---------------------------------------------------------------------------
# Sources and evidence (M10.25)
# ---------------------------------------------------------------------------


def test_a_single_source_flood_names_its_source() -> None:
    """When exactly one source was observed, it is reported (M10.14)."""
    rule = flood_rule()

    findings = feed(rule, syn_packets(destination_port=443, count=10))

    finding = findings[0]
    assert finding.source_ip == DEFAULT_SOURCE_IP
    assert finding.evidence["distinct_sources"] == 1


def test_a_distributed_flood_names_no_single_source() -> None:
    """Several observed sources are counted, not pinned on one (M10.14)."""
    rule = flood_rule(rate_threshold=5.0)
    packets = [
        make_syn_packet(source_ip="10.0.0.1", timestamp=DETECTION_BASE_TIME),
        make_syn_packet(source_ip="10.0.0.2", timestamp=DETECTION_BASE_TIME),
        make_syn_packet(source_ip="10.0.0.3", timestamp=DETECTION_BASE_TIME),
        make_syn_packet(source_ip="10.0.0.1", timestamp=DETECTION_BASE_TIME),
        make_syn_packet(source_ip="10.0.0.2", timestamp=DETECTION_BASE_TIME),
    ]

    findings = feed(rule, packets)

    finding = findings[0]
    assert finding.source_ip is None
    assert finding.evidence["distinct_sources"] == 3


def test_the_finding_states_the_observed_window() -> None:
    """Evidence reports the window the rate was averaged over (M10.14)."""
    rule = flood_rule(window_seconds=2.0, rate_threshold=5.0)

    findings = feed(rule, syn_packets(destination_port=443, count=10))

    evidence = findings[0].evidence
    assert evidence["observation_window_seconds"] == 2.0
    assert evidence["syn_packets_per_second"] == 5.0


# ---------------------------------------------------------------------------
# Inputs the rule must not count (M10.25)
# ---------------------------------------------------------------------------


def test_syn_ack_replies_are_not_counted() -> None:
    """A SYN+ACK answers a SYN; it is not itself a flood (M10.9)."""
    rule = flood_rule(rate_threshold=1.0)
    packets = [
        make_syn_packet(
            destination_port=443, tcp_flags="SA", timestamp=DETECTION_BASE_TIME
        )
        for _ in range(50)
    ]

    findings = feed(rule, packets)

    assert findings == []


def test_non_tcp_traffic_is_not_counted() -> None:
    """Only TCP SYNs contribute to a SYN rate (M10.9)."""
    rule = flood_rule(rate_threshold=1.0)
    packets = [
        make_syn_packet(
            destination_port=443, protocol="UDP", timestamp=DETECTION_BASE_TIME
        )
        for _ in range(50)
    ]

    findings = feed(rule, packets)

    assert findings == []


def test_a_context_without_a_packet_is_ignored() -> None:
    """A periodic pass with no packet reports nothing."""
    rule = flood_rule()

    assert rule.evaluate(make_context()) is None


def test_a_packet_without_a_destination_is_ignored() -> None:
    """The detector names the flooded destination, so it needs one (M10.14)."""
    rule = flood_rule()
    packet = make_syn_packet(destination_ip=None, destination_port=443)

    assert rule.evaluate(make_context(packet=packet)) is None


# ---------------------------------------------------------------------------
# Bounded state (M10.19)
# ---------------------------------------------------------------------------


def test_normal_syn_traffic_stays_silent() -> None:
    """An ordinary handshake opens with a single SYN (M10.25)."""
    rule = flood_rule()

    findings = feed(rule, syn_packets(destination_port=443, count=3))

    assert findings == []
    assert rule.state_size() == 1


def test_firing_clears_the_destination_state() -> None:
    """The suppression leaves nothing behind for the next window (M10.18)."""
    rule = flood_rule()

    feed(rule, syn_packets(destination_port=443, count=10))

    assert rule.state_size() == 0


def test_reset_discards_every_destination() -> None:
    """Reset returns the detector to an empty state (M10.19)."""
    rule = flood_rule(rate_threshold=1000.0)
    feed(rule, syn_packets(destination_ip="10.0.0.1", destination_port=443, count=3))
    feed(rule, syn_packets(destination_ip="10.0.0.2", destination_port=443, count=3))
    assert rule.state_size() == 2

    rule.reset()

    assert rule.state_size() == 0
