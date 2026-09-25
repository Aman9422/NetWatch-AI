"""Behavioural tests for the port scan detector (M10.24).

The detector's contract is narrow: count the distinct destination ports one
source opens contact with inside a window, and report the source once that count
reaches the configured threshold. These tests pin down the threshold boundary,
the tumbling window, the SYN/multi-port characterisation, the minimal
suppression and the negative cases that must stay silent.
"""

from __future__ import annotations

from app.detection import PortScanRule
from tests.detection_fakes import (
    DEFAULT_DESTINATION_IP,
    DEFAULT_SOURCE_IP,
    DETECTION_BASE_TIME,
    feed,
    make_context,
    make_syn_packet,
    make_udp_attempt,
    syn_packets,
)


def ports(*port_numbers: int) -> list[int]:
    """Return the port numbers as an explicit list, for readable expectations."""
    return list(port_numbers)


# ---------------------------------------------------------------------------
# The threshold boundary (M10.24)
# ---------------------------------------------------------------------------


def test_a_scan_below_the_port_threshold_stays_silent() -> None:
    """Four distinct ports against a threshold of five is not a scan (M10.24)."""
    rule = PortScanRule(unique_port_threshold=5)

    findings = feed(rule, syn_packets(destination_ports=range(1, 5)))

    assert findings == []


def test_a_scan_exactly_at_the_port_threshold_fires_once() -> None:
    """The condition is met at the threshold, not one port later (M10.24)."""
    rule = PortScanRule(unique_port_threshold=5)

    findings = feed(rule, syn_packets(destination_ports=range(1, 6)))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "port_scan"
    assert finding.rule_name == "Port Scan"
    assert finding.source_ip == DEFAULT_SOURCE_IP
    # A scan spans destinations, so no single destination is claimed.
    assert finding.destination_ip is None
    assert finding.evidence["unique_destination_ports"] == 5
    assert finding.evidence["unique_port_threshold"] == 5


def test_a_scan_past_the_threshold_keeps_reporting() -> None:
    """A source sweeping far beyond the threshold still produces findings."""
    rule = PortScanRule(unique_port_threshold=5)

    findings = feed(rule, syn_packets(destination_ports=range(1, 21)))

    assert findings
    assert all(
        int(finding.evidence["unique_destination_ports"]) >= 5
        for finding in findings
    )
    assert all(finding.source_ip == DEFAULT_SOURCE_IP for finding in findings)


def test_crossing_the_threshold_forgets_the_source() -> None:
    """One window cannot emit a stream of identical findings (M10.18)."""
    rule = PortScanRule(unique_port_threshold=5)

    # Twenty ports with a threshold of five: the source is forgotten each time
    # it fires, so the sweep produces one finding per completed batch of five.
    findings = feed(rule, syn_packets(destination_ports=range(1, 21)))

    assert len(findings) == 4
    assert all(
        finding.evidence["unique_destination_ports"] == 5 for finding in findings
    )


def test_repeating_one_port_is_never_a_scan() -> None:
    """Only *distinct* ports count, so a client retrying one port is silent."""
    rule = PortScanRule(unique_port_threshold=5)

    findings = feed(
        rule, syn_packets(destination_port=443, count=50)
    )

    assert findings == []
    assert rule.state_size() == 1


# ---------------------------------------------------------------------------
# Sources and windows (M10.24)
# ---------------------------------------------------------------------------


def test_sources_are_measured_independently() -> None:
    """One source below the threshold does not carry another over it."""
    rule = PortScanRule(unique_port_threshold=5)
    quiet = syn_packets(source_ip="10.0.0.1", destination_ports=range(1, 4))
    noisy = syn_packets(source_ip="10.0.0.2", destination_ports=range(1, 6))

    findings = feed(rule, quiet + noisy)

    assert len(findings) == 1
    assert findings[0].source_ip == "10.0.0.2"


def test_ports_are_counted_across_one_window() -> None:
    """Three ports now and three more a second later cross a threshold of five."""
    rule = PortScanRule(window_seconds=10.0, unique_port_threshold=5)
    first = syn_packets(destination_ports=range(1, 4), start_time=DETECTION_BASE_TIME)
    second = syn_packets(
        destination_ports=range(100, 103), start_time=DETECTION_BASE_TIME + 1.0
    )

    findings = feed(rule, first + second)

    assert len(findings) == 1
    assert findings[0].evidence["unique_destination_ports"] == 5


def test_a_new_window_restarts_the_port_count() -> None:
    """Ports seen in an elapsed window are not carried forward (M10.13)."""
    rule = PortScanRule(window_seconds=10.0, unique_port_threshold=5)
    first = syn_packets(destination_ports=range(1, 4), start_time=DETECTION_BASE_TIME)
    second = syn_packets(
        destination_ports=range(100, 103), start_time=DETECTION_BASE_TIME + 100.0
    )

    findings = feed(rule, first + second)

    assert findings == []


# ---------------------------------------------------------------------------
# Characterisation: SYN scan versus multi-port (M10.24)
# ---------------------------------------------------------------------------


def test_a_syn_sweep_is_reported_as_a_syn_scan() -> None:
    """When every attempt is a pure SYN, the wording says so (M10.8)."""
    rule = PortScanRule(unique_port_threshold=5)

    findings = feed(rule, syn_packets(destination_ports=range(1, 6)))

    finding = findings[0]
    assert "SYN port scan" in finding.description
    assert finding.evidence["syn_attempts"] == 5
    assert finding.evidence["connection_attempts"] == 5
    assert finding.evidence["syn_ratio"] == 1.0
    assert finding.metadata["scan_characterisation"] == "syn"


def test_a_udp_sweep_is_reported_as_multi_port() -> None:
    """A datagram sweep from ephemeral ports is not labelled a SYN scan."""
    rule = PortScanRule(unique_port_threshold=5)
    packets = [
        make_udp_attempt(destination_port=port) for port in range(1, 6)
    ]

    findings = feed(rule, packets)

    finding = findings[0]
    assert finding.description == f"Possible port scan detected from {DEFAULT_SOURCE_IP}"
    assert finding.protocol == "UDP"
    assert finding.evidence["syn_attempts"] == 0
    assert finding.evidence["syn_ratio"] == 0.0
    assert finding.metadata["scan_characterisation"] == "multi_port"


def test_the_finding_carries_the_observed_window() -> None:
    """Evidence states the window the count was measured over (M10.14)."""
    rule = PortScanRule(window_seconds=7.5, unique_port_threshold=3)

    findings = feed(rule, syn_packets(destination_ports=range(1, 4)))

    evidence = findings[0].evidence
    assert evidence["observation_window_seconds"] == 7.5
    assert "window_start" in evidence


# ---------------------------------------------------------------------------
# Inputs the rule must not count (M10.24)
# ---------------------------------------------------------------------------


def test_only_connection_attempts_are_counted() -> None:
    """A bare ACK or a SYN+ACK is part of a conversation, not a scan."""
    rule = PortScanRule(unique_port_threshold=3)
    packets = [
        make_syn_packet(destination_port=port, tcp_flags="A")
        for port in range(1, 8)
    ]

    findings = feed(rule, packets)

    assert findings == []


def test_a_syn_ack_reply_is_not_a_connection_attempt() -> None:
    """A server answering from many ports is not scanning (M10.8)."""
    rule = PortScanRule(unique_port_threshold=3)
    packets = [
        make_syn_packet(destination_port=port, tcp_flags="SA")
        for port in range(1, 8)
    ]

    findings = feed(rule, packets)

    assert findings == []


def test_a_context_without_a_packet_is_ignored() -> None:
    """A snapshot evaluation cannot be a scan, so it reports nothing."""
    rule = PortScanRule(unique_port_threshold=3)

    assert rule.evaluate(make_context()) is None


def test_a_packet_without_a_source_address_is_ignored() -> None:
    """The detector names the scanning source, so it needs one (M10.14)."""
    rule = PortScanRule(unique_port_threshold=3)
    packet = make_syn_packet(source_ip=None, destination_port=80)

    assert rule.evaluate(make_context(packet=packet)) is None


# ---------------------------------------------------------------------------
# Bounded state (M10.19)
# ---------------------------------------------------------------------------


def test_firing_clears_the_source_state() -> None:
    """The suppression leaves nothing behind for the next window (M10.18)."""
    rule = PortScanRule(unique_port_threshold=5)

    feed(rule, syn_packets(destination_ports=range(1, 6)))

    assert rule.state_size() == 0


def test_reset_discards_every_source() -> None:
    """Reset returns the detector to an empty state (M10.19)."""
    rule = PortScanRule(unique_port_threshold=50)
    feed(rule, syn_packets(source_ip="10.0.0.1", destination_ports=range(1, 4)))
    feed(rule, syn_packets(source_ip="10.0.0.2", destination_ports=range(1, 4)))
    assert rule.state_size() == 2

    rule.reset()

    assert rule.state_size() == 0


def test_normal_client_traffic_stays_silent() -> None:
    """A client talking to a handful of destinations is not a scan (M10.24)."""
    rule = PortScanRule(unique_port_threshold=20)
    packets = []
    for repeat in range(5):
        packets.extend(
            syn_packets(
                destination_ip=DEFAULT_DESTINATION_IP,
                destination_ports=ports(443, 80, 53),
                start_time=DETECTION_BASE_TIME + repeat,
            )
        )

    findings = feed(rule, packets)

    assert findings == []
