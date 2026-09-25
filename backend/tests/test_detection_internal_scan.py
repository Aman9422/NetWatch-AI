"""Behavioural tests for the internal network scan detector (M10.27).

The detector counts the distinct *internal* destinations one source contacts
inside a window. These tests cover the threshold boundary, the internal-address
filter that keeps external traffic out of the count, source isolation, the
self-contact and non-attempt exclusions, and bounded state.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.detection import InternalNetworkClassifier, InternalScanRule
from app.schemas.packet import NormalizedPacket
from tests.detection_fakes import (
    DEFAULT_SOURCE_IP,
    DETECTION_BASE_TIME,
    feed,
    make_context,
    make_syn_packet,
)

# Private-range addresses used as the internal destinations of a sweep.
INTERNAL_A = "10.0.0.1"
INTERNAL_B = "10.0.0.2"
INTERNAL_C = "10.0.0.3"
INTERNAL_D = "10.0.0.4"
INTERNAL_E = "10.0.0.5"

# Globally routable addresses, which must never be counted as internal.
EXTERNAL_A = "8.8.8.8"
EXTERNAL_B = "1.1.1.1"
EXTERNAL_C = "9.9.9.9"


def internal_ips(count: int) -> list[str]:
    """Return ``count`` distinct private destination addresses."""
    return [f"10.0.0.{index}" for index in range(1, count + 1)]


def attempts_to(
    destination_ips: Iterable[str],
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    destination_port: int = 443,
    start_time: float = DETECTION_BASE_TIME,
) -> list[NormalizedPacket]:
    """Build one connection attempt from ``source_ip`` per destination."""
    return [
        make_syn_packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            timestamp=start_time,
        )
        for destination_ip in destination_ips
    ]


# ---------------------------------------------------------------------------
# The threshold boundary (M10.27)
# ---------------------------------------------------------------------------


def test_few_internal_destinations_stay_silent() -> None:
    """Four internal hosts against a threshold of five is not a sweep (M10.27)."""
    rule = InternalScanRule(unique_destination_threshold=5)

    findings = feed(rule, attempts_to(internal_ips(4)))

    assert findings == []


def test_the_threshold_boundary_fires_once() -> None:
    """Five distinct internal hosts reach a threshold of five (M10.27)."""
    rule = InternalScanRule(unique_destination_threshold=5)

    findings = feed(rule, attempts_to(internal_ips(5)))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "internal_scan"
    assert finding.rule_name == "Internal Network Scan"
    assert finding.source_ip == DEFAULT_SOURCE_IP
    # A sweep spans destinations, so no single destination is claimed.
    assert finding.destination_ip is None
    assert finding.evidence["unique_internal_destinations"] == 5
    assert finding.evidence["unique_destination_threshold"] == 5


def test_a_large_number_of_destinations_keeps_reporting() -> None:
    """A long sweep of internal hosts produces findings (M10.27)."""
    rule = InternalScanRule(unique_destination_threshold=5)

    findings = feed(rule, attempts_to(internal_ips(30)))

    assert findings
    assert all(
        int(finding.evidence["unique_internal_destinations"]) >= 5
        for finding in findings
    )


def test_repeated_one_destination_is_not_a_sweep() -> None:
    """Only *distinct* internal destinations count toward the threshold."""
    rule = InternalScanRule(unique_destination_threshold=5)

    findings = feed(rule, attempts_to([INTERNAL_A] * 40))

    assert findings == []


# ---------------------------------------------------------------------------
# Internal address filtering (M10.27)
# ---------------------------------------------------------------------------


def test_external_destinations_are_never_counted() -> None:
    """A client talking to many public hosts is not sweeping (M10.11)."""
    rule = InternalScanRule(unique_destination_threshold=3)
    external = [EXTERNAL_A, EXTERNAL_B, EXTERNAL_C, "4.4.4.4", "5.5.5.5"]

    findings = feed(rule, attempts_to(external))

    assert findings == []


def test_only_internal_destinations_advance_the_count() -> None:
    """External traffic is filtered out before the destinations are counted."""
    rule = InternalScanRule(unique_destination_threshold=3)
    mixed = [INTERNAL_A, INTERNAL_B, EXTERNAL_A, EXTERNAL_B, EXTERNAL_C]

    mixed_only = feed(rule, attempts_to(mixed))
    assert mixed_only == []

    # The two internal hosts were counted; one more crosses the threshold.
    findings = feed(rule, attempts_to([INTERNAL_C]))

    assert len(findings) == 1
    assert findings[0].evidence["unique_internal_destinations"] == 3


def test_the_classifier_owns_address_policy_is_applied() -> None:
    """An injected classifier decides what "internal" means (M10.11)."""
    classifier = InternalNetworkClassifier(
        local_addresses_provider=lambda: {EXTERNAL_A}
    )

    # 8.8.8.8 is globally routable, but the classifier reports it as one of the
    # host's own addresses, so the detector treats it as an internal host.
    own_rule = InternalScanRule(
        unique_destination_threshold=1, classifier=classifier
    )
    own_findings = feed(own_rule, attempts_to([EXTERNAL_A]))

    assert len(own_findings) == 1
    assert own_findings[0].evidence["unique_internal_destinations"] == 1

    # 1.1.1.1 is neither private nor an own address, so it stays external.
    external_rule = InternalScanRule(
        unique_destination_threshold=1, classifier=classifier
    )

    assert feed(external_rule, attempts_to([EXTERNAL_B])) == []


def test_a_source_contacting_itself_is_ignored() -> None:
    """Talking to one's own address is not a sweep (M10.11)."""
    rule = InternalScanRule(unique_destination_threshold=2)
    packet = make_syn_packet(
        source_ip=INTERNAL_A, destination_ip=INTERNAL_A, destination_port=443
    )

    assert rule.evaluate(make_context(packet=packet)) is None


# ---------------------------------------------------------------------------
# Sources and windows (M10.27)
# ---------------------------------------------------------------------------


def test_sources_are_measured_independently() -> None:
    """One source's internal sweep does not implicate another (M10.27)."""
    rule = InternalScanRule(unique_destination_threshold=5)
    quiet = attempts_to(
        [INTERNAL_A, INTERNAL_B], source_ip="10.0.0.200"
    )
    noisy = attempts_to(internal_ips(5), source_ip="10.0.0.201")

    findings = feed(rule, quiet + noisy)

    assert len(findings) == 1
    assert findings[0].source_ip == "10.0.0.201"


def test_destinations_in_a_new_window_do_not_accumulate() -> None:
    """Internal hosts seen in an elapsed window are not carried forward."""
    rule = InternalScanRule(window_seconds=10.0, unique_destination_threshold=5)
    first = attempts_to(internal_ips(4), start_time=DETECTION_BASE_TIME)
    second = attempts_to(
        internal_ips(4), start_time=DETECTION_BASE_TIME + 100.0
    )

    findings = feed(rule, first + second)

    assert findings == []


def test_the_finding_states_the_observed_window() -> None:
    """Evidence states the window the count was measured over (M10.14)."""
    rule = InternalScanRule(
        window_seconds=8.0, unique_destination_threshold=3
    )

    findings = feed(rule, attempts_to(internal_ips(3)))

    evidence = findings[0].evidence
    assert evidence["observation_window_seconds"] == 8.0
    assert evidence["connection_attempts"] == 3


# ---------------------------------------------------------------------------
# Inputs the rule must not count (M10.27)
# ---------------------------------------------------------------------------


def test_only_connection_attempts_are_counted() -> None:
    """A server answering many internal clients is not sweeping (M10.11)."""
    rule = InternalScanRule(unique_destination_threshold=3)
    packets = [
        make_syn_packet(
            destination_ip=destination_ip, destination_port=443, tcp_flags="SA"
        )
        for destination_ip in internal_ips(8)
    ]

    findings = feed(rule, packets)

    assert findings == []


def test_a_context_without_a_packet_is_ignored() -> None:
    """A periodic pass with no packet reports nothing."""
    rule = InternalScanRule(unique_destination_threshold=3)

    assert rule.evaluate(make_context()) is None


def test_a_packet_without_addresses_is_ignored() -> None:
    """The detector needs a source and an internal destination (M10.14)."""
    rule = InternalScanRule(unique_destination_threshold=3)
    no_source = make_syn_packet(source_ip=None, destination_ip=INTERNAL_A)
    no_destination = make_syn_packet(
        source_ip=DEFAULT_SOURCE_IP, destination_ip=None
    )

    assert rule.evaluate(make_context(packet=no_source)) is None
    assert rule.evaluate(make_context(packet=no_destination)) is None


# ---------------------------------------------------------------------------
# Bounded state (M10.19)
# ---------------------------------------------------------------------------


def test_firing_clears_the_source_state() -> None:
    """The suppression leaves nothing behind for the next window (M10.18)."""
    rule = InternalScanRule(unique_destination_threshold=5)

    feed(rule, attempts_to(internal_ips(5)))

    assert rule.state_size() == 0


def test_reset_discards_every_source() -> None:
    """Reset returns the detector to an empty state (M10.19)."""
    rule = InternalScanRule(unique_destination_threshold=50)
    feed(rule, attempts_to(internal_ips(3), source_ip="10.0.0.200"))
    feed(rule, attempts_to(internal_ips(3), source_ip="10.0.0.201"))
    assert rule.state_size() == 2

    rule.reset()

    assert rule.state_size() == 0
