"""Test doubles and builders for the M10 detection tests (M10.23-M10.29).

Detection tests need three things the generic :mod:`tests.fakes` module does
not provide: packets shaped like the behaviour each detector observes, a way to
build a :class:`~app.detection.context.DetectionContext` without the engine, and
rules that fire, stay silent, record what they were shown or fail on demand.

Like ``tests.fakes``, this module holds no assertions - it exists so each test
file states *what it expects* rather than how to construct the input.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from app.detection.base import DetectionRule
from app.detection.context import DetectionContext
from app.detection.finding import DetectionFinding
from app.schemas.packet import NormalizedPacket, PacketType
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet

# Detection tests share the packet base time so every window is deterministic.
DETECTION_BASE_TIME = PACKET_BASE_TIME

DEFAULT_SOURCE_IP = "192.168.1.10"
DEFAULT_DESTINATION_IP = "8.8.8.8"


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------


def make_syn_packet(**overrides: Any) -> NormalizedPacket:
    """Build a pure TCP SYN - the connection attempt a scanner emits (M10.8)."""
    values: dict[str, Any] = {
        "protocol": "TCP",
        "packet_type": PacketType.TCP,
        "tcp_flags": "S",
    }
    values.update(overrides)
    return make_normalized_packet(**values)


def make_udp_attempt(**overrides: Any) -> NormalizedPacket:
    """Build a UDP datagram sent from an ephemeral port (a connection attempt)."""
    values: dict[str, Any] = {
        "protocol": "UDP",
        "packet_type": PacketType.UDP,
        "source_port": 4096,
        "destination_port": 53,
    }
    values.update(overrides)
    return make_normalized_packet(**values)


def make_icmp_packet(**overrides: Any) -> NormalizedPacket:
    """Build an ICMP packet, which carries no ports at all (M10.10)."""
    values: dict[str, Any] = {
        "protocol": "ICMP",
        "packet_type": PacketType.ICMP,
        "source_port": None,
        "destination_port": None,
    }
    values.update(overrides)
    return make_normalized_packet(**values)


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------


def make_context(
    *,
    packet: NormalizedPacket | None = None,
    timestamp: float | None = None,
    packets_per_second: float | None = None,
    bytes_per_second: float | None = None,
    rate_window_seconds: float | None = None,
    total_packets: int | None = None,
    total_bytes: int | None = None,
    device_resolver: Callable[[str], str | None] | None = None,
) -> DetectionContext:
    """Build a detection context, defaulting its time to the packet's own (M10.4)."""
    if timestamp is None:
        timestamp = (
            packet.timestamp if packet is not None else DETECTION_BASE_TIME
        )
    return DetectionContext(
        timestamp=timestamp,
        packet=packet,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        rate_window_seconds=rate_window_seconds,
        total_packets=total_packets,
        total_bytes=total_bytes,
        device_resolver=device_resolver,
    )


def make_device_resolver(mapping: dict[str, str]) -> Callable[[str], str | None]:
    """Return an address -> device id resolver backed by a fixed mapping (M10.4)."""
    return mapping.get


# ---------------------------------------------------------------------------
# Driving a rule
# ---------------------------------------------------------------------------


def feed(
    rule: DetectionRule,
    packets: Iterable[NormalizedPacket],
    *,
    packets_per_second: float | None = None,
    bytes_per_second: float | None = None,
    rate_window_seconds: float | None = None,
) -> list[DetectionFinding]:
    """Evaluate ``rule`` once per packet and return every finding it raised."""
    findings: list[DetectionFinding] = []
    for packet in packets:
        finding = rule.evaluate(
            make_context(
                packet=packet,
                packets_per_second=packets_per_second,
                bytes_per_second=bytes_per_second,
                rate_window_seconds=rate_window_seconds,
            )
        )
        if finding is not None:
            findings.append(finding)
    return findings


def syn_packets(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    destination_ip: str = DEFAULT_DESTINATION_IP,
    destination_ports: Iterable[int] | None = None,
    count: int | None = None,
    destination_port: int = 443,
    start_time: float = DETECTION_BASE_TIME,
    step: float = 0.0,
) -> list[NormalizedPacket]:
    """Build a stream of SYNs, either across ports or repeated to one port.

    Exactly one of ``destination_ports`` or ``count`` must be supplied: the
    first builds a sweep of distinct ports, the second a repeat at
    ``destination_port``.
    """
    if (destination_ports is None) == (count is None):
        raise ValueError("supply exactly one of destination_ports or count")

    if count is not None:
        ports: list[int] = [destination_port] * count
    else:
        ports = list(destination_ports or ())

    return [
        make_syn_packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=port,
            timestamp=start_time + index * step,
        )
        for index, port in enumerate(ports)
    ]


def repeated_icmp(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    destination_ip: str = DEFAULT_DESTINATION_IP,
    count: int,
    start_time: float = DETECTION_BASE_TIME,
    step: float = 0.0,
) -> list[NormalizedPacket]:
    """Build ``count`` ICMP packets aimed at one destination (M10.10)."""
    return [
        make_icmp_packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            timestamp=start_time + index * step,
        )
        for index in range(count)
    ]


def repeated_udp_attempts(
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    destination_ips: Iterable[str],
    start_time: float = DETECTION_BASE_TIME,
    step: float = 0.0,
    destination_port: int = 53,
) -> list[NormalizedPacket]:
    """Build one UDP attempt per destination address in ``destination_ips``."""
    return [
        make_udp_attempt(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            timestamp=start_time + index * step,
        )
        for index, destination_ip in enumerate(destination_ips)
    ]


# ---------------------------------------------------------------------------
# Fake rules
# ---------------------------------------------------------------------------


class FixedRule(DetectionRule):
    """A rule that fires or stays silent on demand (M10.6/M10.23)."""

    rule_id = "fixed"
    rule_name = "Fixed Rule"
    description = "Test rule returning a preset finding"

    def __init__(
        self,
        *,
        rule_id: str = "fixed",
        fires: bool = True,
        enabled: bool = True,
        source_ip: str | None = DEFAULT_SOURCE_IP,
        destination_ip: str | None = DEFAULT_DESTINATION_IP,
    ) -> None:
        super().__init__(enabled=enabled, window_seconds=10.0)
        self.rule_id = rule_id  # type: ignore[misc] - deliberate per-instance id
        self.fires = fires
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.evaluations = 0

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Count the evaluation and fire when configured to."""
        self.evaluations += 1
        if not self.fires:
            return None
        return DetectionFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            timestamp=context.timestamp,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            protocol="TCP",
            description="Test finding",
        )


class RecordingRule(DetectionRule):
    """A rule that records every context it is shown and never fires (M10.4)."""

    rule_id = "recording"
    rule_name = "Recording Rule"
    description = "Test rule recording the contexts it is evaluated with"

    def __init__(self, *, rule_id: str = "recording") -> None:
        super().__init__()
        self.rule_id = rule_id  # type: ignore[misc] - deliberate per-instance id
        self.contexts: list[DetectionContext] = []

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Record the context and report nothing."""
        self.contexts.append(context)
        return None


class RaisingRule(DetectionRule):
    """A rule that always fails, so failure isolation can be tested (M10.17)."""

    rule_id = "raising"
    rule_name = "Raising Rule"
    description = "Test rule that always raises"

    def __init__(self, *, rule_id: str = "raising") -> None:
        super().__init__()
        self.rule_id = rule_id  # type: ignore[misc] - deliberate per-instance id
        self.evaluations = 0

    def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
        """Count the evaluation, then fail."""
        self.evaluations += 1
        raise RuntimeError("simulated detector failure")


# ---------------------------------------------------------------------------
# Fake traffic-rate source
# ---------------------------------------------------------------------------


class FakeRatesSource:
    """A configurable M6 rate source for engine and detector tests (M10.12)."""

    def __init__(
        self,
        packets_per_second: float = 0.0,
        bytes_per_second: float = 0.0,
        *,
        fail: bool = False,
    ) -> None:
        self.packets_per_second = packets_per_second
        self.bytes_per_second = bytes_per_second
        self.fail = fail
        self.calls: list[str] = []

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return the configured rates, or fail when told to (M10.12)."""
        self.calls.append(window)
        if self.fail:
            raise RuntimeError("simulated statistics outage")
        return self.packets_per_second, self.bytes_per_second
