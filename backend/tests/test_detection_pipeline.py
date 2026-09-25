"""Integration tests: CaptureManager -> PacketProcessor -> M6/M8/M9/M10 (M10.29).

These tests drive real Scapy packets through the same callback path production
uses (fake sniffer -> PacketPipeline -> PacketProcessor -> statistics -> device
discovery -> connection tracking -> DetectionEngine) and assert that a
configured detection condition is what produces a finding -- and that nothing
produces one when the condition is not met.

The detectors themselves are covered behaviourally in
``test_detection_<rule>.py``; here the point is the *wiring*. Each test builds a
small engine around the single detector it is exercising, with thresholds low
enough that a handful of packets satisfies the rule, so the integration test
stays fast and still exercises the real engine, the real pipeline order and the
real finding history.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from app.connections.manager import ConnectionTracker
from app.detection.engine import DetectionEngine
from app.detection.finding import DetectionFinding
from app.detection.rules.high_bandwidth import HighBandwidthRule
from app.detection.rules.icmp_flood import IcmpFloodRule
from app.detection.rules.internal_scan import InternalScanRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.syn_flood import SynFloodRule
from app.devices.manager import DeviceDiscoveryManager
from app.processing.processor import PacketProcessor
from app.schemas.packet import NormalizedPacket
from app.services.capture_manager import CaptureManager
from app.services.packet_pipeline import PacketPipeline
from app.statistics.manager import TrafficStatisticsManager
from tests.detection_fakes import FakeRatesSource, RaisingRule, RecordingRule
from tests.fakes import (
    FakeCaptureSniffer,
    make_interface_manager,
    make_sniffer_factory,
)

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"
DEVICE_A = f"mac:{MAC_A}"
SOURCE_IP = "192.168.1.10"
DESTINATION_IP = "8.8.8.8"

# Thresholds chosen so a handful of packets satisfies each rule. Each rule fires
# exactly when its measurement reaches the threshold, so the evidence quotes
# exactly the threshold value at the moment of firing.
PORT_SCAN_PORTS_THRESHOLD = 5
INTERNAL_SCAN_DESTINATIONS_THRESHOLD = 5
FLOOD_RATE_THRESHOLD = 10.0
FLOOD_WINDOW_SECONDS = 1.0
BANDWIDTH_THRESHOLD = 1_000_000.0
BANDWIDTH_RATE = 5_000_000.0


# ---------------------------------------------------------------------------
# Traffic builders
# ---------------------------------------------------------------------------


def _syn(source_ip: str, destination_ip: str, destination_port: int) -> Any:
    """Build one TCP SYN from ``source_ip`` to ``destination_port``."""
    return (
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=source_ip, dst=destination_ip)
        / TCP(sport=52000, dport=destination_port, flags="S")
    )


def _udp(source_ip: str, destination_ip: str, destination_port: int = 53) -> Any:
    """Build one UDP datagram sent from an ephemeral source port."""
    return (
        Ether(src=MAC_A, dst=MAC_B)
        / IP(src=source_ip, dst=destination_ip)
        / UDP(sport=53000, dport=destination_port)
    )


def _icmp(source_ip: str, destination_ip: str) -> Any:
    """Build one ICMP echo packet."""
    return (
        Ether(src=MAC_A, dst=MAC_B) / IP(src=source_ip, dst=destination_ip) / ICMP()
    )


def _scan_traffic(count: int, *, first_port: int = 4000) -> list[Any]:
    """Return ``count`` SYNs from one source across distinct destination ports."""
    return [
        _syn(SOURCE_IP, DESTINATION_IP, first_port + index)
        for index in range(count)
    ]


def _internal_sweep(count: int) -> list[Any]:
    """Return ``count`` connection attempts to distinct private destinations."""
    return [_udp(SOURCE_IP, f"192.168.1.{20 + index}") for index in range(count)]


# Ten genuinely public addresses, so the internal scan detector cannot count
# them. Documentation ranges such as 203.0.113.0/24 are deliberately avoided:
# ``ipaddress`` classifies those as non-global, exactly like a private range.
PUBLIC_DESTINATIONS: tuple[str, ...] = (
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
    "64.233.160.1",
    "151.101.1.1",
    "13.107.42.12",
    "52.94.236.248",
    "104.16.132.229",
)


def _external_sweep(count: int) -> list[Any]:
    """Return ``count`` connection attempts to distinct *public* destinations."""
    return [_udp(SOURCE_IP, address) for address in PUBLIC_DESTINATIONS[:count]]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _engine(
    rules: list[Any],
    *,
    rates_source: Any | None = None,
    device_resolver: Callable[[str], str | None] | None = None,
) -> DetectionEngine:
    """Build a detection engine around ``rules`` for a pipeline test."""
    return DetectionEngine(
        rules,
        rates_source=rates_source,
        device_resolver=device_resolver,
    )


def _device_resolver(devices: DeviceDiscoveryManager) -> Callable[[str], str | None]:
    """Return an address -> M8 device id resolver over a device registry."""

    def resolve(ip_address: str) -> str | None:
        device = devices.registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    return resolve


def _make_manager(
    registry: list[FakeCaptureSniffer],
    *,
    engine: DetectionEngine | None,
    devices: DeviceDiscoveryManager | None = None,
    statistics: TrafficStatisticsManager | None = None,
    connections: ConnectionTracker | None = None,
) -> CaptureManager:
    """Return a CaptureManager wired to the real pipeline with detection."""
    interface_manager = make_interface_manager()
    interface_manager.select_interface("Wi-Fi")
    return CaptureManager(
        interface_manager=interface_manager,
        sniffer_factory=make_sniffer_factory(registry=registry),
        pipeline=PacketPipeline(
            processor=PacketProcessor(),
            statistics=statistics or TrafficStatisticsManager(),
            devices=devices or DeviceDiscoveryManager(),
            connections=connections,
            detection=engine,
        ),
    )


def _run(
    packets: list[Any],
    *,
    engine: DetectionEngine | None,
    devices: DeviceDiscoveryManager | None = None,
    statistics: TrafficStatisticsManager | None = None,
    connections: ConnectionTracker | None = None,
) -> CaptureManager:
    """Start capture, push ``packets`` through the pipeline, return the manager."""
    registry: list[FakeCaptureSniffer] = []
    manager = _make_manager(
        registry,
        engine=engine,
        devices=devices,
        statistics=statistics,
        connections=connections,
    )
    manager.start()
    for packet in packets:
        registry[0].emit_packet(packet)
    return manager


def _findings(engine: DetectionEngine, **filters: Any) -> list[DetectionFinding]:
    """Return the engine's retained findings matching ``filters``."""
    return engine.get_findings(**filters)
# ---------------------------------------------------------------------------
# The pipeline feeds the engine (M10.21)
# ---------------------------------------------------------------------------


def test_pipeline_evaluates_detection_for_every_normalized_packet() -> None:
    """Detection runs once per normalized packet, after M6/M8 (M10.21)."""
    recorder = RecordingRule()
    engine = _engine([recorder])
    packets = _scan_traffic(4)

    manager = _run(packets, engine=engine)

    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_detection_error_count() == 0
    assert len(recorder.contexts) == len(packets)
    assert engine.get_diagnostics().evaluations == len(packets)


def test_pipeline_context_carries_the_normalized_packet() -> None:
    """Each context sees the packet the pipeline just normalized (M10.4)."""
    recorder = RecordingRule()
    engine = _engine([recorder])

    _run([_syn(SOURCE_IP, DESTINATION_IP, 443)], engine=engine)

    context = recorder.contexts[0]
    assert context.packet is not None
    assert context.source_ip == SOURCE_IP
    assert context.destination_ip == DESTINATION_IP
    assert context.destination_port == 443
    assert context.timestamp > 0


def test_pipeline_keeps_every_consumer_in_step_with_detection() -> None:
    """Statistics, devices, connections and detection all see the same traffic."""
    engine = _engine([PortScanRule(unique_port_threshold=1000, window_seconds=60.0)])
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    connections = ConnectionTracker(
        device_registry=devices.registry, autostart_cleanup=False
    )
    packets = _scan_traffic(3)

    manager = _run(
        packets,
        engine=engine,
        devices=devices,
        statistics=statistics,
        connections=connections,
    )

    assert manager.get_statistics_error_count() == 0
    assert manager.get_device_error_count() == 0
    assert manager.get_connection_error_count() == 0
    assert manager.get_detection_error_count() == 0
    assert statistics.get_statistics().total_packets == len(packets)
    assert devices.get_device_count() == 2
    assert connections.get_active_count() == 3


def test_a_manager_without_detection_still_processes_packets() -> None:
    """Detection is optional wiring: capture works when no engine is supplied."""
    packets = _scan_traffic(3)

    manager = _run(packets, engine=None)

    assert manager.is_running() is True
    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_pipeline().detection is None


# ---------------------------------------------------------------------------
# Port scan through the pipeline (M10.8)
# ---------------------------------------------------------------------------


def port_scan_rule() -> PortScanRule:
    """Return a port scan detector with the test's low threshold."""
    return PortScanRule(
        unique_port_threshold=PORT_SCAN_PORTS_THRESHOLD, window_seconds=60.0
    )


def test_pipeline_reports_a_port_scan_only_above_the_threshold() -> None:
    """A sweep of distinct ports produces a finding; a short one does not (M10.8)."""
    below = _engine([port_scan_rule()])
    _run(_scan_traffic(PORT_SCAN_PORTS_THRESHOLD - 1), engine=below)

    above = _engine([port_scan_rule()])
    _run(_scan_traffic(PORT_SCAN_PORTS_THRESHOLD + 2), engine=above)

    assert _findings(below) == []
    findings = _findings(above)
    assert len(findings) == 1
    assert findings[0].rule_id == "port_scan"
    assert findings[0].source_ip == SOURCE_IP
    assert "Possible" in findings[0].description


def test_pipeline_port_scan_evidence_matches_the_observed_traffic() -> None:
    """The finding's evidence quotes the packets actually sent (M10.14)."""
    emitted = PORT_SCAN_PORTS_THRESHOLD + 3
    engine = _engine([port_scan_rule()])

    _run(_scan_traffic(emitted), engine=engine)

    finding = _findings(engine)[0]
    assert finding.evidence["unique_destination_ports"] == PORT_SCAN_PORTS_THRESHOLD
    assert finding.evidence["unique_port_threshold"] == PORT_SCAN_PORTS_THRESHOLD
    assert finding.evidence["connection_attempts"] == PORT_SCAN_PORTS_THRESHOLD
    assert finding.evidence["observation_window_seconds"] == 60.0


def test_pipeline_repeated_traffic_to_one_port_is_not_a_port_scan() -> None:
    """Ordinary repeated connections to one service never trip the detector."""
    engine = _engine([port_scan_rule()])

    _run([_syn(SOURCE_IP, DESTINATION_IP, 443) for _ in range(20)], engine=engine)

    assert _findings(engine) == []


# ---------------------------------------------------------------------------
# SYN flood through the pipeline (M10.9)
# ---------------------------------------------------------------------------


def test_pipeline_reports_a_syn_flood_against_the_destination() -> None:
    """A high SYN rate at one destination is reported at that destination (M10.9)."""
    engine = _engine(
        [
            SynFloodRule(
                window_seconds=FLOOD_WINDOW_SECONDS,
                rate_threshold=FLOOD_RATE_THRESHOLD,
            )
        ]
    )

    _run([_syn(SOURCE_IP, DESTINATION_IP, 443) for _ in range(12)], engine=engine)

    findings = _findings(engine)
    assert len(findings) == 1
    assert findings[0].rule_id == "syn_flood"
    assert findings[0].destination_ip == DESTINATION_IP
    assert findings[0].source_ip == SOURCE_IP
    # The rule fires the moment the rate reaches the threshold, so the window
    # holds exactly ``threshold * window`` packets at that instant.
    assert findings[0].evidence["syn_packets"] == FLOOD_RATE_THRESHOLD


def test_pipeline_a_lone_syn_is_not_a_flood() -> None:
    """A single SYN never constitutes a flood, whatever the threshold (M10.9)."""
    engine = _engine(
        [SynFloodRule(window_seconds=FLOOD_WINDOW_SECONDS, rate_threshold=0.5)]
    )

    _run([_syn(SOURCE_IP, DESTINATION_IP, 443)], engine=engine)

    assert _findings(engine) == []


# ---------------------------------------------------------------------------
# ICMP flood through the pipeline (M10.10)
# ---------------------------------------------------------------------------


def test_pipeline_reports_an_icmp_flood_against_the_destination() -> None:
    """A high ICMP rate at one destination is reported there (M10.10)."""
    engine = _engine(
        [
            IcmpFloodRule(
                window_seconds=FLOOD_WINDOW_SECONDS,
                rate_threshold=FLOOD_RATE_THRESHOLD,
            )
        ]
    )

    _run([_icmp(SOURCE_IP, DESTINATION_IP) for _ in range(12)], engine=engine)

    findings = _findings(engine)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_flood"
    assert findings[0].destination_ip == DESTINATION_IP
    assert findings[0].protocol == "ICMP"


def test_pipeline_ordinary_ping_traffic_is_not_an_icmp_flood() -> None:
    """A couple of echo packets stay below any sane rate threshold (M10.10)."""
    engine = _engine(
        [IcmpFloodRule(window_seconds=FLOOD_WINDOW_SECONDS, rate_threshold=100.0)]
    )

    _run([_icmp(SOURCE_IP, DESTINATION_IP) for _ in range(2)], engine=engine)

    assert _findings(engine) == []


# ---------------------------------------------------------------------------
# Internal network scan through the pipeline (M10.11)
# ---------------------------------------------------------------------------


def internal_scan_rule() -> InternalScanRule:
    """Return an internal scan detector with the test's low threshold."""
    return InternalScanRule(
        unique_destination_threshold=INTERNAL_SCAN_DESTINATIONS_THRESHOLD,
        window_seconds=60.0,
    )


def test_pipeline_reports_an_internal_sweep_above_the_threshold() -> None:
    """Contacting many internal hosts is reported; a few are not (M10.11)."""
    below = _engine([internal_scan_rule()])
    _run(_internal_sweep(INTERNAL_SCAN_DESTINATIONS_THRESHOLD - 1), engine=below)

    above = _engine([internal_scan_rule()])
    _run(_internal_sweep(INTERNAL_SCAN_DESTINATIONS_THRESHOLD + 2), engine=above)

    assert _findings(below) == []
    findings = _findings(above)
    assert len(findings) == 1
    assert findings[0].rule_id == "internal_scan"
    assert findings[0].source_ip == SOURCE_IP
    assert (
        findings[0].evidence["unique_internal_destinations"]
        == INTERNAL_SCAN_DESTINATIONS_THRESHOLD
    )


def test_pipeline_external_destinations_are_not_an_internal_sweep() -> None:
    """Many public destinations are not an internal network scan (M10.11)."""
    engine = _engine([internal_scan_rule()])

    _run(_external_sweep(len(PUBLIC_DESTINATIONS)), engine=engine)

    assert _findings(engine) == []


# ---------------------------------------------------------------------------
# High bandwidth through the pipeline (M10.12)
# ---------------------------------------------------------------------------


def bandwidth_rule() -> HighBandwidthRule:
    """Return a high bandwidth detector with the test's low threshold."""
    return HighBandwidthRule(
        window_seconds=FLOOD_WINDOW_SECONDS,
        bytes_per_second_threshold=BANDWIDTH_THRESHOLD,
    )


def test_pipeline_reports_a_traffic_spike_from_the_m6_rate() -> None:
    """The spike detector reads the M6 rate through the pipeline (M10.12)."""
    rates = FakeRatesSource(
        packets_per_second=1000.0, bytes_per_second=BANDWIDTH_RATE
    )
    engine = _engine([bandwidth_rule()], rates_source=rates)

    _run(_scan_traffic(3), engine=engine)

    findings = _findings(engine)
    assert len(findings) == 1
    assert findings[0].rule_id == "high_bandwidth"
    assert findings[0].source_ip is None
    assert findings[0].evidence["bytes_per_second"] == BANDWIDTH_RATE
    assert rates.calls  # the engine actually consulted the M6 rate source


def test_pipeline_stays_silent_when_the_rate_source_fails() -> None:
    """A statistics outage yields no spike finding rather than a guess (M10.12)."""
    rates = FakeRatesSource(fail=True)
    engine = _engine([bandwidth_rule()], rates_source=rates)

    manager = _run(_scan_traffic(3), engine=engine)

    assert _findings(engine) == []
    assert manager.get_detection_error_count() == 0


# ---------------------------------------------------------------------------
# Device association through the pipeline (M10.4)
# ---------------------------------------------------------------------------


def test_pipeline_associates_a_finding_with_the_source_device() -> None:
    """A finding is anchored to the M8 device that owns the source (M10.4)."""
    devices = DeviceDiscoveryManager()
    engine = _engine(
        [port_scan_rule()], device_resolver=_device_resolver(devices)
    )

    _run(
        _scan_traffic(PORT_SCAN_PORTS_THRESHOLD + 1),
        engine=engine,
        devices=devices,
    )

    finding = _findings(engine)[0]
    assert finding.source_device_id == DEVICE_A


# ---------------------------------------------------------------------------
# Failure isolation (M10.17/M10.21)
# ---------------------------------------------------------------------------


class _RaisingDetectionEngine(DetectionEngine):
    """Engine whose ``process_packet`` always fails, for isolation tests."""

    def process_packet(self, packet: NormalizedPacket) -> list[DetectionFinding]:
        raise RuntimeError("simulated detection failure")


def test_detection_failure_does_not_stop_capture_or_other_consumers() -> None:
    """A failing detection stage never terminates capture or M6/M8/M9 (M10.21)."""
    statistics = TrafficStatisticsManager()
    devices = DeviceDiscoveryManager()
    connections = ConnectionTracker(
        device_registry=devices.registry, autostart_cleanup=False
    )
    packets = _scan_traffic(4)

    manager = _run(
        packets,
        engine=_RaisingDetectionEngine([]),
        devices=devices,
        statistics=statistics,
        connections=connections,
    )

    assert manager.is_running() is True
    assert manager.get_processed_packet_count() == len(packets)
    assert manager.get_detection_error_count() == len(packets)
    assert statistics.get_statistics().total_packets == len(packets)
    assert devices.get_device_count() == 2
    # One conversation per distinct destination port, all still tracked.
    assert connections.get_active_count() == len(packets)


def test_a_failing_rule_does_not_stop_the_other_rules_through_the_pipeline() -> None:
    """The engine isolates one bad detector while the rest still fire (M10.17)."""
    engine = _engine([RaisingRule(rule_id="raising"), port_scan_rule()])
    emitted = PORT_SCAN_PORTS_THRESHOLD + 1

    manager = _run(_scan_traffic(emitted), engine=engine)

    assert manager.get_detection_error_count() == 0  # the engine contained it
    assert engine.get_rule_counters()["raising"].errors == emitted
    assert [finding.rule_id for finding in _findings(engine)] == ["port_scan"]


def test_disabled_detection_produces_no_findings_and_no_errors() -> None:
    """Disabling the engine removes it from the hot path without failing (M10.21)."""
    engine = _engine([port_scan_rule()])
    engine.set_enabled(False)

    manager = _run(_scan_traffic(PORT_SCAN_PORTS_THRESHOLD + 2), engine=engine)

    assert _findings(engine) == []
    assert manager.get_detection_error_count() == 0
    assert engine.get_diagnostics().evaluations == 0
