"""M10 verification script — see the rule-based detectors produce findings (M10.30).

Two modes:

  sample  (default)  Push synthetic packets through a full PacketPipeline
                     (PacketProcessor -> Statistics -> Devices -> DetectionEngine)
                     covering all five M10 detectors, then print every finding
                     with its evidence. No admin rights or Npcap needed.
  live               Capture real traffic through CaptureManager ->
                     PacketPipeline -> DetectionEngine for a few seconds.
                     Requires Npcap and (Windows) admin.

The detectors are configured with LOW thresholds so a handful of synthetic
packets demonstrates each one. That is a lab configuration for verification, not
the shipped default; the defaults live in ``app/config/settings.py`` (M10.7).

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m10.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m10.py live --interface "Wi-Fi" --seconds 5
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from app.config.settings import Settings  # noqa: E402
from app.detection import (  # noqa: E402
    DetectionEngine,
    DetectionFinding,
    build_default_rules,
)
from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.services.packet_pipeline import PacketPipeline  # noqa: E402
from app.statistics.manager import TrafficStatisticsManager  # noqa: E402

_BANNER_WIDTH = 66

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"

# Port-scan source sweeping a public host across distinct ports.
SCAN_SOURCE = "192.168.1.10"
SCAN_DESTINATION = "8.8.8.8"
SCAN_PORTS = [20, 21, 22, 23, 24, 25]

# SYN-flood source hammering one destination on one port.
FLOOD_SOURCE = "10.0.0.5"
FLOOD_DESTINATION = "192.168.0.99"
FLOOD_PORT = 80
FLOOD_SYNS = 25

# ICMP-flood source pinging one destination repeatedly.
ICMP_SOURCE = "10.0.0.6"
ICMP_DESTINATION = "192.168.0.100"
ICMP_PACKETS = 8

# Internal-scan source sweeping the local subnet.
SWEEP_SOURCE = "192.168.1.50"
SWEEP_DESTINATIONS = [
    "192.168.1.20",
    "192.168.1.21",
    "192.168.1.22",
    "192.168.1.23",
    "192.168.1.24",
    "192.168.1.25",
]

# Fixed reference time so the printed timestamps are stable within a run.
_BASE_TIME = time.time()

# The five detectors M10 must demonstrate.
_EXPECTED_RULES = [
    "port_scan",
    "syn_flood",
    "icmp_flood",
    "internal_scan",
    "high_bandwidth",
]


class _FixedRatesSource:
    """A stand-in for M6 that always reports a high traffic rate (M10.12)."""

    def __init__(self, bytes_per_second: float, packets_per_second: float) -> None:
        self._bytes_per_second = bytes_per_second
        self._packets_per_second = packets_per_second

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return the fixed ``(packets_per_second, bytes_per_second)``."""
        return self._packets_per_second, self._bytes_per_second


def _sample_packets() -> list[tuple[str, object, float]]:
    """Return labelled packets covering all five M10 detectors."""
    packets: list[tuple[str, object, float]] = []

    for index, port in enumerate(SCAN_PORTS):
        packets.append(
            (
                f"port scan     {SCAN_SOURCE}:52000 -> {SCAN_DESTINATION}:{port}",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=SCAN_SOURCE, dst=SCAN_DESTINATION)
                / TCP(sport=52000, dport=port, flags="S"),
                _BASE_TIME + 2.00 + index * 0.01,
            )
        )

    for index in range(FLOOD_SYNS):
        packets.append(
            (
                f"syn flood     {FLOOD_SOURCE}:40000 -> "
                f"{FLOOD_DESTINATION}:{FLOOD_PORT}",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=FLOOD_SOURCE, dst=FLOOD_DESTINATION)
                / TCP(sport=40000, dport=FLOOD_PORT, flags="S"),
                _BASE_TIME + 10.00 + index * 0.005,
            )
        )

    for index in range(ICMP_PACKETS):
        packets.append(
            (
                f"icmp flood    {ICMP_SOURCE} -> {ICMP_DESTINATION}",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=ICMP_SOURCE, dst=ICMP_DESTINATION)
                / ICMP(),
                _BASE_TIME + 20.00 + index * 0.005,
            )
        )

    for index, destination in enumerate(SWEEP_DESTINATIONS):
        packets.append(
            (
                f"internal scan {SWEEP_SOURCE}:53000 -> {destination}:445",
                Ether(src=MAC_A, dst=MAC_B)
                / IP(src=SWEEP_SOURCE, dst=destination)
                / UDP(sport=53000, dport=445),
                _BASE_TIME + 30.00 + index * 0.01,
            )
        )

    return packets


def _build_engine(devices: DeviceDiscoveryManager) -> DetectionEngine:
    """Build a detection engine with lab thresholds for every detector (M10.7)."""

    def resolve_device(ip_address: str) -> str | None:
        """Return the M8 device id owning ``ip_address``, or ``None`` (M10.4)."""
        device = devices.registry.get_by_ip(ip_address)
        return device.device_id if device is not None else None

    lab_settings = Settings(
        port_scan_unique_port_threshold=5,
        syn_flood_time_window_seconds=1.0,
        syn_flood_rate_threshold=20.0,
        icmp_flood_time_window_seconds=1.0,
        icmp_flood_rate_threshold=5.0,
        internal_scan_unique_destination_threshold=5,
        high_bandwidth_bytes_per_second_threshold=1_000_000.0,
    )
    return DetectionEngine(
        build_default_rules(lab_settings),
        rates_source=_FixedRatesSource(5_000_000.0, 1_000.0),
        device_resolver=resolve_device,
    )


def _describe(finding: DetectionFinding) -> None:
    """Print one finding with the evidence that produced it (M10.14)."""
    endpoints = f"{finding.source_ip or '*'} -> {finding.destination_ip or '*'}"
    print(f"  [{finding.rule_id:<15}] {endpoints}")
    print(f"      {finding.description}")
    print(
        f"      confidence={finding.confidence:.2f} "
        f"protocol={finding.protocol or '*'}"
    )
    source_device = finding.source_device_id or "(unknown)"
    destination_device = finding.destination_device_id or "(unknown)"
    print(f"      devices src={source_device} dst={destination_device}")
    for key, value in sorted(finding.evidence.items()):
        print(f"      evidence {key} = {value}")


def _check_expectations(engine: DetectionEngine, pipeline: PacketPipeline) -> list[str]:
    """Return the M10 expectations that were not met."""
    failures: list[str] = []

    for rule_id in _EXPECTED_RULES:
        matched = engine.get_findings(rule_id=rule_id)
        if not matched:
            failures.append(f"no finding was produced by rule '{rule_id}'")
            continue
        # Every finding must carry evidence explaining why it fired (M10.14).
        if not matched[0].evidence:
            failures.append(f"rule '{rule_id}' produced a finding with no evidence")

    # Confidence must be a bounded observation value, not a risk score (M10.15).
    for finding in engine.get_findings():
        if not 0.0 <= finding.confidence <= 1.0:
            failures.append(
                f"rule '{finding.rule_id}' confidence {finding.confidence} "
                "is outside [0.0, 1.0]"
            )

    diagnostics = engine.get_diagnostics()
    if diagnostics.errors != 0:
        failures.append(f"the engine isolated {diagnostics.errors} rule error(s)")
    if pipeline.get_detection_error_count() != 0:
        failures.append(
            f"the pipeline counted {pipeline.get_detection_error_count()} "
            "detection error(s)"
        )
    if pipeline.get_processed_count() == 0:
        failures.append("no packet was processed by the pipeline")

    if not failures:
        print("\n  OK: all five detectors fired with evidence, no rule failures")
    return failures


def run_sample_mode() -> int:
    """Feed synthetic packets through the whole pipeline and verify the findings."""
    devices = DeviceDiscoveryManager()
    engine = _build_engine(devices)
    pipeline = PacketPipeline(
        statistics=TrafficStatisticsManager(),
        devices=devices,
        connections=None,
        persistence=None,
        detection=engine,
    )

    print("=" * _BANNER_WIDTH)
    print("M10 SAMPLE MODE — synthetic packets, no privileges required")
    print("=" * _BANNER_WIDTH)

    for label, packet, captured_at in _sample_packets():
        try:
            pipeline.process(packet, captured_at=captured_at)
        except Exception as exc:  # noqa: BLE001 - surface any processing failure
            print(f"\n[{label}] PROCESSING FAILED: {exc}")

    findings = engine.get_findings()
    print(f"\ndevices discovered: {devices.get_device_count()}")
    print(f"packets processed : {pipeline.get_processed_count()}")
    print(f"\n--- Findings ({len(findings)}) ---")
    if not findings:
        print("  (none)")
    for finding in findings:
        _describe(finding)

    diagnostics = engine.get_diagnostics()
    print("\n--- Detection diagnostics ---")
    print(f"  evaluations       : {diagnostics.evaluations:,}")
    print(f"  findings          : {diagnostics.findings:,}")
    print(f"  errors            : {diagnostics.errors:,}")
    print(f"  registered rules  : {diagnostics.registered_rules:,}")
    print(f"  pipeline det errs : {pipeline.get_detection_error_count():,}")

    failures = _check_expectations(engine, pipeline)

    print("\n" + "=" * _BANNER_WIDTH)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("Sample mode finished with failures.")
        return 1
    print("Sample mode complete — all checks passed.")
    return 0


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic and print the findings the detectors raised."""
    from app.services.capture_manager import CaptureManager
    from app.services.capture_state import CaptureError
    from app.services.interface_manager import get_interface_manager

    interface_manager = get_interface_manager()
    try:
        interface_manager.select_interface(interface)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not select interface '{interface}': {exc}")
        return 1

    devices = DeviceDiscoveryManager()
    engine = _build_engine(devices)
    pipeline = PacketPipeline(
        statistics=TrafficStatisticsManager(),
        devices=devices,
        connections=None,
        persistence=None,
        detection=engine,
    )
    manager = CaptureManager(interface_manager=interface_manager, pipeline=pipeline)
    try:
        manager.stop()
    except Exception:  # noqa: BLE001 - no session to stop
        pass

    print("=" * _BANNER_WIDTH)
    print(f"M10 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
    print("=" * _BANNER_WIDTH)
    print("Generate only authorized local traffic (browse, ping a host you own).")

    try:
        manager.start()
    except CaptureError as exc:
        print(f"START FAILED: {exc.code} - {exc.message}")
        return 1

    time.sleep(seconds)
    processed = manager.get_processed_packet_count()
    detection_errors = manager.get_detection_error_count()
    manager.stop()

    findings = engine.get_findings()
    print("\n--- Capture result ---")
    print(f"  normalized ok      : {processed}")
    print(f"  detection errors   : {detection_errors}")
    print(f"  findings raised    : {len(findings)}")

    print(f"\n--- Findings ({len(findings)}) ---")
    if not findings:
        print("  (none — no detector's configured condition was met)")
    for finding in findings:
        _describe(finding)

    if detection_errors:
        print("\nDetection reported errors; see the log above.")
        return 1
    print("\nLive mode complete.")
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify M10 rule-based detection findings."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="sample",
        choices=("sample", "live"),
        help="sample = synthetic packets (default), live = real capture",
    )
    parser.add_argument("--interface", default="Wi-Fi", help="Interface for live mode")
    parser.add_argument(
        "--seconds", type=float, default=5.0, help="Live capture duration"
    )
    args = parser.parse_args()

    if args.mode == "live":
        return run_live_mode(args.interface, args.seconds)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
