"""M10 performance baseline — measure detection cost and its API (M10.31).

Measures the M10 detection layer in isolation, so a reader can see what adding
detection costs over a pipeline that already normalizes, aggregates, discovers
devices and tracks conversations:

  * packets evaluated per second with detection enabled,
  * detection overhead per packet (microseconds),
  * each detector's own per-packet rule execution time,
  * findings produced and bounded detector state size,
  * Python memory held by the engine and its rules (``tracemalloc``),
  * API response times for the read-only detection endpoints.

This is a local, single-machine baseline for the M10 detection code only. It is
NOT a production-capacity claim: it excludes real capture (Scapy/Npcap), the M5
normalization step, the M6/M8/M9 consumers, the M7 packet write, the network
stack, JSON serialization at the wire, and any database. Numbers will differ on
other hardware and workloads.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m10.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m10.py --packets 200000
"""

from __future__ import annotations

import argparse
import logging
import statistics as stats
import sys
import time
import tracemalloc
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.detection import (  # noqa: E402
    DetectionContext,
    DetectionEngine,
    DetectionFinding,
    DetectionRule,
    HighBandwidthRule,
    IcmpFloodRule,
    InternalScanRule,
    PortScanRule,
    SynFloodRule,
)
from app.schemas.packet import NormalizedPacket, PacketType  # noqa: E402

_BANNER_WIDTH = 66

# Two endpoints reused by every synthetic flow; identity comes from the ports.
_SOURCE_IP = "10.0.0.1"
_DESTINATION_IP = "10.0.0.2"
_PORT_BASE = 1024
_PORT_SPAN = 60_000
_PROTOCOLS = [(PacketType.TCP, "TCP"), (PacketType.UDP, "UDP")]

# Fixed past timestamp so window/rate state is stable across the run.
_PAST_TIMESTAMP = 1_000_000.0

# A steady traffic rate fed to the bandwidth detector (M10.12).
_BYTES_PER_SECOND = 2_000_000.0
_PACKETS_PER_SECOND = 5_000.0

# Thresholds high enough that the throughput run does not fire constantly: this
# measures evaluation cost, not finding-generation cost.
_BENCH_PORT_THRESHOLD = 1_000_000
_BENCH_RATE_THRESHOLD = 1_000_000.0
_BENCH_SCAN_THRESHOLD = 1_000_000


class _FixedRatesSource:
    """A stand-in for M6 returning a fixed rate (M10.12)."""

    def get_rates(self, window: str = "1s") -> tuple[float, float]:
        """Return the fixed ``(packets_per_second, bytes_per_second)``."""
        return _PACKETS_PER_SECOND, _BYTES_PER_SECOND


def _ports_for(flow: int) -> tuple[int, int]:
    """Return the unique (source, destination) port pair of a flow number."""
    source_port = _PORT_BASE + (flow % _PORT_SPAN)
    destination_port = _PORT_BASE + ((flow // _PORT_SPAN) % _PORT_SPAN)
    return source_port, destination_port


def _flow_packet(flow: int, timestamp: float) -> NormalizedPacket:
    """Build one packet belonging to flow number ``flow``."""
    packet_type, protocol = _PROTOCOLS[flow % len(_PROTOCOLS)]
    source_port, destination_port = _ports_for(flow)
    return NormalizedPacket(
        packet_id=flow + 1,
        timestamp=timestamp,
        length=128,
        source_ip=_SOURCE_IP,
        destination_ip=_DESTINATION_IP,
        protocol=protocol,
        packet_type=packet_type,
        source_port=source_port,
        destination_port=destination_port,
    )


def _build_batch(packets: int, flows: int, timestamp: float) -> list[NormalizedPacket]:
    """Return ``packets`` packets cycling through ``flows`` distinct flows."""
    return [_flow_packet(index % flows, timestamp) for index in range(packets)]


def _default_rules() -> list[DetectionRule]:
    """Build the five detectors with non-firing thresholds for the cost run."""
    return [
        PortScanRule(unique_port_threshold=_BENCH_PORT_THRESHOLD),
        SynFloodRule(rate_threshold=_BENCH_RATE_THRESHOLD),
        IcmpFloodRule(rate_threshold=_BENCH_RATE_THRESHOLD),
        InternalScanRule(unique_destination_threshold=_BENCH_SCAN_THRESHOLD),
        HighBandwidthRule(bytes_per_second_threshold=1_000_000_000.0),
    ]


def benchmark_throughput(packets: int, flows: int) -> None:
    """Time detection over a batch and print the cost and overhead."""
    batch = _build_batch(packets, flows, time.time())

    # Disabled-engine pass: the context is still built, but no rule runs.
    disabled = DetectionEngine(_default_rules(), enabled=False)
    disabled_start = time.perf_counter()
    for packet in batch:
        disabled.process_packet(packet)
    disabled_elapsed = time.perf_counter() - disabled_start

    # Enabled pass: every rule is evaluated against the same batch.
    enabled = DetectionEngine(_default_rules(), rates_source=_FixedRatesSource())
    enabled_start = time.perf_counter()
    for packet in batch:
        enabled.process_packet(packet)
    enabled_elapsed = time.perf_counter() - enabled_start

    enabled_throughput = packets / enabled_elapsed if enabled_elapsed > 0 else 0.0
    per_packet_us = (enabled_elapsed / packets) * 1_000_000 if packets else 0.0
    disabled_per_packet_us = (
        (disabled_elapsed / packets) * 1_000_000 if packets else 0.0
    )
    overhead_us = per_packet_us - disabled_per_packet_us
    diagnostics = enabled.get_diagnostics()

    print("=" * _BANNER_WIDTH)
    print("M10 PERFORMANCE BASELINE — detection (M10.31)")
    print("=" * _BANNER_WIDTH)
    print(f"packets evaluated     : {packets:,}")
    print(f"distinct flows        : {flows:,}")
    print(f"registered rules      : {diagnostics.registered_rules}")
    print(f"wall time (enabled)   : {enabled_elapsed:.3f} s")
    print(f"throughput (enabled)  : {enabled_throughput:,.0f} packets/sec")
    print(f"per-packet (enabled)  : {per_packet_us:.3f} us")
    print(f"per-packet (disabled) : {disabled_per_packet_us:.3f} us")
    print(f"detection overhead    : {overhead_us:.3f} us/packet")
    print(f"evaluations           : {diagnostics.evaluations:,}")
    print(f"findings              : {diagnostics.findings:,}")
    print(f"errors                : {diagnostics.errors:,}")
    print(f"retained findings     : {diagnostics.retained_findings:,}")
    _benchmark_rule_times(batch)


def _benchmark_rule_times(batch: list[NormalizedPacket]) -> None:
    """Time each detector's own per-packet evaluation (M10.31)."""
    context = DetectionContext(
        timestamp=time.time(),
        bytes_per_second=_BYTES_PER_SECOND,
        packets_per_second=_PACKETS_PER_SECOND,
        rate_window_seconds=1.0,
    )
    rules: list[tuple[str, DetectionRule]] = [
        ("port_scan", PortScanRule(unique_port_threshold=_BENCH_PORT_THRESHOLD)),
        ("syn_flood", SynFloodRule(rate_threshold=_BENCH_RATE_THRESHOLD)),
        ("icmp_flood", IcmpFloodRule(rate_threshold=_BENCH_RATE_THRESHOLD)),
        ("internal_scan", InternalScanRule(unique_destination_threshold=_BENCH_SCAN_THRESHOLD)),
        ("high_bandwidth", HighBandwidthRule(bytes_per_second_threshold=1_000_000_000.0)),
    ]

    print("\n--- Per-detector rule execution ---")
    for name, rule in rules:
        start = time.perf_counter()
        for packet in batch:
            rule.evaluate(
                DetectionContext(
                    timestamp=context.timestamp,
                    packet=packet,
                    bytes_per_second=_BYTES_PER_SECOND,
                    packets_per_second=_PACKETS_PER_SECOND,
                    rate_window_seconds=1.0,
                )
            )
        elapsed = time.perf_counter() - start
        per_packet_us = (elapsed / len(batch)) * 1_000_000 if batch else 0.0
        print(
            f"  {name:<16} {elapsed:7.3f} s  "
            f"{per_packet_us:7.3f} us/packet  state={rule.state_size():,}"
        )


def benchmark_memory(packets: int, flows: int) -> None:
    """Measure Python memory held by the engine and its bounded rules (M10.19).

    ``tracemalloc`` adds substantial overhead, so this runs separately from the
    throughput measurement; only the memory figures should be read from it.
    """
    engine = DetectionEngine(_default_rules(), rates_source=_FixedRatesSource())
    batch = _build_batch(packets, flows, _PAST_TIMESTAMP)

    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    for packet in batch:
        engine.process_packet(packet)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    state_total = sum(rule.state_size() for rule in engine.get_rules())
    print("\n--- Memory (tracemalloc) ---")
    print(f"  heap before         : {before / 1024 / 1024:.2f} MiB")
    print(f"  heap after          : {current / 1024 / 1024:.2f} MiB")
    print(f"  peak heap           : {peak / 1024 / 1024:.2f} MiB")
    print(f"  rules               : {len(engine.get_rules())}")
    print(f"  tracked subjects    : {state_total:,}")
    print(
        "  note                : detector state and the finding history are both "
        "capped, so this footprint does not grow without bound"
    )


def benchmark_api(iterations: int, seeded_findings: int) -> None:
    """Time the read-only detection endpoints through the ASGI test client."""
    from fastapi.testclient import TestClient

    from app.config.settings import settings
    from app.detection import get_detection_engine
    from app.main import app

    engine = _seed_engine(seeded_findings)

    endpoints: list[tuple[str, dict[str, int] | None]] = [
        ("/api/v1/detections", {"limit": 100}),
        ("/api/v1/detections/rules", None),
    ]

    original_env = settings.app_env
    settings.app_env = "test"  # skip init_db() during startup
    app.dependency_overrides[get_detection_engine] = lambda: engine
    print("\n--- API response time (TestClient, in-process) ---")
    # Each request logs at INFO; over hundreds of iterations that buries the
    # measurements, so the noisy loggers are muted for the duration.
    muted = (
        "httpx",
        "app.main",
        "app.api.v1.detections",
        "app.detection.engine",
    )
    previous_levels = {name: logging.getLogger(name).level for name in muted}
    for name in muted:
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        with TestClient(app) as client:
            for endpoint, params in endpoints:
                samples: list[float] = []
                for _ in range(iterations):
                    start = time.perf_counter()
                    response = client.get(endpoint, params=params)
                    samples.append((time.perf_counter() - start) * 1000.0)
                    if response.status_code != 200:
                        raise RuntimeError(
                            f"{endpoint} returned HTTP {response.status_code}"
                        )
                label = endpoint if params is None else f"{endpoint}?limit=100"
                print(
                    f"  {label:<36} avg {stats.mean(samples):6.2f} ms  "
                    f"max {max(samples):6.2f} ms"
                )
    finally:
        for name, level in previous_levels.items():
            logging.getLogger(name).setLevel(level)
        app.dependency_overrides.pop(get_detection_engine, None)
        settings.app_env = original_env


def _seed_engine(count: int) -> DetectionEngine:
    """Return an engine seeded with ``count`` retained findings.

    A temporary scripted rule is registered, evaluated once per finding, then
    removed, so the engine's history is populated through its public API.
    """

    class _ScriptedRule(DetectionRule):
        """A rule returning preset findings, one per evaluation."""

        rule_id = "scripted"
        rule_name = "Scripted Rule"
        description = "Benchmark rule returning preset findings"

        def __init__(self, findings: list[DetectionFinding]) -> None:
            super().__init__(window_seconds=1.0)
            self._pending = list(findings)

        def evaluate(self, context: DetectionContext) -> DetectionFinding | None:
            """Return the next preset finding, or ``None`` once exhausted."""
            if not self._pending:
                return None
            return self._pending.pop(0)

    findings = [
        DetectionFinding(
            rule_id="port_scan",
            rule_name="Port Scan",
            timestamp=time.time() + index,
            source_ip=_SOURCE_IP,
            destination_ip=None,
            protocol="TCP",
            description="Possible port scan detected",
            evidence={"unique_destination_ports": 37, "unique_port_threshold": 20},
        )
        for index in range(count)
    ]
    rule = _ScriptedRule(findings)
    engine = DetectionEngine([rule])
    for _ in findings:
        engine.evaluate(DetectionContext(timestamp=time.time()))
    engine.unregister(rule.rule_id)
    return engine


def main() -> int:
    """Parse arguments and run the baseline measurements."""
    parser = argparse.ArgumentParser(
        description="Measure the M10 detection performance baseline."
    )
    parser.add_argument(
        "--packets", type=int, default=100_000, help="Packets to evaluate"
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=10_000,
        help="Distinct flows the packets cycle through",
    )
    parser.add_argument(
        "--memory-packets",
        type=int,
        default=20_000,
        help="Packets used for the tracemalloc phase (it is much slower)",
    )
    parser.add_argument(
        "--api-iterations", type=int, default=200, help="Requests timed per endpoint"
    )
    parser.add_argument(
        "--api-findings",
        type=int,
        default=1_000,
        help="Findings seeded before the API phase",
    )
    args = parser.parse_args()

    if args.packets < 1:
        print("--packets must be at least 1")
        return 1
    if args.flows < 1:
        print("--flows must be at least 1")
        return 1
    if args.memory_packets < 1:
        print("--memory-packets must be at least 1")
        return 1
    if args.api_iterations < 1:
        print("--api-iterations must be at least 1")
        return 1
    if args.api_findings < 1:
        print("--api-findings must be at least 1")
        return 1

    benchmark_throughput(args.packets, args.flows)
    benchmark_memory(args.memory_packets, args.flows)
    benchmark_api(args.api_iterations, args.api_findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
