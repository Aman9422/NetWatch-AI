"""M6 performance baseline — measure the statistics engine and its API (M6.22).

Records a large batch of synthetic ``NormalizedPacket`` objects directly into a
:class:`TrafficStatisticsManager` and reports:

  * packets aggregated per second,
  * per-packet statistics-update overhead (microseconds),
  * CPU time consumed by the aggregation,
  * peak Python memory held by the engine (``tracemalloc``),
  * API response times for the read-only statistics endpoints.

This is a local, single-machine baseline for the M6 aggregation code only. It is
NOT a production-capacity claim: it excludes real capture (Scapy/Npcap), the M5
normalization step, the network stack, JSON serialization at the wire, and any
database. Numbers will differ on other hardware and workloads.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m6.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m6.py --packets 500000 --max-keys 4096
"""

from __future__ import annotations

import argparse
import random
import statistics as stats
import sys
import time
import tracemalloc
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.schemas.packet import NormalizedPacket, PacketType  # noqa: E402
from app.statistics.manager import TrafficStatisticsManager  # noqa: E402

# Distinct source hosts. Deliberately far larger than the default max-keys
# (1024) so the benchmark exercises BoundedCounter eviction, not just the happy
# path where every key fits.
_IP_HOSTS = 4096
_PORTS = [443, 80, 53, 22, 3389, 8080, 123, 5353]
# A fixed local-address set so traffic-direction classification (M6.7) runs
# through the same TTL cache the production capture path uses — otherwise the
# benchmark hides that path entirely.
_LOCAL_ADDRESSES = frozenset({"10.0.0.1", "10.0.0.2", "10.0.0.3"})
_PROTOCOLS = [
    (PacketType.TCP, "TCP"),
    (PacketType.UDP, "UDP"),
    (PacketType.DNS, "UDP"),
    (PacketType.ICMP, "ICMP"),
]
# Fixed past timestamp for the memory phase (forces window pruning on query).
_PAST_TIMESTAMP = 1_000_000.0
# How often the memory phase reads a snapshot to prune the rate windows.
_PRUNE_INTERVAL = 2_000
_API_ENDPOINTS = (
    "/api/v1/statistics/traffic",
    "/api/v1/statistics/protocols",
    "/api/v1/statistics/top-talkers",
    "/api/v1/statistics/ports",
)


def _make_packet(
    rng: random.Random, index: int, timestamp: float
) -> NormalizedPacket:
    """Build one synthetic normalized packet with varied, high-cardinality keys.

    Source hosts sweep across ``_IP_HOSTS`` distinct ("10.a.b.1") addresses, so
    once ``_IP_HOSTS`` exceeds ``max_keys`` the bounded counters must evict.
    """
    packet_type, protocol = rng.choice(_PROTOCOLS)
    host = index % _IP_HOSTS
    octet_a = host // 256
    octet_b = host % 256
    return NormalizedPacket(
        packet_id=index + 1,
        timestamp=timestamp,
        length=rng.choice([64, 128, 512, 1500]),
        source_ip=f"10.{octet_a}.{octet_b}.1",
        destination_ip=f"10.{octet_a}.{octet_b}.2" if index % 3 else "8.8.8.8",
        protocol=protocol,
        packet_type=packet_type,
        source_port=rng.choice(_PORTS),
        destination_port=rng.choice(_PORTS),
    )


def benchmark_engine(packets: int, max_keys: int) -> None:
    """Record ``packets`` packets and print throughput, CPU and latency metrics."""
    rng = random.Random(1234)
    manager = TrafficStatisticsManager(max_tracked_keys=max_keys)
    manager.set_local_addresses_provider(lambda: set(_LOCAL_ADDRESSES))
    now = time.time()
    batch = [_make_packet(rng, index, now) for index in range(packets)]

    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    for packet in batch:
        manager.record_packet(packet)
    wall_elapsed = time.perf_counter() - wall_start
    cpu_elapsed = time.process_time() - cpu_start

    snapshot = manager.get_statistics()
    throughput = packets / wall_elapsed if wall_elapsed > 0 else 0.0
    per_packet_us = (wall_elapsed / packets) * 1_000_000 if packets else 0.0

    print("=" * 66)
    print("M6 PERFORMANCE BASELINE — statistics engine (M6.22)")
    print("=" * 66)
    print(f"packets recorded      : {packets:,}")
    print(f"max tracked keys      : {max_keys:,}")
    print(f"wall time             : {wall_elapsed:.3f} s")
    print(f"cpu time              : {cpu_elapsed:.3f} s")
    print(f"throughput            : {throughput:,.0f} packets/sec")
    print(f"per-packet overhead   : {per_packet_us:.3f} us")
    print(f"total packets         : {snapshot.total_packets:,}")
    print(f"total bytes           : {snapshot.total_bytes:,}")
    print(f"sources tracked       : {len(snapshot.top_sources)} (top listing)")


def benchmark_memory(packets: int, max_keys: int) -> None:
    """Measure Python memory held by the bounded counters while aggregating.

    ``tracemalloc`` adds substantial overhead, so this runs separately from the
    throughput measurement; only the memory figures should be read from it.

    Packets are stamped with a fixed *past* timestamp and a snapshot is read
    periodically, so the sliding rate windows stay pruned. That isolates the
    footprint of the bounded key counters from the transient window buffers —
    exactly the memory the engine is designed to keep bounded.
    """
    rng = random.Random(4321)
    manager = TrafficStatisticsManager(max_tracked_keys=max_keys)
    manager.set_local_addresses_provider(lambda: set(_LOCAL_ADDRESSES))
    batch = [_make_packet(rng, index, _PAST_TIMESTAMP) for index in range(packets)]

    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    for index, packet in enumerate(batch):
        manager.record_packet(packet)
        if index % _PRUNE_INTERVAL == 0:
            manager.get_statistics()  # prune rate windows, keep counters only
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    snapshot = manager.get_statistics()
    print("\n--- Memory (tracemalloc; counters only, windows pruned) ---")
    print(f"heap before           : {before / 1024 / 1024:.2f} MiB")
    print(f"heap after            : {current / 1024 / 1024:.2f} MiB")
    print(f"peak heap             : {peak / 1024 / 1024:.2f} MiB")
    print(f"distinct sources kept : {len(snapshot.top_sources)} (top listing)")
    print(
        "note                  : the 5 bounded counters cap distinct keys at "
        f"{max_keys:,} each, so this footprint does not grow with packet count"
    )


def benchmark_api(iterations: int) -> None:
    """Time the read-only statistics endpoints through the ASGI test client."""
    from fastapi.testclient import TestClient

    from app.config.settings import settings
    from app.main import app
    from app.statistics.manager import get_statistics_manager

    manager = TrafficStatisticsManager()
    rng = random.Random(9)
    now = time.time()
    for index in range(1000):
        manager.record_packet(_make_packet(rng, index, now))

    original_env = settings.app_env
    settings.app_env = "test"  # skip init_db() during startup
    app.dependency_overrides[get_statistics_manager] = lambda: manager
    print("\n--- API response time (TestClient, in-process) ---")
    try:
        with TestClient(app) as client:
            for endpoint in _API_ENDPOINTS:
                samples: list[float] = []
                for _ in range(iterations):
                    start = time.perf_counter()
                    response = client.get(endpoint)
                    samples.append((time.perf_counter() - start) * 1000.0)
                    if response.status_code != 200:
                        raise RuntimeError(
                            f"{endpoint} returned HTTP {response.status_code}"
                        )
                print(
                    f"  {endpoint:<38} avg {stats.mean(samples):6.2f} ms  "
                    f"max {max(samples):6.2f} ms"
                )
    finally:
        app.dependency_overrides.pop(get_statistics_manager, None)
        settings.app_env = original_env


def main() -> int:
    """Parse arguments and run the baseline measurements."""
    parser = argparse.ArgumentParser(
        description="Measure the M6 statistics engine performance baseline."
    )
    parser.add_argument(
        "--packets", type=int, default=200_000, help="Packets to aggregate"
    )
    parser.add_argument(
        "--max-keys", type=int, default=1024, help="Bounded counter capacity per key set"
    )
    parser.add_argument(
        "--api-iterations", type=int, default=200, help="Requests timed per endpoint"
    )
    args = parser.parse_args()

    if args.packets < 1:
        print("--packets must be at least 1")
        return 1
    if args.max_keys < 1:
        print("--max-keys must be at least 1")
        return 1
    if args.api_iterations < 1:
        print("--api-iterations must be at least 1")
        return 1

    benchmark_engine(args.packets, args.max_keys)
    benchmark_memory(args.packets, args.max_keys)
    benchmark_api(args.api_iterations)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
