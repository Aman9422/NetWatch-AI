"""M9 performance baseline — measure connection tracking and its API (M9.27).

Feeds large batches of synthetic ``NormalizedPacket`` objects into a
:class:`ConnectionTracker` and reports:

  * packets processed per second and per-packet tracking overhead (microseconds),
  * new conversations created per second,
  * existing-conversation update rate,
  * active conversation count and the registry footprint,
  * single-connection lookup time,
  * idle-sweep (expiration) time,
  * Python memory held by the registry (``tracemalloc``),
  * API response times for the read-only connection endpoints.

This is a local, single-machine baseline for the M9 tracking code only. It is
NOT a production-capacity claim: it excludes real capture (Scapy/Npcap), the M5
normalization step, the M7 packet write, the network stack, JSON serialization at
the wire, and any database. Numbers will differ on other hardware and workloads.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m9.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m9.py --packets 200000 --flows 20000
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

from app.connections.manager import ConnectionTracker  # noqa: E402
from app.schemas.packet import NormalizedPacket, PacketType  # noqa: E402

_BANNER_WIDTH = 66

# Two endpoints reused by every synthetic flow; identity comes from the ports,
# which are derived from the flow number and so never collide.
_SOURCE_IP = "10.0.0.1"
_DESTINATION_IP = "10.0.0.2"
_PORT_BASE = 1024
_PORT_SPAN = 60_000
_PROTOCOLS = [(PacketType.TCP, "TCP"), (PacketType.UDP, "UDP")]
# Fixed past timestamp for the memory phase, so rate/timing state is stable.
_PAST_TIMESTAMP = 1_000_000.0
# How many lookups are timed for the lookup benchmark.
_LOOKUPS = 5_000
# Idle gap used to force every active conversation to expire.
_EXPIRY_GAP_SECONDS = 10_000.0


def _ports_for(flow: int) -> tuple[int, int]:
    """Return the unique (source, destination) port pair of a flow number."""
    source_port = _PORT_BASE + (flow % _PORT_SPAN)
    destination_port = _PORT_BASE + ((flow // _PORT_SPAN) % _PORT_SPAN)
    return source_port, destination_port


def _flow_packet(flow: int, timestamp: float) -> NormalizedPacket:
    """Build one packet belonging to conversation number ``flow``."""
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
    """Return ``packets`` packets cycling through ``flows`` conversations."""
    return [
        _flow_packet(index % flows, timestamp) for index in range(packets)
    ]


def benchmark_throughput(packets: int, flows: int, max_tracked: int) -> None:
    """Feed ``packets`` packets and print throughput and creation metrics."""
    tracker = ConnectionTracker(
        max_tracked=max_tracked, max_historical=1, autostart_cleanup=False
    )
    batch = _build_batch(packets, flows, time.time())

    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    for packet in batch:
        tracker.process_packet(packet)
    wall_elapsed = time.perf_counter() - wall_start
    cpu_elapsed = time.process_time() - cpu_start

    throughput = packets / wall_elapsed if wall_elapsed > 0 else 0.0
    per_packet_us = (wall_elapsed / packets) * 1_000_000 if packets else 0.0
    created = tracker.get_created_count()
    new_per_sec = created / wall_elapsed if wall_elapsed > 0 else 0.0

    print("=" * _BANNER_WIDTH)
    print("M9 PERFORMANCE BASELINE — connection tracking (M9.27)")
    print("=" * _BANNER_WIDTH)
    print(f"packets processed     : {packets:,}")
    print(f"distinct flows        : {flows:,}")
    print(f"max tracked (cap)     : {max_tracked:,}")
    print(f"wall time             : {wall_elapsed:.3f} s")
    print(f"cpu time              : {cpu_elapsed:.3f} s")
    print(f"throughput            : {throughput:,.0f} packets/sec")
    print(f"per-packet overhead   : {per_packet_us:.3f} us")
    print(f"new conversations     : {created:,}")
    print(f"new conversations/sec : {new_per_sec:,.0f}")
    print(f"active now            : {tracker.get_active_count():,}")
    print(f"evictions (cap hit)   : {tracker.get_eviction_count():,}")
    print(f"historical dropped    : {tracker.get_dropped_count():,}")
    print(f"tracking errors       : {tracker.get_error_count():,}")
    _benchmark_lookups(tracker)


def _benchmark_lookups(tracker: ConnectionTracker) -> None:
    """Time single-conversation lookups and a bounded listing."""
    connection_ids = [
        connection.connection_id
        for connection in tracker.list_connections(limit=100)
    ]
    if not connection_ids:
        print("\n--- Conversation lookup ---")
        print("  (no conversations to look up)")
        return
    lookups = max(_LOOKUPS, len(connection_ids))

    lookup_start = time.perf_counter()
    for index in range(lookups):
        tracker.get_connection(connection_ids[index % len(connection_ids)])
    lookup_us = ((time.perf_counter() - lookup_start) / lookups) * 1_000_000

    list_samples: list[float] = []
    for _ in range(200):
        start = time.perf_counter()
        tracker.list_connection_views(limit=100)
        list_samples.append((time.perf_counter() - start) * 1_000_000)

    print("\n--- Conversation lookup ---")
    print(f"  get_connection(id)  : {lookup_us:8.3f} us  ({lookups:,} lookups)")
    print(
        f"  list 100 views      : {stats.mean(list_samples):8.3f} us  "
        f"(max {max(list_samples):.3f} us)"
    )


def benchmark_expiry(flows: int, max_tracked: int) -> None:
    """Time an idle sweep that retires a full active registry."""
    # The active cap must hold every conversation under test, otherwise the
    # sweep would be measured against a cap-limited subset instead of the set.
    tracker = ConnectionTracker(
        max_tracked=max(max_tracked, flows),
        max_historical=flows + 1,
        autostart_cleanup=False,
    )
    timestamp = time.time()
    for flow in range(flows):
        tracker.process_packet(_flow_packet(flow, timestamp))

    active_before = tracker.get_active_count()
    sweep_start = time.perf_counter()
    expired = tracker.expire_connections(now=timestamp + _EXPIRY_GAP_SECONDS)
    sweep_elapsed = time.perf_counter() - sweep_start
    per_connection_us = (
        (sweep_elapsed / expired) * 1_000_000 if expired else 0.0
    )

    print("\n--- Idle sweep (expiration) ---")
    print(f"  active before       : {active_before:,}")
    print(f"  retired             : {expired:,}")
    print(f"  sweep time          : {sweep_elapsed * 1000:.3f} ms")
    print(f"  per connection      : {per_connection_us:.3f} us")


def benchmark_memory(flows: int, max_tracked: int) -> None:
    """Measure Python memory held by the bounded connection registry.

    ``tracemalloc`` adds substantial overhead, so this runs separately from the
    throughput measurement; only the memory figures should be read from it.
    """
    tracker = ConnectionTracker(
        max_tracked=max_tracked, max_historical=1, autostart_cleanup=False
    )
    batch = _build_batch(flows, flows, _PAST_TIMESTAMP)

    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    for packet in batch:
        tracker.process_packet(packet)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n--- Memory (tracemalloc) ---")
    print(f"  heap before         : {before / 1024 / 1024:.2f} MiB")
    print(f"  heap after          : {current / 1024 / 1024:.2f} MiB")
    print(f"  peak heap           : {peak / 1024 / 1024:.2f} MiB")
    print(f"  conversations held  : {tracker.get_active_count():,}")
    print(
        f"  note                : the registry is capped at {max_tracked:,} "
        "conversations, so this footprint does not grow without bound"
    )


def benchmark_api(iterations: int, seeded_flows: int) -> None:
    """Time the read-only connection endpoints through the ASGI test client."""
    from fastapi.testclient import TestClient

    from app.config.settings import settings
    from app.connections.manager import get_connection_tracker
    from app.main import app

    tracker = ConnectionTracker(autostart_cleanup=False)
    timestamp = time.time()
    for flow in range(seeded_flows):
        tracker.process_packet(_flow_packet(flow, timestamp))

    connections = tracker.list_connections(limit=100)
    detail_url = (
        f"/api/v1/connections/{connections[0].connection_id}"
        if connections
        else None
    )
    endpoints: list[tuple[str, dict[str, int] | None]] = [
        ("/api/v1/connections", {"limit": 100}),
        ("/api/v1/connections/active", {"limit": 100}),
    ]
    if detail_url is not None:
        endpoints.append((detail_url, None))

    original_env = settings.app_env
    settings.app_env = "test"  # skip init_db() during startup
    app.dependency_overrides[get_connection_tracker] = lambda: tracker
    print("\n--- API response time (TestClient, in-process) ---")
    # Each request logs at INFO twice; over hundreds of iterations that buries
    # the measurements, so the noisy loggers are muted for the duration.
    muted = (
        "httpx",
        "app.main",
        "app.api.v1.connections",
        "app.connections.manager",
        "app.persistence.manager",
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
                    f"  {label:<44} avg {stats.mean(samples):6.2f} ms  "
                    f"max {max(samples):6.2f} ms"
                )
    finally:
        for name, level in previous_levels.items():
            logging.getLogger(name).setLevel(level)
        app.dependency_overrides.pop(get_connection_tracker, None)
        settings.app_env = original_env


def main() -> int:
    """Parse arguments and run the baseline measurements."""
    parser = argparse.ArgumentParser(
        description="Measure the M9 connection tracking performance baseline."
    )
    parser.add_argument(
        "--packets", type=int, default=200_000, help="Packets to process"
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=20_000,
        help="Distinct conversations the packets cycle through",
    )
    parser.add_argument(
        "--max-tracked",
        type=int,
        default=8_192,
        help="Cap on active conversations (defaults to the M9 setting)",
    )
    parser.add_argument(
        "--memory-flows",
        type=int,
        default=5_000,
        help="Conversations used for the tracemalloc phase (it is much slower)",
    )
    parser.add_argument(
        "--api-iterations", type=int, default=200, help="Requests timed per endpoint"
    )
    parser.add_argument(
        "--api-flows", type=int, default=1_000, help="Conversations seeded for the API"
    )
    args = parser.parse_args()

    if args.packets < 1:
        print("--packets must be at least 1")
        return 1
    if args.flows < 1:
        print("--flows must be at least 1")
        return 1
    if args.max_tracked < 1:
        print("--max-tracked must be at least 1")
        return 1
    if args.memory_flows < 1:
        print("--memory-flows must be at least 1")
        return 1
    if args.api_iterations < 1:
        print("--api-iterations must be at least 1")
        return 1
    if args.api_flows < 1:
        print("--api-flows must be at least 1")
        return 1

    benchmark_throughput(args.packets, args.flows, args.max_tracked)
    benchmark_expiry(args.flows, args.max_tracked)
    benchmark_memory(args.memory_flows, args.max_tracked)
    benchmark_api(args.api_iterations, args.api_flows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
