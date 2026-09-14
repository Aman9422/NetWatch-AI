"""M8 performance baseline — measure device discovery and its API (M8.24).

Feeds a large batch of synthetic ``NormalizedPacket`` objects into a
:class:`DeviceDiscoveryManager` and reports:

  * packets processed per second,
  * per-packet discovery overhead (microseconds),
  * devices discovered,
  * device lookup time (single-device and registry listing),
  * Python memory held by the registry (``tracemalloc``),
  * API response times for the read-only device endpoints.

This is a local, single-machine baseline for the M8 discovery code only. It is
NOT a production-capacity claim: it excludes real capture (Scapy/Npcap), the M5
normalization step, the network stack, JSON serialization at the wire, and any
database. Numbers will differ on other hardware and workloads.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_M8.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_M8.py --packets 200000 --devices 4096
"""

from __future__ import annotations

import argparse
import statistics as stats
import sys
import time
import tracemalloc
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.schemas.packet import NormalizedPacket, PacketType  # noqa: E402

_BANNER_WIDTH = 66

# Host counts and ports used to build varied synthetic traffic.
_HOSTS = 2048
_PORTS = [443, 80, 53, 22, 3389]
_PROTOCOLS = [(PacketType.TCP, "TCP"), (PacketType.UDP, "UDP")]
# Fixed past timestamp for the memory phase, so rate/timing state is stable.
_PAST_TIMESTAMP = 1_000_000.0
# How many lookups are timed for the lookup benchmark.
_LOOKUPS = 5_000


def _mac_for(host: int) -> str:
    """Return a unique unicast MAC for a host index (first octet 0x02)."""
    return (
        f"02:00:{(host >> 24) & 0xFF:02X}:{(host >> 16) & 0xFF:02X}:"
        f"{(host >> 8) & 0xFF:02X}:{host & 0xFF:02X}"
    )


def _ip_for(host: int) -> str:
    """Return a unique IPv4 address for a host index."""
    return f"10.{(host >> 16) & 0xFF}.{(host >> 8) & 0xFF}.{host & 0xFF}"


def _make_packet(index: int, timestamp: float) -> NormalizedPacket:
    """Build one synthetic packet between two hosts in the ``_HOSTS`` range."""
    host = index % _HOSTS
    peer = (host + 1) % _HOSTS
    packet_type, protocol = _PROTOCOLS[index % len(_PROTOCOLS)]
    port = _PORTS[index % len(_PORTS)]
    return NormalizedPacket(
        packet_id=index + 1,
        timestamp=timestamp,
        length=128,
        source_mac=_mac_for(host),
        destination_mac=_mac_for(peer),
        source_ip=_ip_for(host),
        destination_ip=_ip_for(peer),
        protocol=protocol,
        packet_type=packet_type,
        source_port=port,
        destination_port=port,
    )


def benchmark_discovery(packets: int, max_devices: int) -> None:
    """Feed ``packets`` packets and print throughput and lookup metrics."""
    manager = DeviceDiscoveryManager(max_devices=max_devices)
    now = time.time()
    batch = [_make_packet(index, now) for index in range(packets)]

    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    for packet in batch:
        manager.process_packet(packet)
    wall_elapsed = time.perf_counter() - wall_start
    cpu_elapsed = time.process_time() - cpu_start

    device_count = manager.get_device_count()
    throughput = packets / wall_elapsed if wall_elapsed > 0 else 0.0
    per_packet_us = (wall_elapsed / packets) * 1_000_000 if packets else 0.0

    print("=" * _BANNER_WIDTH)
    print("M8 PERFORMANCE BASELINE — device discovery (M8.24)")
    print("=" * _BANNER_WIDTH)
    print(f"packets processed     : {packets:,}")
    print(f"max devices (cap)     : {max_devices:,}")
    print(f"wall time             : {wall_elapsed:.3f} s")
    print(f"cpu time              : {cpu_elapsed:.3f} s")
    print(f"throughput            : {throughput:,.0f} packets/sec")
    print(f"per-packet overhead   : {per_packet_us:.3f} us")
    print(f"devices discovered    : {device_count:,}")
    print(f"evictions (cap hit)   : {manager.get_eviction_count():,}")
    print(f"discovery errors      : {manager.get_error_count():,}")
    _benchmark_lookups(manager)


def _benchmark_lookups(manager: DeviceDiscoveryManager) -> None:
    """Time single-device lookups and a bounded registry listing."""
    device_ids = [device.device_id for device in manager.list_devices(limit=100)]
    if not device_ids:
        print("\n--- Device lookup ---")
        print("  (no devices to look up)")
        return
    lookups = max(_LOOKUPS, len(device_ids))

    lookup_start = time.perf_counter()
    for index in range(lookups):
        manager.get_device(device_ids[index % len(device_ids)])
    lookup_us = ((time.perf_counter() - lookup_start) / lookups) * 1_000_000

    list_samples: list[float] = []
    for _ in range(200):
        start = time.perf_counter()
        manager.list_device_views(limit=100)
        list_samples.append((time.perf_counter() - start) * 1_000_000)

    print("\n--- Device lookup ---")
    print(f"  get_device(id)      : {lookup_us:8.3f} us  ({lookups:,} lookups)")
    print(
        f"  list 100 devices    : {stats.mean(list_samples):8.3f} us  "
        f"(max {max(list_samples):.3f} us)"
    )


def benchmark_memory(packets: int, max_devices: int) -> None:
    """Measure Python memory held by the bounded device registry.

    ``tracemalloc`` adds substantial overhead, so this runs separately from the
    throughput measurement; only the memory figures should be read from it.
    """
    manager = DeviceDiscoveryManager(max_devices=max_devices)
    batch = [_make_packet(index, _PAST_TIMESTAMP) for index in range(packets)]

    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    for packet in batch:
        manager.process_packet(packet)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n--- Memory (tracemalloc) ---")
    print(f"heap before           : {before / 1024 / 1024:.2f} MiB")
    print(f"heap after            : {current / 1024 / 1024:.2f} MiB")
    print(f"peak heap             : {peak / 1024 / 1024:.2f} MiB")
    print(f"devices held          : {manager.get_device_count():,}")
    print(
        f"note                  : the registry is capped at {max_devices:,} devices, "
        "so this footprint does not grow without bound"
    )


def benchmark_api(iterations: int, seeded_devices: int) -> None:
    """Time the read-only device endpoints through the ASGI test client."""
    from fastapi.testclient import TestClient

    from app.config.settings import settings
    from app.devices.manager import get_device_manager
    from app.main import app

    manager = DeviceDiscoveryManager()
    now = time.time()
    for index in range(seeded_devices):
        manager.process_packet(_make_packet(index, now))

    devices = manager.list_devices()
    detail_url = f"/api/v1/devices/{devices[0].device_id}" if devices else None
    endpoints: list[tuple[str, dict[str, int] | None]] = [
        ("/api/v1/devices", {"limit": 100})
    ]
    if detail_url is not None:
        endpoints.append((detail_url, None))

    original_env = settings.app_env
    settings.app_env = "test"  # skip init_db() during startup
    app.dependency_overrides[get_device_manager] = lambda: manager
    print("\n--- API response time (TestClient, in-process) ---")
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
                    f"  {label:<40} avg {stats.mean(samples):6.2f} ms  "
                    f"max {max(samples):6.2f} ms"
                )
    finally:
        app.dependency_overrides.pop(get_device_manager, None)
        settings.app_env = original_env


def main() -> int:
    """Parse arguments and run the baseline measurements."""
    parser = argparse.ArgumentParser(
        description="Measure the M8 device discovery performance baseline."
    )
    parser.add_argument(
        "--packets", type=int, default=200_000, help="Packets to process"
    )
    parser.add_argument(
        "--devices", type=int, default=4096, help="Maximum tracked devices"
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
        "--api-devices", type=int, default=1000, help="Devices seeded for the API phase"
    )
    args = parser.parse_args()

    if args.packets < 1:
        print("--packets must be at least 1")
        return 1
    if args.devices < 1:
        print("--devices must be at least 1")
        return 1
    if args.memory_packets < 1:
        print("--memory-packets must be at least 1")
        return 1
    if args.api_iterations < 1:
        print("--api-iterations must be at least 1")
        return 1
    if args.api_devices < 1:
        print("--api-devices must be at least 1")
        return 1

    benchmark_discovery(args.packets, args.devices)
    benchmark_memory(args.memory_packets, args.devices)
    benchmark_api(args.api_iterations, args.api_devices)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
