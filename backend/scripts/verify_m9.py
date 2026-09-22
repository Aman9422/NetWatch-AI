"""M9 verification script — see network conversations tracked (M9.26).

Two modes:

  sample  (default)  Push synthetic packets covering a TCP handshake, UDP, ICMP
                     and IPv6 through PacketProcessor -> DeviceDiscoveryManager
                     -> ConnectionTracker and print the tracked conversations.
                     No admin rights or Npcap needed — runs anywhere. It also
                     expires the conversations and shows them retired.
  live               Capture real traffic through CaptureManager ->
                     PacketProcessor -> DeviceDiscoveryManager ->
                     ConnectionTracker for a few seconds. Requires Npcap and
                     (Windows) admin.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m9.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m9.py live --interface "Wi-Fi" --seconds 5
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
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from app.connections.connection import Connection  # noqa: E402
from app.connections.manager import ConnectionTracker  # noqa: E402
from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.processing.processor import PacketProcessor  # noqa: E402

_BANNER_WIDTH = 66

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"
IP_A = "192.168.1.10"
IP_B = "192.168.1.20"
IPV6_A = "fe80::1"
IPV6_B = "fe80::2"

# Idle time added to the last packet so every conversation looks expired.
_EXPIRY_GAP_SECONDS = 10_000.0

# (protocol, source ip, destination ip) -> (expected state, expected packets).
_EXPECTED: dict[tuple[str, str, str], tuple[str, int]] = {
    ("TCP", IP_A, IP_B): ("established", 3),
    ("UDP", IP_A, IP_B): ("active", 1),
    ("ICMP", IP_A, IP_B): ("active", 1),
    ("TCP", IPV6_A, IPV6_B): ("observed", 1),
}


def _sample_packets() -> list[tuple[str, object, float]]:
    """Return labelled packets forming four distinct conversations."""
    base = _BASE_TIME
    return [
        (
            "TCP SYN        A:52000 -> B:443",
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src=IP_A, dst=IP_B)
            / TCP(sport=52000, dport=443, flags="S"),
            base + 0.00,
        ),
        (
            "TCP SYN/ACK    B:443   -> A:52000",
            Ether(src=MAC_B, dst=MAC_A)
            / IP(src=IP_B, dst=IP_A)
            / TCP(sport=443, dport=52000, flags="SA"),
            base + 0.05,
        ),
        (
            "TCP ACK        A:52000 -> B:443",
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src=IP_A, dst=IP_B)
            / TCP(sport=52000, dport=443, flags="A"),
            base + 0.10,
        ),
        (
            "UDP DNS        A:53000 -> B:53",
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src=IP_A, dst=IP_B)
            / UDP(sport=53000, dport=53),
            base + 0.20,
        ),
        (
            "ICMP echo      A -> B",
            Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) / ICMP(),
            base + 0.30,
        ),
        (
            "IPv6/TCP       fe80::1:1234 -> fe80::2:80",
            Ether(src=MAC_A, dst=MAC_B)
            / IPv6(src=IPV6_A, dst=IPV6_B)
            / TCP(sport=1234, dport=80),
            base + 0.40,
        ),
    ]


# Fixed reference time so the printed timestamps are stable within a run.
_BASE_TIME = time.time()


def _describe(connection: Connection) -> str:
    """Render one conversation as a single readable line."""
    return (
        f"  {connection.protocol:<4} "
        f"{connection.source_ip}:{connection.source_port or '*':<6} -> "
        f"{connection.destination_ip}:{connection.destination_port or '*':<6} "
        f"{connection.state.value:<11} "
        f"pkts={connection.packet_count:<3} bytes={connection.byte_count}"
    )


def _print_connections(tracker: ConnectionTracker, *, title: str) -> None:
    """Print the tracked conversations with their counters and timing."""
    connections = tracker.list_connections(active_only=False)
    print(f"\n--- {title} ({len(connections)}) ---")
    if not connections:
        print("  (none)")
        return
    for connection in connections:
        print(_describe(connection))
        print(f"      id  = {connection.connection_id}")
        device_source = connection.source_device_id or "(unknown)"
        device_dest = connection.destination_device_id or "(unknown)"
        print(f"      src = {device_source}   dst = {device_dest}")
        print(
            f"      sent={connection.source_packet_count}/"
            f"{connection.source_byte_count}  "
            f"received={connection.destination_packet_count}/"
            f"{connection.destination_byte_count}"
        )
        print(
            f"      first_seen={connection.first_seen:.3f} "
            f"last_seen={connection.last_seen:.3f}"
        )


def _print_diagnostics(tracker: ConnectionTracker) -> None:
    """Print the tracker's counters and registry sizes."""
    print("\n--- Connection diagnostics ---")
    print(f"  conversations created     : {tracker.get_created_count():,}")
    print(f"  packets skipped           : {tracker.get_skipped_count():,}")
    print(f"  tracking errors           : {tracker.get_error_count():,}")
    print(f"  active conversations      : {tracker.get_active_count():,}")
    print(f"  historical conversations  : {tracker.get_historical_count():,}")
    print(f"  expirations               : {tracker.get_expired_count():,}")
    print(f"  capacity evictions        : {tracker.get_eviction_count():,}")


def _find(
    tracker: ConnectionTracker, key: tuple[str, str, str]
) -> Connection | None:
    """Return the conversation matching a ``(protocol, source, destination)`` key."""
    protocol, source_ip, destination_ip = key
    for connection in tracker.list_connections(active_only=False):
        if (
            connection.protocol == protocol
            and connection.source_ip == source_ip
            and connection.destination_ip == destination_ip
        ):
            return connection
    return None


def _check_expectations(tracker: ConnectionTracker) -> list[str]:
    """Return the M9 expectations that were not met."""
    failures: list[str] = []

    for key, (expected_state, expected_packets) in _EXPECTED.items():
        connection = _find(tracker, key)
        if connection is None:
            failures.append(f"no conversation for {key[0]} {key[1]} -> {key[2]}")
            continue
        if connection.state.value != expected_state:
            failures.append(
                f"{key[0]} {key[1]}->{key[2]} state was "
                f"{connection.state.value}, expected {expected_state}"
            )
        if connection.packet_count != expected_packets:
            failures.append(
                f"{key[0]} {key[1]}->{key[2]} packet_count was "
                f"{connection.packet_count}, expected {expected_packets}"
            )

    tcp = _find(tracker, ("TCP", IP_A, IP_B))
    if tcp is not None:
        if (tcp.source_packet_count, tcp.destination_packet_count) != (2, 1):
            failures.append(
                "the TCP conversation's directional counters were "
                f"{tcp.source_packet_count}/{tcp.destination_packet_count}, "
                "expected 2/1 (both directions grouped)"
            )
        if tcp.source_device_id != f"mac:{MAC_A}":
            failures.append(
                f"TCP source device was {tcp.source_device_id}, "
                f"expected mac:{MAC_A}"
            )
        if tcp.destination_device_id != f"mac:{MAC_B}":
            failures.append(
                f"TCP destination device was {tcp.destination_device_id}, "
                f"expected mac:{MAC_B}"
            )

    if tracker.get_active_count() != len(_EXPECTED):
        failures.append(
            f"active conversations were {tracker.get_active_count()}, "
            f"expected {len(_EXPECTED)}"
        )
    if tracker.get_error_count() != 0:
        failures.append(f"tracking recorded {tracker.get_error_count()} error(s)")

    if not failures:
        print("\n  OK: identity, grouping, counters, devices and state as expected")
    return failures


def run_sample_mode() -> int:
    """Normalize synthetic packets and verify what connection tracking recorded."""
    processor = PacketProcessor(interface="<sample>")
    devices = DeviceDiscoveryManager()
    tracker = ConnectionTracker(
        device_registry=devices.registry,
        autostart_cleanup=False,
    )
    print("=" * _BANNER_WIDTH)
    print("M9 SAMPLE MODE — synthetic packets, no privileges required")
    print("=" * _BANNER_WIDTH)

    for label, packet, captured_at in _sample_packets():
        try:
            normalized = processor.process(packet, captured_at=captured_at)
        except Exception as exc:  # noqa: BLE001 - surface any processing failure
            print(f"\n[{label}] PROCESSING FAILED: {exc}")
            continue
        # Device discovery runs before connection tracking, exactly as the
        # production pipeline orders them (M9.14/M9.20).
        devices.process_packet(normalized)
        tracker.process_packet(normalized)
        print(f"observed [{label}]")

    print(f"\ndevices discovered: {devices.get_device_count()}")
    _print_connections(tracker, title="Active conversations")
    _print_diagnostics(tracker)

    failures = _check_expectations(tracker)

    last_seen = max(
        (connection.last_seen for connection in tracker.list_connections()),
        default=_BASE_TIME,
    )
    print(f"\n--- Expiration (idle {_EXPIRY_GAP_SECONDS:g}s) ---")
    expired = tracker.expire_connections(now=last_seen + _EXPIRY_GAP_SECONDS)
    print(f"  retired {expired} conversation(s)")
    _print_connections(tracker, title="Retired conversations")
    print(f"  active now: {tracker.get_active_count()}")

    if expired != len(_EXPECTED):
        failures.append(
            f"expiration retired {expired} conversation(s), "
            f"expected {len(_EXPECTED)}"
        )
    else:
        print(f"  OK: all {expired} conversation(s) retired")

    print("\n" + "=" * _BANNER_WIDTH)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("Sample mode finished with failures.")
        return 1
    print("Sample mode complete — all checks passed.")
    return 0


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic and print the conversations observed from it."""
    from app.services.capture_manager import CaptureManager
    from app.services.capture_state import CaptureError
    from app.services.interface_manager import get_interface_manager

    interface_manager = get_interface_manager()
    try:
        interface_manager.select_interface(interface)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not select interface '{interface}': {exc}")
        return 1

    manager = CaptureManager(interface_manager=interface_manager)
    try:
        manager.stop()
    except Exception:  # noqa: BLE001 - no session to stop
        pass

    print("=" * _BANNER_WIDTH)
    print(f"M9 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
    print("=" * _BANNER_WIDTH)
    print("Generate harmless traffic now (browse a page, ping a host).")

    try:
        manager.start()
    except CaptureError as exc:
        print(f"START FAILED: {exc.code} - {exc.message}")
        return 1

    time.sleep(seconds)
    raw = manager.get_packet_count()
    processed = manager.get_processed_packet_count()
    processing_errors = manager.get_processing_error_count()
    statistics_errors = manager.get_statistics_error_count()
    device_errors = manager.get_device_error_count()
    connection_errors = manager.get_connection_error_count()
    tracker = manager.get_pipeline().connections
    manager.stop()

    print("\n--- Capture result ---")
    print(f"  raw captured            : {raw}")
    print(f"  normalized ok           : {processed}")
    print(f"  processing errors       : {processing_errors}")
    print(f"  statistics errors       : {statistics_errors}")
    print(f"  device discovery errors : {device_errors}")
    print(f"  connection errors       : {connection_errors}")

    if tracker is None:
        print("\nNo connection tracker is wired into the pipeline.")
        return 1

    _print_connections(tracker, title="Observed conversations")
    _print_diagnostics(tracker)

    if connection_errors:
        print("\nConnection tracking reported errors; see the log above.")
        return 1
    if processed and tracker.get_created_count() == 0:
        print("\nTraffic was processed but no conversation was created.")
        return 1
    print("\nLive mode complete.")
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify M9 connection tracking and network conversations."
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
