"""M6 verification script — see the Traffic Statistics Engine aggregate traffic.

Two modes:

  sample  (default)  Push synthetic packets for every supported protocol
                     through PacketProcessor -> TrafficStatisticsManager and
                     print the aggregated statistics snapshot. No admin rights
                     or Npcap needed — runs anywhere.
  live               Capture real traffic through CaptureManager ->
                     PacketProcessor -> TrafficStatisticsManager for a few
                     seconds. Requires Npcap and (Windows) admin.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m6.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m6.py live --interface "Wi-Fi" --seconds 5
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

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402

from app.processing.processor import PacketProcessor  # noqa: E402
from app.schemas.statistics import TopEntry, TrafficSnapshot  # noqa: E402
from app.statistics.manager import TrafficStatisticsManager  # noqa: E402

_BANNER_WIDTH = 66


def _sample_packets() -> list[tuple[str, object]]:
    """Return labelled synthetic packets covering every supported protocol."""
    return [
        (
            "IPv4 / TCP -> 443",
            Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
            / IP(src="192.168.1.10", dst="142.250.0.1")
            / TCP(sport=52341, dport=443, flags="S"),
        ),
        (
            "IPv4 / TCP -> 443",
            Ether()
            / IP(src="192.168.1.10", dst="142.250.0.1")
            / TCP(sport=52342, dport=443, flags="A"),
        ),
        (
            "IPv4 / UDP -> 53",
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5353, dport=53),
        ),
        (
            "IPv4 / ICMP",
            Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(),
        ),
        (
            "IPv6 / TCP -> 80",
            Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=1234, dport=80),
        ),
        (
            "DNS over UDP",
            Ether()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=51000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com")),
        ),
        ("ARP", Ether(src="aa:bb:cc:dd:ee:ff") / ARP()),
    ]


def _print_top(title: str, entries: list[TopEntry]) -> None:
    """Print one ranked section (top sources/destinations/ports)."""
    print(f"\n--- {title} ---")
    if not entries:
        print("  (none)")
        return
    for entry in entries:
        print(f"  {entry.key:<24} {entry.packets:>6} pkt  {entry.bytes:>8} B")


def _print_snapshot(snapshot: TrafficSnapshot) -> None:
    """Print a full statistics snapshot in a readable layout."""
    print("\n--- Totals ---")
    print(f"  total packets : {snapshot.total_packets}")
    print(f"  total bytes   : {snapshot.total_bytes}")
    print(f"  packets/sec   : {snapshot.packets_per_second:.2f}")
    print(f"  bytes/sec     : {snapshot.bytes_per_second:.2f}")
    print(f"  bits/sec      : {snapshot.bits_per_second:.2f}")

    print("\n--- Protocol distribution ---")
    if not snapshot.protocol_statistics:
        print("  (none)")
    for stat in snapshot.protocol_statistics:
        print(
            f"  {stat.protocol:<6} {stat.packets:>6} pkt  "
            f"{stat.bytes:>8} B  {stat.percentage:>6.2f}%"
        )

    print("\n--- Direction ---")
    if not snapshot.direction_statistics:
        print("  (none)")
    for direction in snapshot.direction_statistics:
        print(
            f"  {direction.direction.value:<8} {direction.packets:>6} pkt  "
            f"{direction.bytes:>8} B"
        )

    _print_top("Top sources", snapshot.top_sources)
    _print_top("Top destinations", snapshot.top_destinations)
    _print_top("Top ports", snapshot.top_ports)


def run_sample_mode() -> int:
    """Normalize synthetic packets and print the aggregated statistics."""
    processor = PacketProcessor(interface="<sample>")
    statistics = TrafficStatisticsManager()
    print("=" * _BANNER_WIDTH)
    print("M6 SAMPLE MODE — synthetic packets, no privileges required")
    print("=" * _BANNER_WIDTH)

    for label, packet in _sample_packets():
        try:
            # Stamp with the processing moment, exactly as the capture layer
            # supplies ``captured_at``, so the rate windows are meaningful.
            normalized = processor.process(packet, captured_at=time.time())
        except Exception as exc:  # noqa: BLE001 - surface any processing failure
            print(f"\n[{label}] PROCESSING FAILED: {exc}")
            continue
        statistics.record_packet(normalized)
        print(
            f"recorded [{label}] -> {normalized.packet_type.value} "
            f"{normalized.length} B"
        )

    _print_snapshot(statistics.get_statistics())
    print("\n" + "=" * _BANNER_WIDTH)
    print("Sample mode complete.")
    return 0


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic and print the statistics aggregated from it."""
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
    print(f"M6 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
    print("=" * _BANNER_WIDTH)
    try:
        manager.start()
    except CaptureError as exc:
        print(f"START FAILED: {exc.code} - {exc.message}")
        return 1

    time.sleep(seconds)
    raw = manager.get_packet_count()
    processed = manager.get_processed_packet_count()
    errors = manager.get_processing_error_count()
    statistics_errors = manager.get_statistics_error_count()
    snapshot = manager.get_pipeline().statistics.get_statistics()
    manager.stop()

    print("\n--- Capture result ---")
    print(f"  raw captured      : {raw}")
    print(f"  normalized ok     : {processed}")
    print(f"  processing errors : {errors}")
    print(f"  statistics errors : {statistics_errors}")
    _print_snapshot(snapshot)
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify the M6 traffic statistics engine."
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
