"""M5 verification script — see PacketProcessor turn packets into normalized data.

Two modes:

  sample  (default)  Build synthetic packets for every supported protocol and
                     print the normalized result. No admin rights or Npcap
                     needed — runs anywhere.
  live               Capture real traffic through CaptureManager -> PacketProcessor
                     for a few seconds. Requires Npcap and (Windows) admin.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m5.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m5.py live --interface "Wi-Fi" --seconds 3
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
from scapy.packet import Raw  # noqa: E402

from app.processing.processor import PacketProcessor  # noqa: E402
from app.schemas.packet import PacketType  # noqa: E402


def _sample_packets() -> list[tuple[str, object]]:
    """Return labelled synthetic packets covering every protocol path."""
    return [
        (
            "IPv4 / TCP (SYN)",
            Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
            / IP(src="192.168.1.10", dst="142.250.0.1")
            / TCP(sport=52341, dport=443, flags="S"),
        ),
        (
            "IPv4 / UDP",
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5353, dport=53),
        ),
        (
            "IPv4 / ICMP",
            Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(),
        ),
        (
            "IPv6 / TCP",
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
        ("Unknown (raw)", Raw(b"\x00\x01\x02\x03")),
    ]


def _print_normalized(label: str, packet) -> None:
    """Print a normalized packet in a readable single block."""
    print(f"\n[{label}]")
    print(f"  packet_id    : {packet.packet_id}")
    print(f"  packet_type  : {packet.packet_type.value}")
    print(f"  protocol     : {packet.protocol}")
    print(f"  ip_version   : {packet.ip_version}")
    print(f"  mac          : {packet.source_mac} -> {packet.destination_mac}")
    print(f"  ip           : {packet.source_ip} -> {packet.destination_ip}")
    print(f"  ports        : {packet.source_port} -> {packet.destination_port}")
    print(f"  tcp_flags    : {packet.tcp_flags}")
    print(f"  length       : {packet.length}")


def run_sample_mode() -> int:
    """Normalize synthetic packets and print the results."""
    processor = PacketProcessor(interface="<sample>")
    print("=" * 62)
    print("M5 SAMPLE MODE — synthetic packets, no privileges required")
    print("=" * 62)

    for label, packet in _sample_packets():
        try:
            normalized = processor.process(packet)
        except Exception as exc:  # noqa: BLE001 - surface any processing failure
            print(f"\n[{label}] PROCESSING FAILED: {exc}")
            continue
        _print_normalized(label, normalized)

    print("\n" + "=" * 62)
    print("Sample mode complete.")
    return 0


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic and normalize it through the M5 pipeline."""
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

    print("=" * 62)
    print(f"M5 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
    print("=" * 62)
    try:
        manager.start()
    except CaptureError as exc:
        print(f"START FAILED: {exc.code} - {exc.message}")
        return 1

    time.sleep(seconds)
    raw = manager.get_packet_count()
    processed = manager.get_processed_packet_count()
    errors = manager.get_processing_error_count()
    manager.stop()

    print("\n--- Result ---")
    print(f"raw captured     : {raw}")
    print(f"normalized ok    : {processed}")
    print(f"processing errors: {errors}")
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(description="Verify the M5 packet processing layer.")
    parser.add_argument(
        "mode",
        nargs="?",
        default="sample",
        choices=("sample", "live"),
        help="sample = synthetic packets (default), live = real capture",
    )
    parser.add_argument("--interface", default="Wi-Fi", help="Interface for live mode")
    parser.add_argument("--seconds", type=float, default=3.0, help="Live capture duration")
    args = parser.parse_args()

    if args.mode == "live":
        return run_live_mode(args.interface, args.seconds)
    return run_sample_mode()


if __name__ == "__main__":
    raise SystemExit(main())
