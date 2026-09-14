"""M8 verification script — see devices discovered and tracked (M8.23).

Two modes:

  sample  (default)  Push synthetic packets covering every addressing case
                     through PacketProcessor -> DeviceDiscoveryManager and print
                     the discovered device registry. No admin rights or Npcap
                     needed — runs anywhere. It also waits past the inactivity
                     threshold and shows the devices turn ``inactive``.
  live               Capture real traffic through CaptureManager ->
                     PacketProcessor -> DeviceDiscoveryManager for a few
                     seconds. Requires Npcap and (Windows) admin.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_M8.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_M8.py live --interface "Wi-Fi" --seconds 5
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
from scapy.layers.l2 import ARP, Ether  # noqa: E402

from app.devices.device import ObservedDevice  # noqa: E402
from app.devices.manager import DeviceDiscoveryManager  # noqa: E402
from app.processing.processor import PacketProcessor  # noqa: E402
from app.schemas.device import DeviceStatus  # noqa: E402

_BANNER_WIDTH = 66

MAC_A = "AA:BB:CC:DD:EE:FF"
MAC_B = "22:33:44:55:66:77"

# Expected observations for MAC_A in sample mode (see ``_sample_packets``).
_EXPECTED_MAC_A_PACKETS = 5


def _sample_packets() -> list[tuple[str, object]]:
    """Return labelled packets covering every addressing and identity case."""
    return [
        (
            "IPv4/TCP with both MACs",
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=52000, dport=443),
        ),
        (
            "IPv4/UDP with both MACs",
            Ether(src=MAC_A, dst=MAC_B)
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / UDP(sport=53000, dport=53),
        ),
        (
            "IPv6/TCP from the same MAC",
            Ether(src=MAC_A, dst=MAC_B)
            / IPv6(src="fe80::1", dst="fe80::2")
            / TCP(sport=1234, dport=80),
        ),
        (
            "IPv4/ICMP in the other direction",
            Ether(src=MAC_B, dst=MAC_A)
            / IP(src="192.168.1.20", dst="192.168.1.10")
            / ICMP(),
        ),
        (
            "IPv4/UDP with no layer-2 header (IP-only device)",
            IP(src="192.168.1.99", dst="192.168.1.98") / UDP(sport=40000, dport=53),
        ),
        (
            "ARP request to the broadcast address",
            Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1"),
        ),
    ]


def _describe(device: ObservedDevice, *, now: float, threshold: float) -> str:
    """Render one device as a single readable line."""
    addresses = ", ".join(sorted(device.ip_addresses)) or "(none)"
    status = device.status(now=now, inactivity_threshold=threshold)
    return (
        f"  {device.device_id:<26} mac={device.mac_address or '(none)':<18} "
        f"{status.value:<8} ip=[{addresses}]"
    )


def _print_devices(
    manager: DeviceDiscoveryManager, *, now: float, threshold: float
) -> None:
    """Print every tracked device with its counters and timing."""
    devices = manager.list_devices()
    print(f"\n--- Devices ({len(devices)}) ---")
    if not devices:
        print("  (none)")
        return
    for device in devices:
        print(_describe(device, now=now, threshold=threshold))
        print(
            f"      packets={device.packet_count} bytes={device.byte_count} "
            f"sent={device.packets_sent} received={device.packets_received}"
        )
        print(f"      first_seen={device.first_seen} last_seen={device.last_seen}")

    print("\n--- Registry diagnostics ---")
    print(f"  devices tracked                     : {manager.get_device_count()}")
    print(f"  collisions (IP moved between MACs)   : {manager.get_conflict_count()}")
    print(f"  identity upgrades                   : {manager.get_upgrade_count()}")
    print(f"  evictions                           : {manager.get_eviction_count()}")
    print(f"  discovery errors                    : {manager.get_error_count()}")


def run_sample_mode(inactivity_threshold: float, inactive_wait: float) -> int:
    """Normalize synthetic packets and verify what device discovery recorded."""
    processor = PacketProcessor(interface="<sample>")
    manager = DeviceDiscoveryManager(
        inactivity_threshold=inactivity_threshold,
        retention_seconds=inactivity_threshold + 600.0,
    )
    print("=" * _BANNER_WIDTH)
    print("M8 SAMPLE MODE — synthetic packets, no privileges required")
    print("=" * _BANNER_WIDTH)

    for label, packet in _sample_packets():
        try:
            normalized = processor.process(packet, captured_at=time.time())
        except Exception as exc:  # noqa: BLE001 - surface any processing failure
            print(f"\n[{label}] PROCESSING FAILED: {exc}")
            continue
        manager.process_packet(normalized)
        print(
            f"observed [{label}] -> src_mac={normalized.source_mac or '-'} "
            f"src_ip={normalized.source_ip or '-'}"
        )

    now = time.time()
    _print_devices(manager, now=now, threshold=inactivity_threshold)

    failures = _check_expectations(manager, now=now, threshold=inactivity_threshold)

    print(f"\n--- Inactivity (threshold {inactivity_threshold:g}s) ---")
    print(f"  waiting {inactive_wait:g}s for traffic to stop ...")
    time.sleep(inactive_wait)
    _print_devices(manager, now=time.time(), threshold=inactivity_threshold)

    inactive = len(manager.list_devices(status=DeviceStatus.INACTIVE))
    if inactive != manager.get_device_count():
        failures.append(
            f"expected all {manager.get_device_count()} devices inactive, got {inactive}"
        )
    else:
        print(f"  OK: all {inactive} device(s) are now inactive")

    print("\n" + "=" * _BANNER_WIDTH)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("Sample mode finished with failures.")
        return 1
    print("Sample mode complete — all checks passed.")
    return 0


def _check_expectations(
    manager: DeviceDiscoveryManager, *, now: float, threshold: float
) -> list[str]:
    """Return the list of M8 expectations that were not met."""
    failures: list[str] = []
    device_a = manager.get_device(f"mac:{MAC_A}")
    device_b = manager.get_device(f"mac:{MAC_B}")

    if device_a is None:
        failures.append(f"device mac:{MAC_A} was not discovered")
    else:
        if device_a.ip_addresses != {"192.168.1.10", "fe80::1"}:
            failures.append(
                f"mac:{MAC_A} addresses were {sorted(device_a.ip_addresses)}"
            )
        if device_a.packet_count != _EXPECTED_MAC_A_PACKETS:
            failures.append(
                f"mac:{MAC_A} packet_count was {device_a.packet_count}, "
                f"expected {_EXPECTED_MAC_A_PACKETS}"
            )
        active = device_a.status(now=now, inactivity_threshold=threshold)
        if active is not DeviceStatus.ACTIVE:
            failures.append(f"mac:{MAC_A} was not active right after its traffic")

    if device_b is None:
        failures.append(f"device mac:{MAC_B} was not discovered")
    else:
        # MAC_B is the destination of the IPv6 packet, so it legitimately
        # owns both the IPv4 and the IPv6 address it was addressed with.
        expected_b = {"192.168.1.20", "fe80::2"}
        if device_b.ip_addresses != expected_b:
            failures.append(
                f"mac:{MAC_B} addresses were {sorted(device_b.ip_addresses)}"
            )
        if device_b.packet_count != 4:
            failures.append(
                f"mac:{MAC_B} packet_count was {device_b.packet_count}, expected 4"
            )

    if manager.get_device("ip:192.168.1.99") is None:
        failures.append("the IP-only device ip:192.168.1.99 was not discovered")

    if any(
        device.device_id.endswith("FF:FF:FF:FF:FF:FF")
        for device in manager.list_devices()
    ):
        failures.append("the broadcast address was tracked as a device")

    if not failures:
        print("\n  OK: discovery, addressing, counters and status all as expected")
    return failures


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic and print the devices discovered from it."""
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
    print(f"M8 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
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
    devices = manager.get_pipeline().devices
    manager.stop()

    print("\n--- Capture result ---")
    print(f"  raw captured           : {raw}")
    print(f"  normalized ok          : {processed}")
    print(f"  processing errors      : {processing_errors}")
    print(f"  statistics errors      : {statistics_errors}")
    print(f"  device discovery errors: {device_errors}")

    now = time.time()
    _print_devices(devices, now=now, threshold=devices.inactivity_threshold)

    if device_errors:
        print("\nDevice discovery reported errors; see the log above.")
        return 1
    if processed and devices.get_device_count() == 0:
        print("\nTraffic was processed but no device was discovered.")
        return 1
    print("\nLive mode complete.")
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify M8 device discovery and tracking."
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
    parser.add_argument(
        "--inactivity-threshold",
        type=float,
        default=2.0,
        help="Seconds before a quiet device becomes inactive (sample mode)",
    )
    parser.add_argument(
        "--inactive-wait",
        type=float,
        default=3.0,
        help="Seconds to wait after traffic stops (sample mode)",
    )
    args = parser.parse_args()

    if args.mode == "live":
        return run_live_mode(args.interface, args.seconds)
    if args.inactivity_threshold < 0:
        print("--inactivity-threshold must not be negative")
        return 1
    if args.inactive_wait < 0:
        print("--inactive-wait must not be negative")
        return 1
    return run_sample_mode(args.inactivity_threshold, args.inactive_wait)


if __name__ == "__main__":
    raise SystemExit(main())
