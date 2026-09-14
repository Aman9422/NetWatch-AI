"""M7 verification script — see packets persisted, queried and retained (M7.22/M7.23).

Two modes:

  sample  (default)  Persist synthetic packets covering the main protocol cases
                     (DNS, web, ping, local TCP) through PacketProcessor ->
                     PacketPersistence -> SQLite, then read them back and verify
                     the stored metadata. It also seeds an expired packet and
                     runs retention to show old rows are deleted and recent ones
                     kept. No admin rights or Npcap needed — runs anywhere, and
                     against a throwaway in-memory database, never ``netwatch.db``.
  live               Capture real traffic through CaptureManager ->
                     PacketProcessor -> PacketPersistence for a few seconds, then
                     read the stored packets back. Requires Npcap and (Windows)
                     admin.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\verify_m7.py
    & ".venv\\Scripts\\python.exe" scripts\\verify_m7.py live --interface "Wi-Fi" --seconds 5
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from app.persistence.manager import PacketPersistence  # noqa: E402
from app.persistence.mapping import to_packet_values  # noqa: E402
from app.persistence.retention import PacketRetentionService  # noqa: E402
from app.processing.processor import PacketProcessor  # noqa: E402
from app.repositories.packet import PacketRepository  # noqa: E402
from app.services.packet_query import PacketQueryService  # noqa: E402
from tests.fakes import make_normalized_packet  # noqa: E402

_BANNER_WIDTH = 66

# Retention window used by the sample-mode retention check.
_RETENTION_DAYS = 7


def _sample_packets() -> list[tuple[str, object]]:
    """Return labelled, harmless packets covering the main protocol cases."""
    return [
        (
            "DNS lookup (UDP/53)",
            Ether()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=51000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com")),
        ),
        (
            "Web request (TCP/443)",
            Ether()
            / IP(src="192.168.1.10", dst="142.250.0.1")
            / TCP(sport=52000, dport=443, flags="S"),
        ),
        (
            "Ping (ICMP)",
            Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(),
        ),
        (
            "Local TCP traffic",
            Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=40000, dport=8080),
        ),
    ]


def _make_engine():
    """Return a throwaway in-memory SQLite engine with the schema created."""
    from app import models as _models  # noqa: F401 - registers the tables
    from app.database.base import Base

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine


def _session_factory(engine):
    """Return a factory building sessions bound to ``engine``."""

    def factory() -> Session:
        return Session(bind=engine)

    return factory


def _print_stored(session_factory, *, limit: int = 50) -> int:
    """Print stored packets and return how many rows exist in total."""
    session: Session = session_factory()
    try:
        repository = PacketRepository(session)
        total = repository.count()
        rows = repository.list(limit=limit)
    finally:
        session.close()

    print(f"\n--- Stored packets ({total}) ---")
    if not rows:
        print("  (none)")
        return total
    print(
        f"  {'captured (UTC)':<21} {'source':<17} {'sport':>5} -> "
        f"{'destination':<17} {'dport':>5}  {'proto':<6} {'len':>5} {'payload'}"
    )
    for row in rows:
        source_port = "-" if row.source_port is None else str(row.source_port)
        destination_port = (
            "-" if row.destination_port is None else str(row.destination_port)
        )
        payload = "NULL" if row.payload_length is None else str(row.payload_length)
        print(
            f"  {row.timestamp.isoformat():<21} {row.source_ip:<17} {source_port:>5} -> "
            f"{row.destination_ip:<17} {destination_port:>5}  "
            f"{row.protocol:<6} {row.packet_length:>5} {payload}"
        )
    return total


def _persist_sample_packets(session_factory) -> tuple[PacketPersistence, int]:
    """Normalize and persist the sample packets; return the layer and count."""
    processor = PacketProcessor(interface="<sample>")
    persistence = PacketPersistence(
        session_factory=session_factory,
        autostart=False,
        batch_size=2,
        flush_interval=60.0,
    )
    accepted = 0
    for label, packet in _sample_packets():
        normalized = processor.process(packet)
        if persistence.record_packet(normalized):
            accepted += 1
        print(
            f"buffered [{label}] -> {normalized.packet_type.value} "
            f"{normalized.length} B"
        )
    written = persistence.flush()
    print(
        f"\nflush wrote {written} row(s) in {persistence.get_batch_count()} batch(es); "
        f"buffered accepted={accepted}"
    )
    return persistence, accepted


def _verify_retention(session_factory) -> list[str]:
    """Seed an expired row, run retention and verify only it is deleted."""
    failures: list[str] = []
    now = datetime.now(timezone.utc)

    # An old row (well past the window) written directly, so the recent packets
    # captured a moment ago are the control group.
    old_packet = to_packet_values(
        make_normalized_packet(
            timestamp=(now - timedelta(days=_RETENTION_DAYS + 10)).timestamp(),
            source_ip="10.0.0.99",
            destination_ip="10.0.0.100",
        )
    )
    assert old_packet is not None
    session: Session = session_factory()
    try:
        before = PacketRepository(session).count()
        PacketRepository(session).write_batch([old_packet])
    finally:
        session.close()

    service = PacketRetentionService(
        session_factory=session_factory, retention_days=_RETENTION_DAYS
    )
    deleted = service.cleanup(now=now)

    session = session_factory()
    try:
        after = PacketRepository(session).count()
    finally:
        session.close()

    print("\n--- Retention ---")
    print(f"  retention window      : {_RETENTION_DAYS} days")
    print(f"  rows before seeding   : {before}")
    print(f"  rows seeded (expired) : 1")
    print(f"  rows deleted          : {deleted}")
    print(f"  rows after cleanup    : {after}")

    if deleted != 1:
        failures.append(f"retention deleted {deleted} row(s), expected 1")
    if after != before:
        failures.append(f"retention left {after} rows, expected {before}")
    if not failures:
        print("  OK: only the expired packet was removed; recent ones preserved")
    return failures


def run_sample_mode() -> int:
    """Persist, query and retain synthetic packets against a throwaway database."""
    print("=" * _BANNER_WIDTH)
    print("M7 SAMPLE MODE — synthetic packets, no privileges required")
    print("=" * _BANNER_WIDTH)

    engine = _make_engine()
    session_factory = _session_factory(engine)
    try:
        persistence, accepted = _persist_sample_packets(session_factory)
        total = _print_stored(session_factory)

        failures = _check_expectations(session_factory, persistence, accepted, total)
        failures += _verify_retention(session_factory)

        # Show the query service answering a real question over stored data.
        print("\n--- Query service ---")
        session = session_factory()
        try:
            service = PacketQueryService(session)
            recent = service.recent(limit=3)
            dns = service.by_protocol("DNS")
        finally:
            session.close()
        print(f"  recent(3)         -> {len(recent)} packet(s)")
        print(f"  by_protocol(DNS)  -> {len(dns)} packet(s)")
    finally:
        engine.dispose()

    print("\n" + "=" * _BANNER_WIDTH)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print("Sample mode finished with failures.")
        return 1
    print("Sample mode complete — all checks passed.")
    return 0


def _check_expectations(
    session_factory, persistence: PacketPersistence, accepted: int, total: int
) -> list[str]:
    """Return the list of M7 expectations that were not met."""
    failures: list[str] = []
    expected = len(_sample_packets())

    if accepted != expected:
        failures.append(f"accepted {accepted} packet(s), expected {expected}")
    if total != expected:
        failures.append(f"stored {total} row(s), expected {expected}")
    if persistence.get_persisted_count() != expected:
        failures.append(
            f"persisted counter was {persistence.get_persisted_count()}, "
            f"expected {expected}"
        )
    if persistence.get_failed_count() != 0:
        failures.append(f"{persistence.get_failed_count()} batch(es) failed")
    if persistence.get_queue_depth() != 0:
        failures.append("the buffer was not fully drained after flush")

    session: Session = session_factory()
    try:
        rows = PacketRepository(session).list(limit=100)
    finally:
        session.close()

    if any(row.payload_length is not None for row in rows):
        failures.append("a payload length was stored (payload must stay NULL, M7.5)")
    if any(row.source_ip is None or row.destination_ip is None for row in rows):
        failures.append("a stored row is missing an endpoint")
    protocols = {row.protocol for row in rows}
    if "DNS" not in protocols:
        failures.append(f"DNS was not labelled (protocols seen: {sorted(protocols)})")
    if not any(row.destination_port == 443 for row in rows):
        failures.append("the web request (destination port 443) was not stored")

    if not failures:
        print(
            "\n  OK: every packet persisted, values match, and no payload was "
            "stored"
        )
    return failures


def run_live_mode(interface: str, seconds: float) -> int:
    """Capture real traffic, persist it, and read the stored packets back."""
    from app.persistence.manager import PacketPersistence as _Persistence
    from app.services.capture_manager import CaptureManager
    from app.services.capture_state import CaptureError
    from app.services.interface_manager import get_interface_manager

    interface_manager = get_interface_manager()
    try:
        interface_manager.select_interface(interface)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not select interface '{interface}': {exc}")
        return 1

    engine = _make_engine()
    session_factory = _session_factory(engine)
    persistence = _Persistence(session_factory=session_factory, autostart=False)
    manager = CaptureManager(interface_manager=interface_manager)
    manager.get_pipeline()._persistence = persistence  # noqa: SLF001 - dev script

    print("=" * _BANNER_WIDTH)
    print(f"M7 LIVE MODE — capturing on '{interface}' for {seconds:g}s")
    print("=" * _BANNER_WIDTH)
    print("Generate harmless traffic now (browse a page, ping a host).")

    try:
        try:
            manager.stop()
        except Exception:  # noqa: BLE001 - no session to stop
            pass
        manager.start()
    except CaptureError as exc:
        print(f"START FAILED: {exc.code} - {exc.message}")
        engine.dispose()
        return 1

    import time as _time

    _time.sleep(seconds)
    raw = manager.get_packet_count()
    processed = manager.get_processed_packet_count()
    manager.stop()  # flushes the persistence buffer (M7.18)

    print("\n--- Capture result ---")
    print(f"  raw captured      : {raw}")
    print(f"  normalized ok     : {processed}")
    print(f"  persistence errors: {manager.get_pipeline().get_persistence_error_count()}")

    total = _print_stored(session_factory)
    engine.dispose()

    if processed and total == 0:
        print("\nTraffic was processed but no packet was persisted.")
        return 1
    print("\nLive mode complete.")
    return 0


def main() -> int:
    """Parse arguments and dispatch to the selected mode."""
    parser = argparse.ArgumentParser(
        description="Verify M7 packet persistence, queries and retention."
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
