"""M7 performance baseline — measure packet persistence (M7.24).

Feeds large batches of synthetic packets through the M7 persistence path and
reports:

  * packets persisted per second (mapping + buffering, and database write),
  * average write latency and per-packet overhead,
  * batches committed and queue depth,
  * Python memory held by the bounded buffer (``tracemalloc``),
  * CPU time, and
  * SQLite database growth (file size and bytes per row).

The batch-size sweep runs the same workload at more than one ``batch_size`` so
the trade-off between transaction count and throughput is visible.

This is a local, single-machine baseline for the M7 persistence code only. It is
NOT a production-capacity claim: it excludes real capture (Scapy/Npcap), the M5
normalization step, JSON serialization at the wire, and concurrent readers. It
does include the background worker path (the ``autostart`` phase), which is how
persistence actually runs. Numbers will differ on other hardware and workloads.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m7.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m7.py --packets 200000 --batch-sizes 100 500 1000
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

# Make the backend root importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.persistence.manager import PacketPersistence  # noqa: E402
from app.persistence.mapping import to_packet_values  # noqa: E402
from app.repositories.packet import PacketRepository  # noqa: E402
from app.schemas.packet import NormalizedPacket, PacketType  # noqa: E402

_BANNER_WIDTH = 66

# Hosts / ports used to build varied synthetic traffic.
_HOSTS = 4096
_PORTS = [443, 80, 53, 22, 3389]
_PROTOCOLS = [(PacketType.TCP, "TCP"), (PacketType.UDP, "UDP")]
# Fixed past timestamp so no rate/timing state varies between phases.
_TIMESTAMP = 1_000_000.0


def _new_engine(directory: Path, name: str):
    """Create (or recreate) a file-backed SQLite database and its schema."""
    from app import models as _models  # noqa: F401 - registers the tables
    from app.database.base import Base

    path = directory / name
    if path.exists():
        path.unlink()
    engine = create_engine(
        f"sqlite:///{path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    return engine, path


def _session_factory(engine):
    """Return a factory building sessions bound to ``engine``."""

    def factory() -> Session:
        return Session(bind=engine)

    return factory


def _make_packet(index: int) -> NormalizedPacket:
    """Build one synthetic TCP/UDP packet between two hosts in the range."""
    host = index % _HOSTS
    peer = (host + 1) % _HOSTS
    packet_type, protocol = _PROTOCOLS[index % len(_PROTOCOLS)]
    port = _PORTS[index % len(_PORTS)]
    return NormalizedPacket(
        packet_id=index + 1,
        timestamp=_TIMESTAMP + (index % 3600),
        length=128,
        source_ip=f"10.{(host >> 8) & 0xFF}.{host & 0xFF}.1",
        destination_ip=f"10.{(peer >> 8) & 0xFF}.{peer & 0xFF}.2",
        protocol=protocol,
        packet_type=packet_type,
        source_port=port,
        destination_port=port,
    )


def _make_packets(count: int) -> list[NormalizedPacket]:
    """Build ``count`` synthetic packets."""
    return [_make_packet(index) for index in range(count)]


def benchmark_facade(
    directory: Path, packets: list[NormalizedPacket], batch_size: int, queue_max: int
) -> None:
    """Measure mapping+buffering throughput and database write throughput."""
    engine, path = _new_engine(directory, f"facade_{batch_size}.db")
    session_factory = _session_factory(engine)
    persistence = PacketPersistence(
        session_factory=session_factory,
        autostart=False,
        batch_size=batch_size,
        flush_interval=60.0,
        queue_max=queue_max,
    )

    count = len(packets)

    cpu_start = time.process_time()
    record_start = time.perf_counter()
    for packet in packets:
        persistence.record_packet(packet)
    record_elapsed = time.perf_counter() - record_start

    queue_depth = persistence.get_queue_depth()

    write_start = time.perf_counter()
    written = persistence.flush()
    write_elapsed = time.perf_counter() - write_start
    cpu_elapsed = time.process_time() - cpu_start

    total_elapsed = record_elapsed + write_elapsed
    batches = persistence.get_batch_count()
    record_rate = count / record_elapsed if record_elapsed else 0.0
    write_rate = written / write_elapsed if write_elapsed else 0.0
    per_packet_us = (write_elapsed / written) * 1_000_000 if written else 0.0
    latency_ms = (write_elapsed / batches) * 1000.0 if batches else 0.0
    size_mb = path.stat().st_size / 1024 / 1024 if path.exists() else 0.0
    bytes_per_row = (path.stat().st_size / written) if written and path.exists() else 0.0

    print(f"\n--- batch_size = {batch_size:,} ---")
    print(f"  packets recorded          : {count:,}")
    print(f"  packets written           : {written:,}")
    print(f"  batches committed         : {batches:,}")
    print(f"  queue depth after buffer  : {queue_depth:,} (cap {queue_max:,})")
    print(f"  record (map + buffer)     : {record_rate:,.0f} packets/sec")
    print(f"  database write            : {write_rate:,.0f} packets/sec")
    print(f"  per-packet write overhead : {per_packet_us:.3f} us")
    print(f"  average batch latency     : {latency_ms:.3f} ms")
    print(f"  total wall time           : {total_elapsed:.3f} s  (cpu {cpu_elapsed:.3f} s)")
    print(f"  database file size        : {size_mb:.3f} MiB  ({bytes_per_row:.0f} bytes/row)")

    engine.dispose()


def benchmark_worker(
    directory: Path, packets: list[NormalizedPacket], batch_size: int, queue_max: int
) -> None:
    """Measure the realistic background-worker path end to end (M7.8)."""
    engine, _ = _new_engine(directory, f"worker_{batch_size}.db")
    session_factory = _session_factory(engine)
    persistence = PacketPersistence(
        session_factory=session_factory,
        autostart=True,
        batch_size=batch_size,
        flush_interval=0.05,
        queue_max=queue_max,
    )

    count = len(packets)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    for packet in packets:
        persistence.record_packet(packet)
    drained = persistence.stop(flush=True)  # flush any remainder (M7.18)
    wall_elapsed = time.perf_counter() - wall_start
    cpu_elapsed = time.process_time() - cpu_start

    persisted = persistence.get_persisted_count()
    rate = count / wall_elapsed if wall_elapsed else 0.0
    per_packet_us = (wall_elapsed / count) * 1_000_000 if count else 0.0

    print(f"\n--- worker (background thread), batch_size = {batch_size:,} ---")
    print(f"  packets fed               : {count:,}")
    print(f"  packets persisted         : {persisted:,}")
    print(f"  written during final stop : {drained:,}")
    print(f"  throughput                : {rate:,.0f} packets/sec")
    print(f"  per-packet wall overhead  : {per_packet_us:.3f} us")
    print(f"  wall time                 : {wall_elapsed:.3f} s  (cpu {cpu_elapsed:.3f} s)")
    print(f"  failed packets            : {persistence.get_failed_count():,}")
    print(f"  dropped (buffer full)     : {persistence.get_dropped_count():,}")

    engine.dispose()


def benchmark_memory(packets: list[NormalizedPacket], queue_max: int) -> None:
    """Measure Python memory held by the bounded buffer (M7.9).

    ``tracemalloc`` is far slower, so this phase only maps and buffers into an
    in-memory database and never flushes; it measures the buffer footprint,
    which is bounded by ``queue_max``.
    """
    from app import models as _models  # noqa: F401
    from app.database.base import Base
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = _session_factory(engine)
    persistence = PacketPersistence(
        session_factory=session_factory,
        autostart=False,
        batch_size=1000,
        queue_max=queue_max,
    )

    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    for packet in packets:
        persistence.record_packet(packet)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    engine.dispose()

    depth = persistence.get_queue_depth()
    print("\n--- Memory (tracemalloc) ---")
    print(f"  packets buffered          : {depth:,}")
    print(f"  heap before               : {before / 1024 / 1024:.2f} MiB")
    print(f"  heap after                : {current / 1024 / 1024:.2f} MiB")
    print(f"  peak heap                 : {peak / 1024 / 1024:.2f} MiB")
    print(
        f"  note                      : the buffer is capped at {queue_max:,} rows, "
        "so its footprint does not grow without bound"
    )


def benchmark_repository(
    directory: Path, packets: list[NormalizedPacket], batch_size: int
) -> None:
    """Measure the raw repository batch write (database write overhead)."""
    engine, _ = _new_engine(directory, "repository.db")
    session_factory = _session_factory(engine)
    rows = [to_packet_values(packet) for packet in packets]
    clean_rows = [row for row in rows if row is not None]

    session: Session = session_factory()
    try:
        repository = PacketRepository(session)
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        written = 0
        for start in range(0, len(clean_rows), batch_size):
            written += repository.write_batch(clean_rows[start : start + batch_size])
        wall_elapsed = time.perf_counter() - wall_start
        cpu_elapsed = time.process_time() - cpu_start
    finally:
        session.close()

    rate = written / wall_elapsed if wall_elapsed else 0.0
    per_row_us = (wall_elapsed / written) * 1_000_000 if written else 0.0
    batches = (written + batch_size - 1) // batch_size

    print(f"\n--- repository write_batch, batch_size = {batch_size:,} ---")
    print(f"  rows written              : {written:,}")
    print(f"  batches committed         : {batches:,}")
    print(f"  write throughput          : {rate:,.0f} rows/sec")
    print(f"  per-row write overhead    : {per_row_us:.3f} us")
    print(f"  wall time                 : {wall_elapsed:.3f} s  (cpu {cpu_elapsed:.3f} s)")

    engine.dispose()


def main() -> int:
    """Parse arguments and run the baseline measurements."""
    parser = argparse.ArgumentParser(
        description="Measure the M7 packet persistence performance baseline."
    )
    parser.add_argument("--packets", type=int, default=100_000, help="Packets to persist")
    parser.add_argument(
        "--batch-sizes",
        type=int,
        nargs="+",
        default=[100, 500, 1000],
        help="Batch sizes to sweep",
    )
    parser.add_argument(
        "--queue-max", type=int, default=0, help="Buffer cap (0 = size the buffer to --packets)"
    )
    parser.add_argument(
        "--memory-packets",
        type=int,
        default=50_000,
        help="Packets used for the tracemalloc phase (it is much slower)",
    )
    args = parser.parse_args()

    if args.packets < 1:
        print("--packets must be at least 1")
        return 1
    if any(size < 1 for size in args.batch_sizes):
        print("--batch-sizes values must be at least 1")
        return 1
    if args.memory_packets < 1:
        print("--memory-packets must be at least 1")
        return 1

    queue_max = args.queue_max if args.queue_max > 0 else args.packets
    packets = _make_packets(args.packets)

    print("=" * _BANNER_WIDTH)
    print("M7 PERFORMANCE BASELINE — packet persistence (M7.24)")
    print("=" * _BANNER_WIDTH)
    print(f"packets per run           : {args.packets:,}")
    print(f"batch sizes               : {args.batch_sizes}")
    print(f"buffer cap                : {queue_max:,}")

    with tempfile.TemporaryDirectory(prefix="netwatch_m7_") as tmp:
        directory = Path(tmp)
        benchmark_repository(directory, packets, args.batch_sizes[0])
        for batch_size in args.batch_sizes:
            benchmark_facade(directory, packets, batch_size, queue_max)
        benchmark_worker(directory, packets, args.batch_sizes[0], queue_max)
        benchmark_memory(_make_packets(args.memory_packets), args.memory_packets)

    print("\n" + "=" * _BANNER_WIDTH)
    print("Baseline complete. Local single-machine numbers only — not a")
    print("production-capacity claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
