"""M18 performance regression harness — the whole pipeline, measured (M18.10).

What this is
------------

M18.10 asks for reproducible performance measurements and an honest comparison
against the local baselines the earlier milestones recorded. It also asks, in the
same breath, *not* to rebuild every benchmark: M6 through M17 each ship a
``benchmark_m*.py`` that already measures their own layer, and re-measuring those
layers here would produce a second set of numbers that could disagree with the
first for no reason except where they were taken.

So this harness measures the one thing the per-milestone benchmarks do not: the
**whole pipeline as M18 runs it**, end to end, over an isolated store — packets in
one side, API, analytics and report figures out the other — and then, on request,
runs the earlier milestones' own benchmarks and reports their outcomes rather than
re-measuring their layers here. The audit of what each existing benchmark covers,
and the numbers this run produced, live in ``docs/22_M18_Testing_Design.md``.

The lab is the M18.9 verification lab, imported rather than copied
-----------------------------------------------------------------

``verify_m18.py`` builds the real stack over a throwaway database for the M18.9
end-to-end flow. That wiring is imported here (``import verify_m18 as lab``)
instead of being written a second time, for a specific reason: if the two scripts
each built their own stack, a stack could drift — a detector threshold, a queue
cap, a resolver — and the throughput reported here would describe a pipeline the
verification flow never proved correct. Sharing the wiring means the performance
figures describe the same object the end-to-end checks pass against.

The private names are imported deliberately. They are the lab's own spelling of
"this is what M18 runs"; the alternative is a copy of them in this file, which is
the drift the import exists to prevent.

What is measured
----------------

``pipeline``
    Packets per second through the real M5-M12 pipeline, and the same figure as
    microseconds per packet. Sustained, not cold: one stack, one growing store,
    which is what a capture session actually does.

``api``
    Median and 95th-percentile latency for a request to each listing route, over
    the real application through ``TestClient``. That measures the application's
    own request cost — routing, the service call, serialisation — and not network
    transport, because there is none in the measurement.

``analytics``
    The same figures for the five M16 aggregate routes. Reported separately
    because they query the store rather than reading a table linearly, so folding
    them in with the listings would average two different costs into one number.

``reports``
    CSV and PDF generation and a CSV download — the M17 cost, and the only
    measured operation that writes a file.

``memory``
    Python-level allocation growth across the sustained run, via ``tracemalloc``.

What it deliberately does not claim
-----------------------------------

* **No capacity claim.** One process, one development machine, one SQLite file.
  It is a local regression baseline, and the environment is printed with the
  figures because a number without one means nothing.
* **No correctness threshold.** A slow figure is reported, never failed on. A
  timing that had to hold on every machine would be a flaky test wearing a
  benchmark's clothes, which is exactly what M18.10 warns against.
* **No network, no privilege.** Every measurement is in-process. Nothing here
  needs a socket, an elevated capture handle, a paid service or a connection.

The baseline
------------

Two runs on the same machine are comparable; two runs on different machines are
not. ``--save-baseline`` writes this run's medians and environment to a JSON file
(``backend/reports/benchmark_m18_baseline.json``, git-ignored with the other
generated artifacts) and ``--baseline`` reads one back, so a later run reports its
deviation from an earlier one. When no baseline exists the run says so rather than
inventing a comparison.

Usage (from the backend/ directory)::

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m18.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m18.py --milestones
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m18.py --save-baseline

The exit status is 0 when the run completed. It is 1 only when the harness could
not measure at all — a script it cannot find, a database it cannot create — never
because a figure came out higher than last time.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Make the backend root and this script's own directory importable.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = Path(__file__).resolve().parent
for _entry in (_BACKEND_ROOT, _SCRIPTS_DIR):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

#: The M18 lab, imported rather than reimplemented. See the module docstring.
import verify_m18 as lab  # noqa: E402

# -- reproducible inputs -------------------------------------------------------

#: Packets driven per throughput iteration. Large enough that per-iteration
#: scheduling noise does not dominate, small enough that the run stays inside a
#: couple of minutes on the reference machine -- which is a requirement, not a
#: preference: a gate nobody runs is a gate that does not exist. Measured at this
#: size, the whole run takes roughly two minutes on the development machine
#: recorded in ``docs/22_M18_Testing_Design.md``.
DEFAULT_PACKETS = 2000

#: Timed repetitions per measurement, and the warm-up runs discarded before them.
#: A warm-up matters more than it looks: the first request pays for lazy imports
#: and the first packet pays for the statistics window, and neither is a figure
#: about steady state.
DEFAULT_ITERATIONS = 3
DEFAULT_WARMUP = 1

#: Requests timed per route in the API and analytics phases. Higher than the
#: pipeline's iteration count because a request is three orders of magnitude
#: cheaper, and a median over five samples of something that fast is all noise.
API_ITERATIONS = 20
API_WARMUP = 3

#: Report generations timed per format. Generation is the most expensive measured
#: operation, so it gets fewer repetitions than the cheap ones.
REPORT_ITERATIONS = 3
REPORT_WARMUP = 1

#: Distinct sources in the generated traffic, so device discovery and connection
#: tracking do real work instead of updating one entry. Kept well below the packet
#: count so conversations repeat, which is what a capture session looks like.
DISTINCT_SOURCES = 250

#: How many client ports each source cycles through. Sources and ports together
#: bound the conversation set to ``DISTINCT_SOURCES * PORTS_PER_SOURCE`` flows, so
#: the run re-visits conversations instead of opening a new one per packet. That
#: bound is what makes the traced memory figure interpretable: once the set is
#: covered the registries stop growing, so growth after that point is behaviour
#: rather than the size of the input.
PORTS_PER_SOURCE = 8

#: A scan and a sweep are included deliberately. Without them the measurement
#: would cover M5-M9 and leave M10, M11 and M12 — the layers M18.9 verifies are
#: wired correctly — out of the cost entirely.
SCAN_SOURCES = 4
SCAN_PORTS = 12
SWEEP_HOSTS = 12

#: Where a saved baseline lives. A generated artifact, git-ignored with the rest
#: of ``backend/reports/``: a baseline is meaningful for the machine that took it,
#: so it is not something to check in and have another machine compare against.
DEFAULT_BASELINE = _BACKEND_ROOT / "reports" / "benchmark_m18_baseline.json"

#: A deviation at or above this percentage (slower) is called out in the report.
#: Reported, never failed on: see the module docstring.
NOTABLE_DEVIATION_PERCENT = 50.0

#: The per-milestone benchmarks this harness can run on request. M5, M15 and M18
#: are absent on purpose: M5 ships no benchmark, M15 is frontend (its timing is
#: the Vitest suite's own) and M18 is this file.
MILESTONE_BENCHMARKS: tuple[tuple[str, str], ...] = (
    ("M6 statistics", "benchmark_m6.py"),
    ("M7 persistence", "benchmark_m7.py"),
    ("M8 device discovery", "benchmark_m8.py"),
    ("M9 connections", "benchmark_m9.py"),
    ("M10 detection", "benchmark_m10.py"),
    ("M11 alerting", "benchmark_m11.py"),
    ("M12 correlation", "benchmark_m12.py"),
    ("M13 REST API", "benchmark_m13.py"),
    ("M14 WebSockets", "benchmark_m14.py"),
    ("M16 analytics", "benchmark_m16.py"),
    ("M17 reports", "benchmark_m17.py"),
)
# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------


def _percentile(values: Sequence[float], percentile: float) -> float:
    """Return the ``percentile``-th value of ``values`` (nearest rank).

    Nearest rank rather than an interpolated percentile: with five to twenty
    samples an interpolated figure is a number no run actually produced, and the
    tail is the thing worth reporting, so the observed one is the honest answer.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(round(percentile / 100.0 * len(ordered)))))
    return ordered[rank - 1]


@dataclass(frozen=True)
class Sample:
    """One measured operation, as the figures a report can compare (M18.10).

    ``values`` are the per-iteration measurements in the sample's own unit.
    ``higher_is_better`` exists so the deviation report knows which direction is
    worse: packets per second slowing down and a request latency slowing down are
    the same problem with the arithmetic the other way round, and a comparison
    that got it backwards would report an improvement as a regression.
    """

    name: str
    unit: str
    values: list[float] = field(default_factory=list)
    higher_is_better: bool = False

    @property
    def count(self) -> int:
        """Return how many timed iterations produced this sample."""
        return len(self.values)

    @property
    def median(self) -> float:
        """Return the median. The headline: one slow iteration moves the mean."""
        return statistics.median(self.values) if self.values else 0.0

    @property
    def mean(self) -> float:
        """Return the arithmetic mean, printed beside the median."""
        return statistics.fmean(self.values) if self.values else 0.0

    @property
    def p95(self) -> float:
        """Return the 95th percentile, which is the tail a user can feel."""
        return _percentile(self.values, 95.0)

    @property
    def worst(self) -> float:
        """Return the slowest single iteration."""
        return max(self.values) if self.values else 0.0

    @property
    def best(self) -> float:
        """Return the fastest single iteration."""
        return min(self.values) if self.values else 0.0


def _measure(
    call: Callable[[], None], *, iterations: int, warmup: int = 1
) -> list[float]:
    """Time ``call`` ``iterations`` times, after discarding ``warmup`` runs.

    The warm-up runs execute in full and are thrown away: the first request pays
    for lazy imports and the first packet pays for the statistics window, and a
    figure including either would not be about steady state. Returning the
    per-iteration times rather than a total is what lets the report show a tail.
    """
    for _ in range(max(0, warmup)):
        call()
    timings: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        call()
        timings.append(time.perf_counter() - started)
    return timings


def _milliseconds(seconds: Sequence[float]) -> list[float]:
    """Convert a list of second-durations into milliseconds."""
    return [value * 1000.0 for value in seconds]


# ---------------------------------------------------------------------------
# The environment, because a figure without one means nothing (M18.10)
# ---------------------------------------------------------------------------


def _environment() -> dict[str, str]:
    """Return the hardware and software the figures were taken on (M18.10)."""
    import sqlite3

    return {
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "machine": platform.machine() or "unknown",
        "processor": platform.processor() or "unknown",
        "cpu_count": str(os.cpu_count() or 0),
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "sqlite": sqlite3.sqlite_version,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _heading(title: str) -> None:
    """Print a section heading."""
    print()
    print(title)
    print("-" * len(title))


def _print_environment(environment: dict[str, str]) -> None:
    """Print the environment record as a table (M18.10)."""
    _heading("Environment")
    width = max(len(key) for key in environment)
    for key, value in environment.items():
        print(f"  {key.ljust(width)}  {value}")


def _print_table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    """Print a fixed-width table, sized to its own contents."""
    if not rows:
        return
    widths = [len(cell) for cell in header]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    def line(cells: Sequence[str]) -> str:
        return "  " + "  ".join(
            cell.ljust(widths[index]) for index, cell in enumerate(cells)
        )
    print(line(header))
    print("  " + "  ".join("-" * width for width in widths))
    for row in rows:
        print(line(row))


SAMPLE_HEADER = ("operation", "unit", "n", "median", "p95", "mean", "best", "worst")


def _sample_row(sample: Sample) -> tuple[str, ...]:
    """Render one sample as a report row (M18.10)."""
    return (
        sample.name,
        sample.unit,
        str(sample.count),
        f"{sample.median:.2f}",
        f"{sample.p95:.2f}",
        f"{sample.mean:.2f}",
        f"{sample.best:.2f}",
        f"{sample.worst:.2f}",
    )


def _print_samples(samples: Sequence[Sample]) -> None:
    """Print every sample in one table (M18.10)."""
    _heading("Measurements")
    _print_table(SAMPLE_HEADER, [_sample_row(sample) for sample in samples])


# ---------------------------------------------------------------------------
# The baseline a later run compares against (M18.10)
# ---------------------------------------------------------------------------


def _load_baseline(path: Path) -> dict[str, Any]:
    """Read a saved baseline, or return an empty record (M18.10).

    A baseline that cannot be read is reported as absent rather than raised on: a
    missing or malformed local file is no reason to refuse to measure. It must not
    be silently treated as a match either, which is why the caller prints which of
    the two happened.
    """
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _save_baseline(
    path: Path, samples: Sequence[Sample], environment: dict[str, str]
) -> None:
    """Write this run's medians and environment as the next run's baseline (M18.10)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "environment": environment,
        "samples": {
            sample.name: {
                "unit": sample.unit,
                "median": sample.median,
                "p95": sample.p95,
                "count": sample.count,
                "higher_is_better": sample.higher_is_better,
            }
            for sample in samples
        },
    }
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"\nBaseline written: {path}")


def _deviation_lines(samples: Sequence[Sample], baseline: dict[str, Any]) -> list[str]:
    """Return one line per sample comparing it with a saved baseline (M18.10).

    The comparison is a *report*, not a check: a slower figure is stated with the
    percentage, the direction, and the environment the baseline was taken on, so a
    reader can judge it. Nothing here can fail the run.
    """
    saved = baseline.get("samples")
    if not isinstance(saved, dict) or not saved:
        return []
    lines: list[str] = []
    saved_environment = baseline.get("environment")
    if isinstance(saved_environment, dict):
        lines.append(
            f"  baseline taken on: {saved_environment.get('processor', 'unknown')} / "
            f"{saved_environment.get('python', 'unknown')} / "
            f"{saved_environment.get('captured_at', 'unknown time')}"
        )
    for sample in samples:
        previous = saved.get(sample.name)
        if not isinstance(previous, dict):
            lines.append(f"  {sample.name}: no baseline value recorded")
            continue
        before = previous.get("median")
        if not isinstance(before, (int, float)) or before == 0:
            lines.append(f"  {sample.name}: baseline value unusable ({before!r})")
            continue
        after = sample.median
        change = (after - before) / float(before) * 100.0
        worse = change > 0 if not sample.higher_is_better else change < 0
        notable = abs(change) >= NOTABLE_DEVIATION_PERCENT
        verdict = "worse" if worse else "better"
        flag = "  <-- notable" if notable else ""
        lines.append(
            f"  {sample.name}: {before:.2f} -> {after:.2f} {sample.unit} "
            f"({change:+.1f}%, {verdict}){flag}"
        )
    return lines
# ---------------------------------------------------------------------------
# The traffic the pipeline is measured over (M18.10)
# ---------------------------------------------------------------------------

_ETHERNET_SRC = "AA:BB:CC:00:11:22"
_ETHERNET_DST = "AA:BB:CC:00:11:33"

#: The public destination ordinary flows are aimed at. TEST-NET-3 (RFC 5737), so
#: nothing here addresses a host that could exist on a real network.
_PUBLIC_DESTINATION = "203.0.113.9"

#: Ports ordinary flows use: 443 and 53 so protocol identification has a
#: well-known port to name, and a rotating high port so conversations are distinct
#: rather than one entry being updated forever.
_HTTPS_PORT = 443
_DNS_PORT = 53
_DNS_SERVER = "192.168.1.1"

#: Base client port. High enough to stay in the ephemeral range and clear of the
#: well-known ports, so a flow's client end is unambiguous.
_CLIENT_PORT_BASE = 40000


def _flow_index(index: int) -> tuple[str, int]:
    """Return the (source address, source port) of the ``index``-th packet (M18.10).

    Both come from one counter modulo the conversation set, so the run cycles
    through exactly ``DISTINCT_SOURCES * PORTS_PER_SOURCE`` conversations instead of
    inventing a fresh one for every packet.

    That bound is what makes the memory figure mean something. Device discovery and
    connection tracking still do their real work -- a new device the first time, an
    update afterwards -- but their registries stop growing once the set is covered.
    With an unbounded set of fresh conversations the traced growth would be the size
    of the input rather than anything about the code, and a real leak could hide
    inside a number that looked entirely ordinary.
    """
    # One fixed /24, so the pool really is ``DISTINCT_SOURCES`` addresses. Spreading
    # them would add nothing: what matters is that they are distinct and that the
    # last octet stays a valid host address.
    source = f"10.20.0.{1 + index % DISTINCT_SOURCES}"
    port = _CLIENT_PORT_BASE + (index // DISTINCT_SOURCES) % PORTS_PER_SOURCE
    return source, port


def _ordinary_packets(count: int) -> list[Any]:
    """Return ``count`` packets of the kind a capture session mostly sees (M18.10).

    Three shapes, because a pipeline that only ever saw one would have half its
    branches cold: a TCP flow toward a public web port, a UDP query to the local
    resolver, and an ICMP echo every thirteenth packet — often enough to keep that
    path warm without distorting the mix.
    """
    packets: list[Any] = []
    for index in range(count):
        source, sport = _flow_index(index)
        if index % 13 == 12:
            packets.append(
                Ether(src=_ETHERNET_SRC, dst=_ETHERNET_DST)
                / IP(src=source, dst=_PUBLIC_DESTINATION)
                / ICMP(type=8, id=index % 65536)
            )
        elif index % 3 == 0:
            packets.append(
                Ether(src=_ETHERNET_SRC, dst=_ETHERNET_DST)
                / IP(src=source, dst=_DNS_SERVER)
                / UDP(sport=sport, dport=_DNS_PORT)
                / b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            )
        else:
            packets.append(
                Ether(src=_ETHERNET_SRC, dst=_ETHERNET_DST)
                / IP(src=source, dst=_PUBLIC_DESTINATION)
                / TCP(sport=sport, dport=_HTTPS_PORT, flags="PA")
            )
    return packets


def _traffic_pool(count: int) -> list[Any]:
    """Return the reproducible packet set one iteration drives (M18.10).

    Identical on every run and every machine: the same addresses, the same ports,
    the same order. A measurement input that varied between runs could not show a
    regression, because the difference would be as likely to be the input as the
    code.

    The scan and the sweep are appended because they are the traffic that reaches
    M10, M11 and M12. Leaving them out would measure the M5-M9 path and quietly
    omit every layer M18.9 exists to verify.
    """
    packets = _ordinary_packets(count)
    for index in range(SCAN_SOURCES):
        packets.extend(lab._scan_packets(SCAN_PORTS, f"192.168.1.{10 + index}"))
    packets.extend(lab._sweep_packets(SWEEP_HOSTS, "192.168.1.99"))
    return packets


def _describe_inputs(count: int) -> None:
    """Print what the run drives, so the figures state their own conditions (M18.10)."""
    pool = count + SCAN_SOURCES * SCAN_PORTS + SWEEP_HOSTS
    _heading("Inputs and procedure")
    print(
        f"  packets per iteration   {pool} ({count} ordinary + "
        f"{SCAN_SOURCES * SCAN_PORTS} scan + {SWEEP_HOSTS} sweep)"
    )
    print(f"  distinct sources        {DISTINCT_SOURCES}")
    print(
        f"  conversations           {DISTINCT_SOURCES * PORTS_PER_SOURCE} "
        f"({DISTINCT_SOURCES} sources x {PORTS_PER_SOURCE} ports)"
    )
    print("  database                one throwaway SQLite file, removed afterwards")
    print(
        "  procedure               warm-up run discarded, then timed runs; "
        "median is the headline"
    )
    print(
        "  what is NOT measured    capture (no interface is opened), network "
        "transport, multi-process load"
    )


# ---------------------------------------------------------------------------
# Phase 1: the pipeline (M18.10)
# ---------------------------------------------------------------------------


def _phase_pipeline(
    stack: Any, packets: Sequence[Any], *, iterations: int, warmup: int
) -> list[Sample]:
    """Measure the real pipeline's sustained throughput (M18.10).

    One iteration is a whole pool driven through the stack, with persistence and
    connection state flushed at the end — the same call the M18.9 flow makes, so
    what is timed is a capture session's steady state rather than a loop over an
    in-memory counter.

    Returns:
        Two samples over the same timings: packets per second, and the per-packet
        cost in microseconds. Both are reported because "N packets a second" and
        "M microseconds each" answer different questions and a reader should not
        have to divide.
    """
    captured_at = time.time()
    durations = _measure(
        lambda: stack.capture(packets, captured_at),
        iterations=iterations,
        warmup=warmup,
    )
    total = len(packets)
    throughput = [total / value for value in durations if value > 0]
    per_packet = [value * 1_000_000.0 / total for value in durations]
    return [
        Sample(
            name="pipeline throughput",
            unit="packets/s",
            values=throughput,
            higher_is_better=True,
        ),
        Sample(name="pipeline per packet", unit="us", values=per_packet),
    ]


# ---------------------------------------------------------------------------
# Phases 2 and 3: the HTTP surface (M18.10)
# ---------------------------------------------------------------------------

#: The listing routes every request is timed against. The same set the M18.9 live
#: mode checks, so the surface that is measured is the surface that is verified.
_LISTING_ROUTES: tuple[tuple[str, str], ...] = (
    ("devices", lab.DEVICES_URL),
    ("connections", lab.CONNECTIONS_URL),
    ("detections", lab.DETECTIONS_URL),
    ("alerts", lab.ALERTS_URL),
    ("incidents", lab.INCIDENTS_URL),
    ("packets", lab.PACKETS_URL),
    ("dashboard", lab.DASHBOARD_URL),
    ("system status", lab.SYSTEM_URL),
)

#: The five M16 aggregate routes, measured separately because they query the store
#: rather than reading a table linearly, so folding them in with the listings would
#: average two different costs into one figure.
_ANALYTICS_ROUTES: tuple[tuple[str, str], ...] = (
    ("analytics traffic", lab.TRAFFIC_URL),
    ("analytics protocols", lab.PROTOCOLS_URL),
    ("analytics devices", lab.ANALYTICS_DEVICES_URL),
    ("analytics connections", lab.ANALYTICS_CONNECTIONS_URL),
    ("analytics threats", lab.THREATS_URL),
)


def _phase_requests(
    client: Any,
    routes: Sequence[tuple[str, str]],
    *,
    iterations: int,
    warmup: int,
    params: dict[str, str] | None = None,
) -> list[Sample]:
    """Time one request per route and return one millisecond sample each (M18.10).

    The status is checked and reported rather than raised on: the timing of a 500
    is not a latency figure, so a route that did not answer 200 has its real status
    printed by the caller instead of being measured as though it were healthy. A
    benchmark that silently timed error pages would be worse than no benchmark.

    Returns:
        One sample per route, in milliseconds, plus a final ``HTTP errors`` sample
        whose single value is the count of non-200 responses seen. That count is
        part of the result, not a decoration: if it is not zero, every latency
        beside it is suspect and the report says so in the same table.
    """
    samples: list[Sample] = []
    errors = 0
    for name, url in routes:
        def call(url: str = url) -> None:
            client.get(url, params=params or None)

        # One probe outside the timing, so the count is not per-iteration noise.
        if client.get(url, params=params or None).status_code != 200:
            errors += 1
        samples.append(
            Sample(
                name=f"GET {name}",
                unit="ms",
                values=_milliseconds(
                    _measure(call, iterations=iterations, warmup=warmup)
                ),
            )
        )
    samples.append(Sample(name="HTTP errors", unit="count", values=[float(errors)]))
    return samples


def _phase_reports(
    client: Any, *, iterations: int, warmup: int, since: float, until: float
) -> list[Sample]:
    """Measure report generation and a download (M18.10).

    Generation is the most expensive measured operation and the only one that
    writes a file, so it is sampled on its own. The download is timed once per
    generated report: it reads an artifact whose size is fixed by the store, and
    looping it would measure the filesystem cache rather than the layer.

    Returns:
        A sample for CSV generation, one for PDF generation, and one for the CSV
        download — the last only when a generated report really is on the listing,
        because timing a download of nothing would be a fabricated figure.
    """
    body_base = {
        "report_type": lab.CUSTOM,
        "since": lab._iso_from_epoch(since),
        "until": lab._iso_from_epoch(until),
    }
    samples: list[Sample] = []
    errors = 0
    for label, report_format in (("CSV", "CSV"), ("PDF", "PDF")):
        body = dict(body_base, format=report_format)

        def call(body: dict[str, Any] = body) -> None:
            client.post(lab.GENERATE_URL, json=body)

        # A refused generation is timed like any other request, so its status is
        # counted and printed: a median over three 500s is not a generation cost,
        # and reporting one as though it were is the mistake this harness exists to
        # catch.
        if client.post(lab.GENERATE_URL, json=body).status_code != 201:
            errors += 1
        samples.append(
            Sample(
                name=f"generate {label}",
                unit="ms",
                values=_milliseconds(
                    _measure(call, iterations=iterations, warmup=warmup)
                ),
            )
        )
    samples.append(Sample(name="report errors", unit="count", values=[float(errors)]))

    listing = client.get(lab.REPORTS_URL)
    listing_body = listing.json() if listing.status_code == 200 else {}
    reports = ((listing_body.get("data") or {}).get("reports") or []) if listing_body else []
    download_id = reports[0].get("report_id") if reports else None
    if isinstance(download_id, int):
        url = f"{lab.REPORTS_URL}/{download_id}/download"

        def call_download() -> None:
            client.get(url)

        if client.get(url).status_code != 200:
            errors += 1
        samples.append(
            Sample(
                name="download CSV",
                unit="ms",
                values=_milliseconds(
                    _measure(call_download, iterations=iterations, warmup=warmup)
                ),
            )
        )
    return samples
# ---------------------------------------------------------------------------
# Phase 4: memory under sustained traffic (M18.10)
# ---------------------------------------------------------------------------


def _phase_memory(
    stack: Any, packets: Sequence[Any], *, repetitions: int
) -> list[tuple[str, str]]:
    """Measure Python-level allocation growth across sustained traffic (M18.10).

    ``tracemalloc`` traces Python allocations, which is the honest scope of this
    figure and the reason it is labelled as such: a buffer allocated inside a C
    extension — SQLite's page cache, a socket buffer — does not pass through the
    allocator ``tracemalloc`` hooks, so a process could grow while this number
    stayed flat. A figure visible here is certainly real; a flat one is a useful
    negative result rather than proof of no growth anywhere.

    The per-packet figure is the one worth watching: a fixed cost per run is
    warm-up, a cost per packet is a leak.
    """
    total = len(packets) * repetitions
    per_repetition: list[int] = []
    tracemalloc.start()
    try:
        before, _ = tracemalloc.get_traced_memory()
        previous = before
        for _ in range(repetitions):
            stack.capture(packets, time.time())
            current, _ = tracemalloc.get_traced_memory()
            per_repetition.append(current - previous)
            previous = current
        after, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    delta = after - before
    later = per_repetition[1:]
    later_mean = statistics.fmean(later) if later else 0.0
    tail = per_repetition[-1] if per_repetition else 0
    rows = [
        ("packets driven", f"{total}"),
        ("traced before", f"{before / 1024.0:.1f} KiB"),
        ("traced after", f"{after / 1024.0:.1f} KiB"),
        ("traced peak", f"{peak / 1024.0:.1f} KiB"),
        ("growth across phase", f"{delta / 1024.0:+.1f} KiB"),
        ("growth per packet (all)", f"{delta / total / 1024.0 * 1024.0:+.1f} bytes"),
    ]
    # Per repetition, not only as a total: the first repetition fills a bounded
    # working set -- every device and every conversation the run will ever mention
    # is created in it -- and the later ones re-visit that set. Reporting only the
    # average would mix a one-off cost into a figure a reader would take for a
    # per-packet rate, which is exactly how a bounded set gets mistaken for a leak.
    for index, growth in enumerate(per_repetition, start=1):
        rows.append((f"repetition {index}", f"{growth / 1024.0:+.1f} KiB"))
    rows.append(("later repetitions (mean)", f"{later_mean / 1024.0:+.1f} KiB"))
    rows.append(("last repetition", f"{tail / 1024.0:+.1f} KiB"))
    rows.append(
        (
            "reading",
            "a first repetition larger than the rest is the working set being "
            "filled; later ones growing proportionally would indicate a leak",
        )
    )
    rows.append(
        (
            "scope",
            "Python allocations only (tracemalloc); native allocations are not traced",
        )
    )
    return rows


# ---------------------------------------------------------------------------
# The earlier milestones' own benchmarks, which this file does not re-implement
# ---------------------------------------------------------------------------


def _recorded_line(output: str) -> str:
    """Return a benchmark's own recorded-baseline line, or a note (M18.10).

    Each milestone benchmark prints a line beginning ``Recorded`` naming the
    baseline it just took. Quoting that line, rather than parsing the tables of
    eleven different scripts, is what keeps this harness from depending on eleven
    layouts — and it is the line the milestone documents quote too.
    """
    for line in reversed(output.splitlines()):
        if line.startswith("Recorded"):
            return line.strip()
    return "(no 'Recorded' line was printed)"


def _run_milestone_benchmarks(python: str) -> list[tuple[str, str, str]]:
    """Run each earlier milestone's benchmark and report its own result (M18.10).

    Each runs as a child process, so it builds whatever store it needs and its
    figures stay its own. This harness adds no interpretation beyond the exit
    status and the line the script printed itself. A script that exits non-zero is
    reported exactly as that, and is never counted as a measured layer.
    """
    rows: list[tuple[str, str, str]] = []
    for label, script in MILESTONE_BENCHMARKS:
        path = _SCRIPTS_DIR / script
        if not path.is_file():
            rows.append((label, "MISSING", f"{script} is not present"))
            continue
        try:
            completed = subprocess.run(
                [python, str(path)],
                cwd=_BACKEND_ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as error:
            rows.append((label, "ERROR", f"could not be started: {error}"))
            continue
        status = "ok" if completed.returncode == 0 else f"exit {completed.returncode}"
        rows.append((label, status, _recorded_line(completed.stdout)))
    return rows


# ---------------------------------------------------------------------------
# Reporting the run
# ---------------------------------------------------------------------------


def _print_notes() -> None:
    """Print how to read the figures, so the report cannot mislead (M18.10)."""
    _heading("How to read this")
    print("  * The median is the headline: one slow iteration moves the mean, not it.")
    print("  * p95 is the tail. With this many samples it is the slowest run or two,")
    print("    stated as such rather than smoothed into a mean.")
    print("  * Latencies are in-process, through TestClient: the application's own")
    print("    request cost, with no network and no browser in the measurement.")
    print("  * A higher number is not a failure. Nothing here fails the run; a")
    print("    deviation is reported beside the environment it was measured on,")
    print("    because two machines are not comparable.")
    print("  * These are development-machine figures. They are not a capacity claim.")


def _parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Build and parse the command line (M18.10)."""
    parser = argparse.ArgumentParser(
        prog="benchmark_m18.py",
        description="Measure the whole NetWatch AI pipeline as M18 runs it (M18.10).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The exit status is 0 when the run measured everything it selected. "
            "It is never non-zero because a figure was slow."
        ),
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=DEFAULT_PACKETS,
        help=f"ordinary packets per iteration (default: {DEFAULT_PACKETS})",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"timed iterations per measurement (default: {DEFAULT_ITERATIONS})",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP,
        help=f"warm-up iterations discarded (default: {DEFAULT_WARMUP})",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help=f"baseline file to read (default: {DEFAULT_BASELINE.name})",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="write this run's medians to the baseline file for a later run to compare",
    )
    parser.add_argument(
        "--milestones",
        action="store_true",
        help="also run the M6-M17 benchmarks, each in its own process",
    )
    parser.add_argument(
        "--skip-reports",
        action="store_true",
        help="skip the report generation phase (the slowest part of the run)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _run(args: argparse.Namespace) -> int:
    """Measure everything selected and report it (M18.10)."""
    print("=" * 78)
    print("M18 performance regression -- the whole pipeline, as M18 runs it (M18.10)")
    print("=" * 78)

    environment = _environment()
    _print_environment(environment)
    _describe_inputs(args.packets)

    workdir = Path(tempfile.mkdtemp(prefix="netwatch_bench_m18_"))
    db_engine = None
    try:
        db_path = workdir / "bench_m18.db"
        db_engine, factory = lab._connect_database(db_path)
        lab._seed_rule_catalogue(factory)
        stack = lab._build_stack(factory)
        packets = _traffic_pool(args.packets)

        _heading("Phase 1 -- the pipeline (M5-M12)")
        pipeline_samples = _phase_pipeline(
            stack, packets, iterations=args.iterations, warmup=args.warmup
        )
        _print_samples(pipeline_samples)

        holder = lab._StorageHolder(workdir / "reports")
        holder.directory.mkdir(parents=True, exist_ok=True)
        now = time.time()

        with lab._serve(stack, factory, db_engine, holder) as client:
            _heading("Phase 2 -- the REST surface (M13)")
            api_samples = _phase_requests(
                client, _LISTING_ROUTES, iterations=API_ITERATIONS, warmup=API_WARMUP
            )
            _print_samples(api_samples)

            _heading("Phase 3 -- analytics (M16)")
            window = {
                "since": lab._iso_from_epoch(now - 3600.0),
                "until": lab._iso_from_epoch(now + 3600.0),
            }
            analytics_samples = _phase_requests(
                client,
                _ANALYTICS_ROUTES,
                iterations=API_ITERATIONS,
                warmup=API_WARMUP,
                params=window,
            )
            _print_samples(analytics_samples)

            report_samples: list[Sample] = []
            if not args.skip_reports:
                _heading("Phase 4 -- reporting (M17)")
                report_samples = _phase_reports(
                    client,
                    iterations=REPORT_ITERATIONS,
                    warmup=REPORT_WARMUP,
                    since=now - 3600.0,
                    until=now,
                )
                _print_samples(report_samples)

        _heading("Phase 5 -- memory under sustained traffic")
        memory_rows = _phase_memory(stack, packets, repetitions=max(1, args.iterations))
        _print_table(("measurement", "value"), memory_rows)

        samples = [
            *pipeline_samples,
            *api_samples,
            *analytics_samples,
            *report_samples,
        ]

        if args.milestones:
            _heading("The earlier milestones' own benchmarks (M18.10)")
            rows = _run_milestone_benchmarks(sys.executable)
            _print_table(("benchmark", "result", "its own baseline line"), rows)

        _heading("Comparison with the recorded baseline")
        baseline = _load_baseline(args.baseline)
        if not baseline:
            print(f"  no baseline at {args.baseline}")
            print("  this run is the baseline; re-run with --save-baseline to record it")
        else:
            for line in _deviation_lines(samples, baseline):
                print(line)
        if args.save_baseline:
            _save_baseline(args.baseline, samples, environment)

        _print_notes()
        print()
        print("RESULT: measured")
        return 0
    finally:
        if db_engine is not None:
            db_engine.dispose()
        shutil.rmtree(workdir, ignore_errors=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the harness and return the process exit code (M18.10)."""
    args = _parse_arguments(argv)
    if args.packets <= 0:
        print("--packets must be positive", file=sys.stderr)
        return 1
    if args.iterations <= 0:
        print("--iterations must be positive", file=sys.stderr)
        return 1
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
