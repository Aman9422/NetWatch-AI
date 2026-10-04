"""M14 performance baseline — the live WebSocket layer (M14.33).

M14.33 names eight things to measure, and this script measures exactly those and
nothing else. Each figure answers one line of the milestone:

* **connection setup time** — how long a handshake costs, per channel;
* **broadcast latency** (publish → the client has it) and **messages/second**,
  per channel, from the benchmark's own thread through the real
  ``call_soon_threadsafe`` handoff, the real fan-out and the real sender task;
* **packet event throughput with and without the packet channel connected** —
  five rungs of the same pipeline, from the publish call replaced outright to a
  live subscriber draining, so the cost of each step is a difference between two
  measured rows rather than an inference. The rungs separate what *building* an
  event costs per packet from what *delivering* one costs;
* **alert event latency** — the ``alerts`` channel carrying an ``alert.created``
  event the run's own detection actually produced;
* **queue depth high-water mark and drop counts under an overrun** — measured
  against a client that deliberately never drains, because a client that drains
  never lets a bounded queue reach its cap;
* **the pipeline's own packet rate with WebSocket publishing enabled versus the
  same run with it disabled** — the outer rows of the same ladder, which is the
  only honest way to state M14's cost;
* **process CPU and RSS across the run**;
* **simultaneous test clients** — how many can be connected and served at once,
  and what connecting them costs.

**What is deliberately not measured.** The M4–M12 work each packet causes —
normalization, statistics, device discovery, connection tracking, detection,
alerting, correlation — is measured by *that* milestone's baseline, and
``benchmark_m13.py`` established the same rule for the API. Those layers run here
because the pipeline cannot otherwise produce a real event, but every figure is
reported as a *difference* against the same pipeline with publishing off, so the
shared cost cancels and what is left is the WebSocket layer's share.

**This is a local, single-machine baseline, not a capacity claim.** It is one
process, one event loop, one in-process client over a throwaway SQLite file. The
only stack below the socket is a function call, so the absolute numbers are far
more optimistic than a deployed service would see. What they are good for is
comparing channels against each other, comparing the layer against having no
layer, and re-measuring after a change: the packet pool is generated, not random,
so two runs of this script are comparable.

**The keepalive and the dashboard tick are off for the run.** Both publish on
their own timer, and a frame that arrived unasked-for would be timed as though it
were the frame the measurement sent. Their behaviour is M14.9's and M14.24's to
verify, and ``verify_m14.py`` does; here the transport is isolated so a latency
figure means one thing.

Usage (from the backend/ directory):

    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m14.py
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m14.py --packets 5000
    & ".venv\\Scripts\\python.exe" scripts\\benchmark_m14.py --iterations 100
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import math
import platform
import statistics as stats
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Make the backend root — and this script's own directory, for the harness —
# importable when run as a plain script.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = Path(__file__).resolve().parent
for _path in (str(_SCRIPTS_DIR), str(_BACKEND_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import psutil  # noqa: E402

import m14_bench_harness as harness  # type: ignore[import-not-found]  # noqa: E402
from app.websockets import builders, get_event_publisher, reset_websockets  # noqa: E402
from app.websockets.channels import CHANNEL_PATHS, CHANNELS, Channel  # noqa: E402
from app.websockets.dashboard import sample_dashboard  # noqa: E402
from app.websockets.event import (  # noqa: E402
    WebSocketEvent,
    encoded_size,
    iso_utc,
    next_sequence,
)
from app.websockets.event import EventType  # noqa: E402
from app.websockets.manager import WebSocketManager  # noqa: E402
from app.websockets.publisher import (  # noqa: E402
    NullEventPublisher,
    WebSocketEventPublisher,
)

_BANNER_WIDTH = 78

#: Repeated measurements discarded before timing starts, per case. The first
#: publish to a channel pays for lazy work — the registry snapshot, the connection
#: lookup, the first encode of a payload shape — which is a once-per-process cost
#: and would otherwise be reported as the channel's latency.
_WARMUP = 3

#: How many channels the "simultaneous clients" phase targets by default. Four
#: channels times this is the client count, kept well inside the configured caps.
DEFAULT_CLIENTS_PER_CHANNEL = 4

#: The overrun phase broadcasts this many events at a client that never drains.
#: Comfortably past every channel's queue cap (32 to 512), so the drop policy is
#: certainly reached, and small enough that the run stays quick.
OVERRUN_EVENTS = 2000

#: How long a rate measurement waits after its window for the last frames to
#: arrive. Short, because a frame that has not reached the client within this long
#: after the publisher stopped is not part of the burst that was just measured.
_RATE_QUIET_SECONDS = 0.3

_LOGGER_NAME = "netwatch.benchmark.m14"


# -- statistics ---------------------------------------------------------------


@dataclass
class Sample:
    """One measured case: what it was, what it carried, and how long it took.

    ``milliseconds`` holds one entry per timed unit — a request, a publish that was
    received, a whole burst — so the percentiles describe the same population for
    every table. ``detail`` carries the number a reader needs to interpret the
    figure: bytes for a payload, delivered-versus-offered counts for a burst.
    """

    label: str
    detail: str = ""
    rows: int | None = None
    milliseconds: list[float] = field(default_factory=list)

    @property
    def count(self) -> int:
        """Return how many timed units this sample holds."""
        return len(self.milliseconds)

    @property
    def mean(self) -> float:
        """Return the mean time in milliseconds."""
        return stats.fmean(self.milliseconds) if self.milliseconds else 0.0

    @property
    def median(self) -> float:
        """Return the median time in milliseconds.

        The median is the headline figure: a mean is moved by a single slow unit,
        and on a machine doing anything else at the time that is the norm rather
        than the exception.
        """
        return stats.median(self.milliseconds) if self.milliseconds else 0.0

    @property
    def p95(self) -> float:
        """Return the 95th-percentile time in milliseconds."""
        return _percentile(self.milliseconds, 95.0)

    @property
    def worst(self) -> float:
        """Return the slowest time in milliseconds."""
        return max(self.milliseconds) if self.milliseconds else 0.0

    @property
    def per_second(self) -> float:
        """Return how many timed units per second the whole sample sustained.

        Derived from the sum of the individual times rather than from a wall-clock
        span around the loop, so it describes the same units the percentiles do and
        excludes the setup between cases.
        """
        total = sum(self.milliseconds) / 1000.0
        return self.count / total if total > 0.0 else 0.0


def _percentile(values: Sequence[float], fraction: float) -> float:
    """Return the ``fraction``-th percentile of ``values`` (nearest rank)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = math.ceil(fraction / 100.0 * len(ordered))
    return ordered[min(max(rank - 1, 0), len(ordered) - 1)]


def _time_call(call: Callable[[], Any]) -> float:
    """Return one call's wall time in milliseconds."""
    start = time.perf_counter()
    call()
    return (time.perf_counter() - start) * 1000.0


def _print_table(title: str, samples: Sequence[Sample]) -> None:
    """Print one phase's figures as a table, all in milliseconds.

    The median is printed first because it is the figure to quote. A row with no
    timed units prints dashes rather than zeros, so "not measured" cannot be read
    as "instant".
    """
    print("\n" + "-" * _BANNER_WIDTH)
    print(title)
    print("-" * _BANNER_WIDTH)
    print(
        f"  {'case':<38} {'detail':>9}  {'n':>5}  "
        f"{'p50':>8} {'mean':>8} {'p95':>8} {'max':>8} {'/s':>9}"
    )
    for sample in samples:
        if not sample.milliseconds:
            print(f"  {sample.label:<38} {sample.detail:>9}  {'-':>5}  " + "-" * 40)
            continue
        print(
            f"  {sample.label:<38} {sample.detail:>9}  {sample.count:>5}  "
            f"{sample.median:>8.3f} {sample.mean:>8.3f} {sample.p95:>8.3f} "
            f"{sample.worst:>8.3f} {sample.per_second:>9,.0f}"
        )


@dataclass
class Rate:
    """What one channel let through while a publisher sent flat out (M14.33).

    ``published`` is how many events the publisher handed over in the window and
    ``delivered`` how many the client actually received. The two are reported
    together on purpose: a delivered count alone cannot say whether the channel or
    the publisher was the limit, and the answer is different on every channel.
    """

    channel: str
    published: int
    delivered: int
    seconds: float
    ceiling: float | None = None

    @property
    def per_second(self) -> float:
        """Return delivered events per second over the window."""
        return self.delivered / self.seconds if self.seconds > 0.0 else 0.0

    @property
    def published_per_second(self) -> float:
        """Return offered events per second, which is the publisher's own rate."""
        return self.published / self.seconds if self.seconds > 0.0 else 0.0

    @property
    def dropped(self) -> int:
        """Return how many published events the client never saw."""
        return max(0, self.published - self.delivered)


def _print_rates(title: str, rates: Sequence[Rate]) -> None:
    """Print offered against delivered for each channel (M14.33).

    The ``ceiling`` column is the configured rate limit, printed beside the result
    so a channel that delivered far less than it was offered is not read as a
    transport fault when it is the throttle working as designed. Where the ceiling
    is ``none`` and delivery still lags, the bound is the client's own drain rate.
    """
    print("\n" + "-" * _BANNER_WIDTH)
    print(title)
    print("-" * _BANNER_WIDTH)
    print(
        f"  {'channel':<12} {'offered/s':>11} {'delivered/s':>12} "
        f"{'delivered':>10} {'dropped':>9} {'window s':>9} {'ceiling':>9}"
    )
    for rate in rates:
        ceiling = "none" if rate.ceiling is None else f"{rate.ceiling:,.0f}"
        print(
            f"  {rate.channel:<12} {rate.published_per_second:>11,.0f} "
            f"{rate.per_second:>12,.0f} {rate.delivered:>10,} "
            f"{rate.dropped:>9,} {rate.seconds:>9.2f} {ceiling:>9}"
        )


# -- event factories ----------------------------------------------------------

#: The channel each builder produces for, so a latency case can name an event
#: without a lookup table repeated at every call site.
def _reissue(event: WebSocketEvent, *, timestamp: float | None = None) -> WebSocketEvent:
    """Return a fresh envelope carrying a recorded event's type and payload.

    The payload and the type come from an event the run's own pipeline produced, so
    the latency case measures the real ``packet.observed`` or ``alert.created``
    shape. The envelope is rebuilt so each send carries its own id, sequence and
    timestamp: re-sending one identical event would give every frame the same
    ``event_id``, which is not a thing the transport ever does and would invite a
    client to deduplicate the samples.
    """
    moment = time.time() if timestamp is None else timestamp
    return WebSocketEvent(
        type=event.type,
        channel=event.channel,
        source=event.source,
        timestamp=iso_utc(moment) or "",
        sequence=next_sequence(),
        data=event.data,
    )


def _payload_event(channel: Channel, stack: harness.LabStack) -> WebSocketEvent:
    """Return one representative event for ``channel``, from the real builders.

    Every case uses the production builder for its channel:

    * ``packets`` — a ``packet.observed`` the run's pipeline really produced, so
      the payload is a real M5 projection rather than a stand-in;
    * ``alerts`` — an ``alert.created`` the run's detection really raised, the same
      way: the payload is the M11 alert view the wire would carry;
    * ``dashboard`` — a tick built from the services, read exactly as the tick
      reads them. Its *values* therefore describe an idle process, because the
      run's own stack is not installed as the process services; its *shape and
      size* are the tick's own, which is what a transport measurement needs from
      the payload;
    * ``system`` — a service state change, built by its own builder.

    Raises:
        AssertionError: If the run has not yet produced the event a channel needs,
            because measuring a channel with a hand-made payload would be measuring
            something else.
    """
    if channel is Channel.PACKETS:
        recorded = stack.recording.of_type(EventType.PACKET_OBSERVED, limit=1)
        if not recorded:
            raise AssertionError("no packet.observed was published to measure with")
        return _reissue(recorded[0])
    if channel is Channel.ALERTS:
        recorded = stack.recording.of_type(EventType.ALERT_CREATED, limit=1)
        if not recorded:
            raise AssertionError("no alert.created was published to measure with")
        return _reissue(recorded[0])
    if channel is Channel.DASHBOARD:
        return builders.dashboard_event(timestamp=time.time(), **sample_dashboard())  # type: ignore[arg-type]
    return builders.service_event("benchmark", "running")


# -- phase: connection setup --------------------------------------------------


def _phase_connect(client: Any, iterations: int) -> list[Sample]:
    """Measure what a handshake costs on each channel (M14.33).

    The timed unit is the whole ``with`` block — accept, admit, register, start the
    sender task, then the close and the unregister — because that is what a client
    and the server actually pay per session. A handshake measured only up to
    ``accept`` would leave out the task creation and the cleanup, which are the
    parts M14 adds.
    """
    samples: list[Sample] = []
    for channel in CHANNELS:
        path = CHANNEL_PATHS[channel]
        times: list[float] = []
        for _ in range(_WARMUP):
            with client.websocket_connect(path):
                pass
        for _ in range(iterations):
            start = time.perf_counter()
            with client.websocket_connect(path):
                pass
            times.append((time.perf_counter() - start) * 1000.0)
        samples.append(
            Sample(
                label=f"{path}",
                detail=f"queue {harness.process_manager().policies.queue_size(channel)}",
                milliseconds=times,
            )
        )
    return samples


# -- phase: broadcast latency and message rate --------------------------------


def _measure_latency(
    publisher: Any,
    reader: harness.SocketReader,
    build: Callable[[], WebSocketEvent],
    *,
    iterations: int,
    minimum_gap_seconds: float,
) -> Sample:
    """Publish one event at a time and time it until the client has it (M14.33).

    The timed unit is one round trip: the publish call from this thread, the
    ``call_soon_threadsafe`` hop onto the loop, the fan-out, the queue, the sender
    task's write and the client's read. That is the whole path an event travels, and
    it is the path the capture thread uses, so the figure is what a live subscriber
    experiences rather than what a loop-side caller would.

    ``minimum_gap_seconds`` paces the sends where a channel is rate-limited. An
    event the rate limiter drops would never arrive, and waiting for it would turn a
    throttled channel into a timeout instead of a number.
    """
    event = build()
    for _ in range(_WARMUP):
        publisher.publish(build())
        reader.next_frame()
    times: list[float] = []
    last = 0.0
    for _ in range(iterations):
        if minimum_gap_seconds > 0.0:
            wait = minimum_gap_seconds - (time.perf_counter() - last)
            if wait > 0.0:
                time.sleep(wait)
        event = build()
        start = time.perf_counter()
        publisher.publish(event)
        reader.next_frame()
        times.append((time.perf_counter() - start) * 1000.0)
        last = time.perf_counter()
    return Sample(
        label=f"{reader.channel.value} latency",
        detail=f"{encoded_size(event)} B",
        milliseconds=times,
    )


def _measure_rate(
    publisher: Any,
    reader: harness.SocketReader,
    build: Callable[[], WebSocketEvent],
    *,
    window_seconds: float,
) -> Rate:
    """Publish flat out for a window and count what the client received (M14.33).

    The figure is *delivered events per second*, which is the only honest form of
    the claim. Publishing as fast as the process can and counting what came out
    measures whatever actually bounds the channel: the client's own drain rate
    where there is no ceiling, the token bucket on the packet channel, and the
    drop-oldest policy wherever the publisher outruns the sender.

    Nothing is paced, deliberately. A paced loop reports the rate this script
    chose to send at; this one reports the rate the channel let through when the
    publisher was not the limit.
    """
    for _ in range(_WARMUP):
        publisher.publish(build())
        reader.next_frame()
    reader.drain()
    policy = harness.process_manager().policies.policy(reader.channel)
    start = time.perf_counter()
    published = 0
    while time.perf_counter() - start < window_seconds:
        publisher.publish(build())
        published += 1
    seconds = time.perf_counter() - start
    delivered = len(reader.collect(quiet_seconds=_RATE_QUIET_SECONDS))
    return Rate(
        channel=reader.channel.value,
        published=published,
        delivered=delivered,
        seconds=seconds,
        ceiling=policy.max_events_per_second,
    )


def _phase_latency(
    client: Any, stack: harness.LabStack, iterations: int, window_seconds: float
) -> tuple[list[Sample], list[Rate]]:
    """Measure one round trip and the sustained rate, per channel (M14.33).

    All four channels are measured in one session with the background timers quiet,
    so the only frames in flight are the ones this function sends. The rate-limited
    packet channel is paced for the *latency* rows to its configured ceiling — an
    event the limiter dropped would never arrive and waiting for it would turn a
    throttled channel into a timeout — while the rate rows are unpaced, because
    pacing them would report this script's chosen send rate instead of the
    channel's own.
    """
    publisher = get_event_publisher()
    samples: list[Sample] = []
    rates: list[Rate] = []
    with contextlib.ExitStack() as sockets:
        readers: dict[Channel, harness.SocketReader] = {}
        for channel in CHANNELS:
            socket = sockets.enter_context(client.websocket_connect(CHANNEL_PATHS[channel]))
            reader = harness.SocketReader(socket, channel)
            reader.max_queue_hint = harness.process_manager().policies.queue_size(channel)
            readers[channel] = reader
        samples.extend(
            _measure_latency(
                publisher,
                readers[channel],
                lambda channel=channel: _payload_event(channel, stack),
                iterations=iterations,
                minimum_gap_seconds=_gap_for(channel),
            )
            for channel in CHANNELS
        )
        rates.extend(
            _measure_rate(
                publisher,
                readers[channel],
                lambda channel=channel: _payload_event(channel, stack),
                window_seconds=window_seconds,
            )
            for channel in CHANNELS
        )
    return samples, rates


def _gap_for(channel: Channel) -> float:
    """Return the minimum gap between sends for ``channel``, in seconds.

    Zero for a channel with no rate ceiling, and 1.5 tokens' worth of separation for
    the packet channel, so the token bucket is refilled before every send and the
    measurement describes the transport rather than the throttle.
    """
    ceiling = harness.process_manager().policies.policy(channel).max_events_per_second
    if ceiling is None or ceiling <= 0.0:
        return 0.0
    return 1.5 / float(ceiling)


# -- phase: the packet ladder -------------------------------------------------


@dataclass
class Rung:
    """One configuration of the packet path, and what it cost.

    ``milliseconds`` is the whole burst rather than one unit: a rung is a rate, and
    a rate is the only thing that compares across configurations.
    """

    label: str
    packets: int
    milliseconds: float
    detail: str = ""

    @property
    def seconds(self) -> float:
        """Return the burst's wall time in seconds."""
        return self.milliseconds / 1000.0

    @property
    def per_second(self) -> float:
        """Return how many packets per second the pipeline sustained."""
        return self.packets / self.seconds if self.seconds > 0.0 else 0.0

    @property
    def microseconds_each(self) -> float:
        """Return the average cost of one packet, in microseconds."""
        return (self.milliseconds * 1000.0) / self.packets if self.packets else 0.0


def _print_rungs(title: str, rungs: Sequence[Rung]) -> None:
    """Print the packet ladder, with each rung's difference from the first.

    The ``overhead`` column is the part of the rung that M14 accounts for: the
    difference against the first rung, where the pipeline's publish call is
    replaced outright and M14 therefore costs nothing. Printing it rather than
    leaving it to be subtracted by eye is what keeps the shared M4–M12 cost from
    being read as M14's.
    """
    print("\n" + "-" * _BANNER_WIDTH)
    print(title)
    print("-" * _BANNER_WIDTH)
    print(
        f"  {'configuration':<40} {'packets/s':>10} {'us/each':>9} "
        f"{'overhead us':>12}  outcome"
    )
    baseline = rungs[0].microseconds_each if rungs else 0.0
    for rung in rungs:
        overhead = rung.microseconds_each - baseline
        print(
            f"  {rung.label:<40} {rung.per_second:>10,.0f} "
            f"{rung.microseconds_each:>9.2f} {overhead:>12.2f}  {rung.detail}"
        )


def _counters_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    """Return ``after - before`` for every counter, so a phase owns its own run."""
    return {name: after.get(name, 0) - value for name, value in before.items()}


def _run_rung(
    label: str,
    *,
    db_path: Path,
    packets: Sequence[Any],
    passes: int,
    publisher: Any,
    detail: str = "",
) -> tuple[Rung, harness.LabStack]:
    """Drive ``packets`` through one pipeline configuration and time it (M14.33).

    Each rung gets its own stack over its own throwaway database, so a rung starts
    from the same empty state as every other and one rung cannot warm the next. The
    alert-producing warm-up runs *before* the timed burst: an alert has to exist for
    the latency phase to publish a real one, and paying for its detection inside the
    burst would charge the transport for a rule evaluation.

    Returns:
        The rung and the stack, so the caller can keep the events this
        configuration recorded.
    """
    engine, factory = harness.connect_database(db_path)
    harness.seed_rule_catalogue(factory)
    stack = harness.build_lab_stack(factory, publisher)
    stack.process(harness.scan_packets(8))
    stack.process(harness.sweep_packets(8))
    count = len(packets) * passes
    work = list(packets) * passes
    start = time.perf_counter()
    stack.process(work)
    elapsed = (time.perf_counter() - start) * 1000.0
    engine.dispose()
    return (
        Rung(label=label, packets=count, milliseconds=elapsed, detail=detail),
        stack,
    )


def _phase_packet_ladder(
    workdir: Path, packets: Sequence[Any], passes: int, connected: Any
) -> tuple[list[Rung], harness.LabStack]:
    """Measure the packet path at five publishing configurations (M14.33).

    The rungs climb from M14 costing nothing at all to M14 delivering to a live
    subscriber, and each adds exactly one step, so the cost of that step is the
    difference of two measured rows:

    1. **no publish call** — the pipeline's call site replaced by a no-op, which is
       the pipeline exactly as M4–M12 shipped it. This is the only rung where M14
       costs nothing; see rung 2 for why a null publisher is not the same thing;
    2. **null publisher** — the call is made and the event is *built*, then
       discarded. ``publish_packet`` projects the packet into a ``packet.observed``
       before it consults the publisher, so the difference from rung 1 is the cost
       of the projection alone;
    3. **publisher, layer disabled** — a real manager with ``enabled=False``, which
       is the master switch M14.16 documents. The projection still runs, and the
       manager refuses before doing anything else with it;
    4. **publisher, enabled, no subscriber** — a real enabled manager with nobody
       listening on the packet channel, which is a client watching only alerts. The
       event is offered and dropped for want of a subscriber;
    5. **publisher, enabled, one subscriber** — the same, with a subscriber
       connected and draining, so the frame is encoded, queued and written.

    The rungs therefore split M14's cost into the two halves worth knowing
    separately: rung 1 → 2 is what *building* an event costs per packet, and
    rung 2 → 5 is what *delivering* one costs.

    ``connected`` is called around the last rung so the caller can hold a socket
    open for it. Everything else is identical between rungs, including the packet
    pool and the number of packets, which is what makes the differences meaningful.
    """
    rungs: list[Rung] = []
    live_stack: harness.LabStack | None = None

    # The zero rung, and the only configuration where M14 costs nothing: the
    # pipeline's own call site is replaced, so no projection is built and no
    # publisher is consulted. Every later rung pays for the projection, because
    # ``publish_packet`` builds the event before it hands it over.
    with harness.suppressed_publishing():
        rung, stack = _run_rung(
            "1. no publish call (M14 absent)",
            db_path=workdir / "rung1.db",
            packets=packets,
            passes=passes,
            publisher=NullEventPublisher(),
            detail="call replaced",
        )
    rungs.append(rung)

    rung, stack = _run_rung(
        "2. null publisher (built, discarded)",
        db_path=workdir / "rung2.db",
        packets=packets,
        passes=passes,
        publisher=NullEventPublisher(),
    )
    rungs.append(rung)

    disabled = WebSocketEventPublisher(WebSocketManager(enabled=False))
    rung, stack = _run_rung(
        "3. publisher, layer disabled",
        db_path=workdir / "rung3.db",
        packets=packets,
        passes=passes,
        publisher=disabled,
    )
    rungs.append(rung)

    manager = harness.process_manager()
    before = manager.get_counters()
    rung, live_stack = _run_rung(
        "4. publisher, enabled, no subscriber",
        db_path=workdir / "rung4.db",
        packets=packets,
        passes=passes,
        publisher=get_event_publisher(),
        detail="no packet client",
    )
    after = manager.get_counters()
    delta = _counters_delta(before, after)
    rungs.append(
        Rung(
            label=rung.label,
            packets=rung.packets,
            milliseconds=rung.milliseconds,
            detail=(
                f"{delta.get('broadcast', 0):,} broadcast, "
                f"{delta.get('dropped_rate_limited', 0):,} rate-limited"
            ),
        )
    )

    before = manager.get_counters()
    with connected():
        rung, stack = _run_rung(
            "5. publisher, enabled, 1 subscriber",
            db_path=workdir / "rung5.db",
            packets=packets,
            passes=passes,
            publisher=get_event_publisher(),
        )
    after = manager.get_counters()
    delta = _counters_delta(before, after)
    rungs.append(
        Rung(
            label=rung.label,
            packets=rung.packets,
            milliseconds=rung.milliseconds,
            detail=(
                f"{delta.get('delivered', 0):,} delivered, "
                f"{delta.get('dropped_rate_limited', 0):,} rate-limited"
            ),
        )
    )
    if live_stack is None:  # pragma: no cover - rung 4 always produces one
        raise AssertionError("the live rung produced no stack to measure with")
    return rungs, live_stack


# -- phase: the overrun -------------------------------------------------------


def _print_overrun(rows: Sequence[dict[str, Any]]) -> None:
    """Print the bounded-buffer behaviour a stalled client forces (M14.15).

    ``depth`` above the cap would be a bug, and the assertion below makes that
    explicit rather than leaving a reader to compare two columns.
    """
    print("\n" + "-" * _BANNER_WIDTH)
    print(
        f"Bounded queue under an overrun - {OVERRUN_EVENTS:,} events, no drain "
        "(M14.15)"
    )
    print("-" * _BANNER_WIDTH)
    print(
        f"  {'channel':<12} {'cap':>6} {'depth':>7} {'offered':>9} "
        f"{'sent':>7} {'dropped':>9} {'rate-limited':>13}"
    )
    for row in rows:
        print(
            f"  {row['channel']:<12} {row['queue_size']:>6} "
            f"{row['depth_high_water']:>7} {row['offered']:>9,} "
            f"{row['sent']:>7,} {row['dropped_queue_full']:>9,} "
            f"{row['manager_dropped_rate_limited']:>13,}"
        )
        if int(row["depth_high_water"]) > int(row["queue_size"]):
            raise AssertionError(
                f"{row['channel']}: queue depth {row['depth_high_water']} exceeded "
                f"its cap of {row['queue_size']} (M14.15)"
            )


# -- phase: simultaneous clients ----------------------------------------------


@contextlib.contextmanager
def _holding(client: Any, channel: Channel) -> Any:
    """Hold one socket open for the duration of the ``with`` block (M14.33).

    The reader is created so the socket is drained: a subscriber that never read
    would let its bounded queue fill and the ladder's delivery count would describe
    back-pressure rather than the broadcast.
    """
    with client.websocket_connect(CHANNEL_PATHS[channel]) as socket:
        yield harness.SocketReader(socket, channel)


def _phase_clients(client: Any, per_channel: int, iterations: int) -> list[Sample]:
    """Measure connecting and serving many clients at once (M14.33).

    Two claims, one table. The **connect** rows time opening ``per_channel``
    clients on one channel and closing them, so the cost of admitting a socket is
    separated from the cost of having one. The **fan-out** rows hold every client
    open at once and time one publish until *all* of them have it, which is the
    case a dashboard with a hundred tabs actually exercises: the sender tasks run
    concurrently and the subscriber that finishes last sets the figure.

    The packet channel is paced in the fan-out case for the same reason as in the
    latency phase: it is rate-limited, and an event the limiter dropped would never
    arrive, so an unpaced fan-out would report a throttle as a timeout rather than
    as a number.
    """
    samples: list[Sample] = []
    manager = harness.process_manager()
    publisher = get_event_publisher()

    for channel in CHANNELS:
        times = [
            _time_call(lambda: _connect_once(client, channel))
            for _ in range(iterations)
        ]
        samples.append(
            Sample(
                label=f"connect {CHANNEL_PATHS[channel]}",
                detail=f"{per_channel} held",
                milliseconds=times,
            )
        )

    with contextlib.ExitStack() as stack:
        readers: dict[Channel, list[harness.SocketReader]] = {c: [] for c in CHANNELS}
        for channel in CHANNELS:
            for _ in range(per_channel):
                readers[channel].append(
                    harness.SocketReader(
                        stack.enter_context(
                            client.websocket_connect(CHANNEL_PATHS[channel])
                        ),
                        channel,
                    )
                )
        held = manager.get_connection_count()
        for channel in CHANNELS:
            for reader in readers[channel]:
                reader.drain()
            gap = _gap_for(channel)
            times = []
            last = 0.0
            for _ in range(iterations):
                if gap > 0.0:
                    wait = gap - (time.perf_counter() - last)
                    if wait > 0.0:
                        time.sleep(wait)
                event = _payload_event(channel, _CLIENT_STACK[0])
                start = time.perf_counter()
                publisher.publish(event)
                for reader in readers[channel]:
                    reader.next_frame()
                times.append((time.perf_counter() - start) * 1000.0)
                last = time.perf_counter()
            samples.append(
                Sample(
                    label=f"fan-out {channel.value}",
                    detail=f"{len(readers[channel])} clients",
                    milliseconds=times,
                )
            )
        print(f"\n  held {held} simultaneous connection(s) during the fan-out rows")
    return samples


#: The stack the client phase publishes with, set by :func:`main` before the phase
#: runs. A one-element list rather than a global rebind so the phase can read it
#: without taking a stack parameter it uses for nothing else.
_CLIENT_STACK: list[harness.LabStack] = []


def _connect_once(client: Any, channel: Channel) -> None:
    """Open and close one socket, measuring nothing itself."""
    with client.websocket_connect(CHANNEL_PATHS[channel]):
        pass


# -- process resources --------------------------------------------------------


def _resource_snapshot() -> tuple[float, float]:
    """Return the process's resident memory in MiB and its CPU seconds so far.

    Sampled around the packet ladder rather than continuously: the ladder is the
    only CPU-bound phase, and a sampler thread would perturb the very figure it was
    measuring.
    """
    process = psutil.Process()
    memory = process.memory_info()
    cpu = process.cpu_times()
    return memory.rss / (1024.0 * 1024.0), float(cpu.user) + float(cpu.system)


def _print_resources(
    label: str, before: tuple[float, float], after: tuple[float, float], packets: int
) -> None:
    """Print the RSS and CPU a phase cost (M14.33)."""
    rss_delta = after[0] - before[0]
    cpu_delta = after[1] - before[1]
    per_packet = (cpu_delta * 1_000_000.0) / packets if packets else 0.0
    print(
        f"  {label:<28} RSS {before[0]:>7.1f} -> {after[0]:>7.1f} MiB "
        f"({rss_delta:+.1f})  CPU {cpu_delta:>6.2f} s for {packets:,} packets "
        f"({per_packet:>6.2f} us/packet)"
    )


# -- header, policy and closing note ------------------------------------------


def _print_header(args: argparse.Namespace, pool: int) -> None:
    """Print what this run is, so a recorded baseline is self-describing."""
    print("=" * _BANNER_WIDTH)
    print("M14 performance baseline - the live WebSocket layer (M14.33)")
    print("=" * _BANNER_WIDTH)
    print(f"  packet pool        : {pool:,} distinct packets, cycled {args.passes}x")
    print(f"  iterations         : {args.iterations} timed unit(s) per case")
    print(f"  clients per channel: {args.clients}")
    print(f"  overrun events     : {OVERRUN_EVENTS:,} per channel")
    print(f"  rate window        : {args.window} s per channel")
    print(f"  python             : {platform.python_version()} ({platform.machine()})")
    print(f"  platform           : {platform.system()} {platform.release()}")
    print(
        "  note               : in-process client, one event loop, no network "
        "stack - a local baseline, not a capacity claim"
    )


def _print_policy() -> None:
    """Print the effective per-channel policy the figures were taken under.

    A latency figure without the queue depth and rate ceiling beside it cannot be
    compared with anything: a small queue is why a channel drops, and a ceiling is
    why a channel is paced.
    """
    manager = harness.process_manager()
    print("\n  effective policy (from settings)")
    print(
        f"    {'channel':<12} {'queue':>6} {'ceiling/s':>10} "
        f"{'priority':>10} {'enabled':>8}"
    )
    for channel in CHANNELS:
        policy = manager.policies.policy(channel)
        ceiling = (
            "none"
            if policy.max_events_per_second is None
            else f"{policy.max_events_per_second:,.0f}"
        )
        print(
            f"    {channel.value:<12} {policy.queue_size:>6} {ceiling:>10} "
            f"{policy.priority:>10} {str(policy.enabled):>8}"
        )


def _print_closing_note() -> None:
    """State plainly what the figures above are, and are not.

    A benchmark that does not say what it left out invites the numbers to be read
    as a throughput claim. This one is deliberately not that: it is one process,
    one loop, with the socket replaced by an in-process transport.
    """
    print("\n" + "=" * _BANNER_WIDTH)
    print("Read these as a local baseline, not as WebSocket capacity")
    print("=" * _BANNER_WIDTH)
    print("  * measured  : handshake cost, publish-to-client latency and rate per")
    print("                channel, the M14 cost of the packet path, bounded-queue")
    print("                depth and drops under an overrun, CPU and RSS, fan-out")
    print("                to many simultaneous clients")
    print("  * excluded  : the M4-M12 work each packet causes (each milestone has")
    print("                its own baseline), and any real network stack")
    print("  * transport : in-process (Starlette's TestClient), so no loopback cost")
    print("  * timers    : keepalive and dashboard tick quiet, so no extra frame")
    print("  * use       : compare channels, compare with and without the layer,")
    print("                and re-run after a change")


# -- command line -------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="M14 performance baseline for the WebSocket layer (M14.33)."
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=2000,
        help="distinct packets in the pool the ladder and fan-out use (default 2000)",
    )
    parser.add_argument(
        "--passes",
        type=int,
        default=1,
        help="how many times the pool is driven through the pipeline (default 1)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=50,
        help="timed unit(s) per case (default 50)",
    )
    parser.add_argument(
        "--clients",
        type=int,
        default=DEFAULT_CLIENTS_PER_CHANNEL,
        help="simultaneous clients per channel (default 4)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="seconds each channel's rate measurement runs for (default 1.0)",
    )
    args = parser.parse_args()
    if args.window <= 0.0:
        parser.error("--window must be positive")
    if args.packets < 1:
        parser.error("--packets must be at least 1")
    if args.passes < 1:
        parser.error("--passes must be at least 1")
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    if args.clients < 1:
        parser.error("--clients must be at least 1")
    return args


def _configure_logging() -> None:
    """Quiet the application's loggers so the figures are readable.

    The layers under the socket log at INFO as they work, which is right in a
    service and noise over a table of measurements. Nothing is disabled: the level
    is raised, so a warning or worse would still be seen.
    """
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    for name in ("app", "httpx", "httpcore", _LOGGER_NAME):
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> int:
    """Run every phase and print the baseline (M14.33)."""
    args = _parse_args()
    _configure_logging()
    workdir = harness.temp_workdir()
    try:
        packets = harness.load_packets(args.packets)
        with harness.lab_websocket_settings():
            # The manager reads the caps and the policy table once, when it is built,
            # so the reset has to be inside the settings block: a manager built
            # earlier would keep the shipped caps and the lab run would be measured
            # against the wrong policy.
            reset_websockets()
            _print_header(args, len(packets))
            before_ladder = _resource_snapshot()
            with harness.serving() as client:
                _print_policy()
                _print_table(
                    "Connection setup - one socket opened and closed (M14.33)",
                    _phase_connect(client, args.iterations),
                )
                rungs, stack = _phase_packet_ladder(
                    workdir,
                    packets,
                    args.passes,
                    lambda: _holding(client, Channel.PACKETS),
                )
                _print_rungs(
                    "Packet path ladder - M14 absent to a live subscriber (M14.33)",
                    rungs,
                )
                after_ladder = _resource_snapshot()
                _print_resources(
                    "packet ladder",
                    before_ladder,
                    after_ladder,
                    sum(rung.packets for rung in rungs),
                )
                # The dashboard payload is built by the tick's own sampler, which
                # reads the process-wide session factory. Pointing that at this
                # run's throwaway store for the duration is what lets that payload
                # be the real one without the run reading the developer's database.
                with harness.isolated_app_sessions(stack.factory):
                    latency, rates = _phase_latency(
                        client, stack, args.iterations, args.window
                    )
                    _print_table(
                        "Broadcast latency, per channel - publish to client (M14.33)",
                        latency,
                    )
                    _print_rates(
                        "Channel throughput - unthrottled publisher, one client "
                        "(M14.33)",
                        rates,
                    )
                    _print_overrun(
                        [
                            harness.overrun_for(channel, events=OVERRUN_EVENTS)
                            for channel in CHANNELS
                        ]
                    )
                    _CLIENT_STACK.append(stack)
                    _print_table(
                        "Simultaneous clients - connect and fan-out (M14.33)",
                        _phase_clients(client, args.clients, args.iterations),
                    )
                    _CLIENT_STACK.clear()
        _print_closing_note()
    finally:
        # The database is throwaway, and the one place a process-wide session
        # factory would have reached the developer's file — the dashboard sampler —
        # was pointed at it for the run, so that file was neither written nor read.
        # Removing the directory is therefore the whole cleanup.
        harness.remove_workdir(workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
