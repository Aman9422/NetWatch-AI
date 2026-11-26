"""Baseline-engine tests (M21.9).

The engine is the component the capture pipeline actually calls, so the properties
tested here are about *containment* as much as about learning:

* ``process_packet`` never raises into the capture thread and never touches the
  database, because a slow disk there would stall capture (M21.5).
* A flush failure is counted, logged and survived — the loop keeps running.
* Shutdown drains the partial window, so a session that ended mid-window still
  contributes what it really observed.
* A restart re-reads the persisted profile rather than starting again from zero,
  which is what M21.7 means by "must not unnecessarily discard persisted
  baselines".

No thread is started in most of these: ``autostart=False`` plus an injected clock
makes a flush a single deterministic call.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

import pytest
from sqlalchemy.orm import Session

from app.baselines.aggregation import WindowCounters
from app.baselines.engine import BaselineEngine
from app.baselines.store import BaselineStore
from app.schemas.packet import NormalizedPacket, PacketType

DEVICE_MAC = "AA:BB:CC:00:00:01"
OTHER_MAC = "AA:BB:CC:00:00:02"

#: Epoch seconds that floor exactly onto a window boundary.
BASE = 1_700_000_040.0


def packet(
    *,
    timestamp: float = BASE,
    source_mac: str = DEVICE_MAC,
    source_ip: str | None = "10.0.0.21",
    destination_ip: str = "10.0.0.5",
    destination_port: int = 443,
    protocol: str = "TCP",
    packet_type: PacketType = PacketType.TCP,
    length: int = 120,
    tcp_flags: str = "S",
) -> NormalizedPacket:
    """Build one normalized packet from a trackable sender."""
    return NormalizedPacket(
        timestamp=timestamp,
        length=length,
        source_mac=source_mac,
        source_ip=source_ip,
        destination_mac="AA:BB:CC:00:00:99",
        destination_ip=destination_ip,
        ip_version=4,
        protocol=protocol,
        source_port=51000,
        destination_port=destination_port,
        tcp_flags=tcp_flags,
        packet_type=packet_type,
    )


def make_engine(
    session_factory: Callable[[], Session],
    *,
    window_seconds: float = 60.0,
) -> BaselineEngine:
    """Build an engine over the isolated database, with no background thread."""
    return BaselineEngine(
        store=BaselineStore(
            session_factory=session_factory,
            provisional_min_samples=3,
            established_min_samples=5,
        ),
        window_seconds=window_seconds,
        flush_interval=60.0,
        autostart=False,
    )


# ---------------------------------------------------------------------------
# the hot path
# ---------------------------------------------------------------------------


def test_a_packet_updates_a_window_without_writing_anything(
    session_factory: Callable[[], Session],
) -> None:
    """The hot path is an in-memory update; the database sees nothing yet."""
    engine = make_engine(session_factory)

    engine.process_packet(packet())

    assert engine.get_observed_packet_count() == 1
    assert engine.get_persisted_window_count() == 0
    assert engine.store.get_profile(f"mac:{DEVICE_MAC}") is None
    assert engine.get_aggregator().pending_windows == 1


def test_an_unattributable_packet_is_counted_as_skipped(
    session_factory: Callable[[], Session],
) -> None:
    """A broadcast sender contributes nothing and does not raise."""
    engine = make_engine(session_factory)

    engine.process_packet(packet(source_mac="FF:FF:FF:FF:FF:FF", source_ip=None))

    assert engine.get_observed_packet_count() == 0
    assert engine.get_skipped_packet_count() == 1


def test_a_malformed_packet_cannot_escape_the_hot_path(
    session_factory: Callable[[], Session],
) -> None:
    """Extraction is where a bad packet dies, not the capture loop (M21.5)."""
    engine = make_engine(session_factory)

    engine.process_packet("not a packet")  # type: ignore[arg-type]
    engine.process_packet(None)  # type: ignore[arg-type]

    assert engine.get_skipped_packet_count() == 2
    assert engine.get_observed_packet_count() == 0


def test_a_packet_with_no_timestamp_falls_back_to_the_clock(
    session_factory: Callable[[], Session],
) -> None:
    """A zero timestamp is replaced by the engine's clock, not by epoch zero.

    Attributing the packet to 1970 would create a window that retention would
    delete on the next pass, so the observation would be lost silently.
    """
    engine = BaselineEngine(
        store=BaselineStore(session_factory=session_factory),
        window_seconds=60.0,
        autostart=False,
        clock=lambda: BASE,
    )

    engine.process_packet(packet(timestamp=0.0))

    closed = engine.get_aggregator().drain()

    assert len(closed) == 1
    assert closed[0].window_start == BASE


def test_two_devices_are_tracked_independently(
    session_factory: Callable[[], Session],
) -> None:
    """One device's packets never reach another's window (M21.5)."""
    engine = make_engine(session_factory)

    engine.process_packet(packet(source_mac=DEVICE_MAC))
    engine.process_packet(packet(source_mac=OTHER_MAC))

    engine.flush_all()

    mine = engine.store.get_profile(f"mac:{DEVICE_MAC}")
    theirs = engine.store.get_profile(f"mac:{OTHER_MAC}")

    assert mine is not None and theirs is not None
    assert mine.sample_count == 1
    assert theirs.sample_count == 1


# ---------------------------------------------------------------------------
# flushing
# ---------------------------------------------------------------------------


def test_flush_all_writes_the_current_window(
    session_factory: Callable[[], Session],
) -> None:
    """A graceful stop keeps a partial window: it is still real observation."""
    engine = make_engine(session_factory)
    engine.process_packet(packet())

    written = engine.flush_all()

    assert written == 1
    assert engine.get_persisted_window_count() == 1
    assert engine.get_aggregator().pending_windows == 0


def test_flush_due_leaves_the_current_window_alone(
    session_factory: Callable[[], Session],
) -> None:
    """A scheduled flush only writes windows whose period has ended."""
    engine = make_engine(session_factory)
    engine.process_packet(packet(timestamp=BASE))

    assert engine.flush_due(now=BASE) == 0
    assert engine.flush_due(now=BASE + 60.0) == 1


def test_a_flush_of_nothing_is_not_an_error(
    session_factory: Callable[[], Session],
) -> None:
    """An idle engine writes no rows and reports that honestly."""
    engine = make_engine(session_factory)

    assert engine.flush_due(now=BASE) == 0
    assert engine.flush_all() == 0


def test_windows_from_several_periods_are_all_written(
    session_factory: Callable[[], Session],
) -> None:
    """A backlog is not truncated to the newest window (the aggregator regression)."""
    engine = make_engine(session_factory)
    for index in range(4):
        engine.process_packet(packet(timestamp=BASE + index * 60.0))

    written = engine.flush_all()

    assert written == 4
    profile = engine.store.get_profile(f"mac:{DEVICE_MAC}")
    assert profile is not None
    assert profile.sample_count == 4


def test_a_flush_write_is_bounded_per_pass(
    session_factory: Callable[[], Session],
) -> None:
    """A backlog is drained over several passes rather than one long write."""
    engine = BaselineEngine(
        store=BaselineStore(
            session_factory=session_factory,
            provisional_min_samples=3,
            established_min_samples=5,
        ),
        window_seconds=60.0,
        max_windows_per_flush=2,
        autostart=False,
    )
    for index in range(5):
        engine.process_packet(packet(timestamp=BASE + index * 60.0))

    assert engine.flush_all() == 2


# ---------------------------------------------------------------------------
# failure containment
# ---------------------------------------------------------------------------


def test_a_failed_write_is_counted_and_survived(
    session_factory: Callable[[], Session],
) -> None:
    """A storage failure must not stop the engine or reach the capture thread."""
    engine = BaselineEngine(
        store=_FailingStore(session_factory=session_factory),
        window_seconds=60.0,
        autostart=False,
    )
    engine.process_packet(packet())

    written = engine.flush_all()

    assert written == 0
    assert engine.get_persist_error_count() == 1
    assert engine.get_flush_pass_count() == 1


def test_the_engine_keeps_flushing_after_a_failure(
    session_factory: Callable[[], Session],
) -> None:
    """The next pass runs, so a transient failure costs one batch, not the engine."""
    engine = BaselineEngine(
        store=_FlakyStore(session_factory), window_seconds=60.0, autostart=False
    )

    engine.process_packet(packet(timestamp=BASE))
    engine.flush_all()
    engine.process_packet(packet(timestamp=BASE + 60.0))
    engine.flush_all()

    assert engine.get_persist_error_count() == 1
    assert engine.get_persisted_window_count() == 1


# ---------------------------------------------------------------------------
# persistence across a restart
# ---------------------------------------------------------------------------


def test_a_restarted_engine_reads_the_stored_profile(
    session_factory: Callable[[], Session],
) -> None:
    """A baseline is a durable record, not a session artefact (M21.7)."""
    first = make_engine(session_factory)
    for index in range(3):
        first.process_packet(packet(timestamp=BASE + index * 60.0))
    first.flush_all()
    before = first.store.get_profile(f"mac:{DEVICE_MAC}")

    # A fresh engine over the same database, which is what a process restart is.
    second = make_engine(session_factory)
    after = second.store.get_profile(f"mac:{DEVICE_MAC}")

    assert before is not None and after is not None
    assert after.sample_count == 3
    assert after.learning_state == before.learning_state


def test_new_windows_continue_an_existing_profile_across_a_restart(
    session_factory: Callable[[], Session],
) -> None:
    """Learning resumes from the stored count rather than from zero."""
    first = make_engine(session_factory)
    for index in range(3):
        first.process_packet(packet(timestamp=BASE + index * 60.0))
    first.flush_all()

    second = make_engine(session_factory)
    second.process_packet(packet(timestamp=BASE + 600.0))
    second.flush_all()

    profile = second.store.get_profile(f"mac:{DEVICE_MAC}")

    assert profile is not None
    assert profile.sample_count == 4


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


def test_a_reset_deletes_the_stored_baseline_and_the_open_window(
    session_factory: Callable[[], Session],
) -> None:
    """Learning genuinely restarts, including from an unflushed window."""
    engine = make_engine(session_factory)
    for index in range(3):
        engine.process_packet(packet(timestamp=BASE + index * 60.0))
    engine.flush_all()
    engine.process_packet(packet(timestamp=BASE + 600.0))

    windows_deleted, profile_deleted = engine.reset_device(f"mac:{DEVICE_MAC}")

    assert windows_deleted == 3
    assert profile_deleted is True
    assert engine.store.get_profile(f"mac:{DEVICE_MAC}") is None
    assert engine.get_aggregator().pending_windows == 0


def test_a_reset_of_one_device_leaves_another_learning(
    session_factory: Callable[[], Session],
) -> None:
    """Reset is scoped to one identity, never to the engine."""
    engine = make_engine(session_factory)
    engine.process_packet(packet(source_mac=DEVICE_MAC))
    engine.process_packet(packet(source_mac=OTHER_MAC))
    engine.flush_all()

    engine.reset_device(f"mac:{DEVICE_MAC}")

    assert engine.store.get_profile(f"mac:{DEVICE_MAC}") is None
    assert engine.store.get_profile(f"mac:{OTHER_MAC}") is not None


# ---------------------------------------------------------------------------
# reads and lifecycle
# ---------------------------------------------------------------------------


def test_the_listing_and_count_read_through_the_store(
    session_factory: Callable[[], Session],
) -> None:
    """The engine is the API's single entry point, so it forwards both reads."""
    engine = make_engine(session_factory)
    engine.process_packet(packet())
    engine.flush_all()

    assert len(engine.list_profiles()) == 1
    assert engine.count_profiles() == 1
    assert engine.get_profile(f"mac:{DEVICE_MAC}") is not None


def test_stop_flushes_by_default_and_can_be_told_not_to(
    session_factory: Callable[[], Session],
) -> None:
    """Shutdown writes the partial window; an abrupt stop may skip it."""
    flushes = make_engine(session_factory)
    flushes.process_packet(packet(source_mac=DEVICE_MAC))
    assert flushes.stop(flush=True) == 1

    # A different device, because both engines share one database: the flush case's
    # profile must not be what the skip assertion reads.
    skips = make_engine(session_factory)
    skips.process_packet(packet(source_mac=OTHER_MAC))
    assert skips.stop(flush=False) == 0
    assert skips.store.get_profile(f"mac:{OTHER_MAC}") is None


def test_an_engine_can_be_started_and_stopped(
    session_factory: Callable[[], Session],
) -> None:
    """The lifespan owns the thread, so both transitions have to work."""
    engine = BaselineEngine(
        store=BaselineStore(session_factory=session_factory),
        window_seconds=60.0,
        flush_interval=0.05,
        autostart=False,
    )

    assert engine.start() is True
    assert engine.is_running is True
    try:
        # A second start on a running engine is a no-op, not a second thread.
        assert engine.start() is False
    finally:
        engine.stop()

    assert engine.is_running is False


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"window_seconds": 0.0}, "window_seconds"),
        ({"flush_interval": 0.0}, "flush_interval"),
        ({"max_windows_per_flush": 0}, "max_windows_per_flush"),
    ],
)
def test_a_nonsensical_configuration_is_rejected(
    session_factory: Callable[[], Session],
    kwargs: dict[str, float],
    message: str,
) -> None:
    """A zero window or interval would make flushing meaningless."""
    with pytest.raises(ValueError, match=message):
        BaselineEngine(
            store=BaselineStore(session_factory=session_factory),
            autostart=False,
            **kwargs,  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# doubles
# ---------------------------------------------------------------------------


class _FailingStore(BaselineStore):
    """A store whose every write fails, standing in for a locked database."""

    def write_windows(self, windows: Sequence[WindowCounters]) -> int:
        """Fail, which the engine has to contain."""
        raise RuntimeError("simulated storage failure")


class _FlakyStore(BaselineStore):
    """A store that fails once then succeeds, standing in for a transient fault."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        """Wrap a real store, so a successful write really persists."""
        super().__init__(session_factory=session_factory)
        self._has_failed = False

    def write_windows(self, windows: Sequence[WindowCounters]) -> int:
        """Fail the first call, then delegate to the real implementation."""
        if not self._has_failed:
            self._has_failed = True
            raise RuntimeError("simulated transient failure")
        return super().write_windows(windows)
