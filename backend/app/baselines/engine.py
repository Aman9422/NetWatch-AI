"""The behavioural baseline engine (M21.9).

One component, and it is a consumer of the M5 pipeline like every other stage: it
is handed a normalized packet and it does two things — extract the behavioural
features and fold them into an in-memory window. Everything else happens on its
own thread.

## The hot path is one dictionary lookup

``process_packet`` must cost almost nothing, because it runs inside the capture
callback. It extracts features (pure arithmetic on a packet already parsed) and
updates a counter under a lock held for microseconds. It **never touches the
database**: a slow disk in this method would stall capture, which M21.5 forbids
outright. Its failure is contained here as well as in the pipeline, so a
malformed packet contributes nothing and the loop continues.

## The flush thread

A single daemon thread wakes on ``baseline_flush_interval_seconds``, closes every
window whose period has ended, and writes the batch in one transaction. Three
properties matter:

* **Bounded per pass.** At most ``baseline_max_windows_per_flush`` rows are
  written at a time, so a backlog is drained over several passes rather than
  holding one long write.
* **Isolated from capture.** The thread's failure neither stops the thread nor
  reaches the capture path: a failed write is counted and the next pass retries
  with whatever is buffered. Windows already handed to a failed write are not
  requeued, deliberately — a permanently failing database would otherwise grow
  the buffer without bound, which is the M7.11 policy applied to a coarser store.
* **Flushed on shutdown.** ``shutdown`` drains every open window, including a
  partial one, and writes it. A session that ended mid-window still contributes
  the observations it made, and dropping them would mean an application restart
  silently lost real behaviour.

## What it is not

It does not score, classify, alert or block. There is no anomaly detection in this
module and no threshold comparing a window to a profile — that is M22. M21 learns
and describes; it never judges.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence

from app.baselines.aggregation import WindowAggregator, WindowCounters
from app.baselines.features import observe
from app.baselines.store import (
    DEFAULT_ESTABLISHED_MIN_SAMPLES,
    DEFAULT_PROVISIONAL_MIN_SAMPLES,
    DEFAULT_STATISTICS_MAX_WINDOWS,
    BaselineStore,
    ProfileSnapshot,
)
from app.config.settings import settings
from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)

#: Defaults mirroring ``app.config.settings`` so the class is usable alone.
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_FLUSH_INTERVAL_SECONDS = 5.0
DEFAULT_MAX_WINDOWS_PER_FLUSH = 500

#: How long ``shutdown`` waits for the flush thread to notice the stop request.
STOP_GRACE_SECONDS = 5.0


class BaselineEngine:
    """Learns per-device behavioural baselines (M21.9).

    Args:
        store: Where windows and profiles are persisted. A store over the
            application database by default.
        window_seconds: Length of one aggregation window.
        flush_interval: Seconds between flushes.
        max_windows_per_flush: Most windows one pass may write.
        aggregator: The in-memory aggregation, injectable so the bounds can be
            tested at small values.
        autostart: When False the flush thread is not started, so a test can call
            :meth:`flush_due` deterministically.
        clock: Time source in epoch seconds; injectable for tests.
    """

    def __init__(
        self,
        *,
        store: BaselineStore | None = None,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        max_windows_per_flush: int = DEFAULT_MAX_WINDOWS_PER_FLUSH,
        aggregator: WindowAggregator | None = None,
        autostart: bool = True,
        clock: Callable[[], float] | None = None,
        window_listener: Callable[[list[WindowCounters]], None] | None = None,
    ) -> None:
        """Create the engine.

        Args:
            window_listener: Called with each batch of windows that reached the
                database, so a downstream consumer (M22's anomaly engine) can
                evaluate *completed* windows without this engine knowing what that
                consumer does. The callback runs after the rows are committed, so
                a consumer reading them back finds them, and its failure is
                contained here — M21 learning must never depend on a consumer
                existing or succeeding (M22.8).

        Raises:
            ValueError: If the window length or flush interval is not positive, or
                the per-flush cap is below one.
        """
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if flush_interval <= 0:
            raise ValueError("flush_interval must be positive")
        if max_windows_per_flush < 1:
            raise ValueError("max_windows_per_flush must be at least 1")

        self._window_seconds = float(window_seconds)
        self._flush_interval = float(flush_interval)
        self._max_windows_per_flush = max_windows_per_flush
        self._store = store or BaselineStore()
        self._aggregator = aggregator or WindowAggregator(
            window_seconds=self._window_seconds
        )
        self._clock: Callable[[], float] = clock or time.time

        self._counter_lock = threading.Lock()
        self._observed_count = 0
        self._skipped_count = 0
        self._persisted_window_count = 0
        self._persist_error_count = 0
        self._flush_pass_count = 0
        self._last_flush_at: float | None = None

        self._lifecycle_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        # Held around a write so a shutdown drain cannot interleave with a
        # scheduled pass and commit the same window twice.
        self._flush_lock = threading.Lock()
        # Whoever consumes closed windows (M22). ``None`` when nothing does, in
        # which case notifying them is one attribute test.
        self._window_listener = window_listener
        self._listener_error_count = 0
        if autostart:
            self.start()

    # -- properties -------------------------------------------------------

    @property
    def window_seconds(self) -> float:
        """Return the aggregation window length in seconds."""
        return self._window_seconds

    @property
    def flush_interval(self) -> float:
        """Return the configured flush interval in seconds."""
        return self._flush_interval

    @property
    def is_running(self) -> bool:
        """Return whether the flush thread is alive."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def store(self) -> BaselineStore:
        """Return the store this engine writes through."""
        return self._store

    # -- hot path ---------------------------------------------------------

    def process_packet(self, packet: NormalizedPacket) -> None:
        """Learn from one normalized packet (M21.5).

        Never raises and never touches the database: it is called from the capture
        thread, so a storage problem here would stall capture. A packet with no
        trackable sender contributes nothing and is counted.
        """
        try:
            observation = observe(packet)
            if observation is None:
                with self._counter_lock:
                    self._skipped_count += 1
                return
            at = packet.timestamp if packet.timestamp > 0 else self._clock()
            if self._aggregator.observe_packet(observation, at=at):
                with self._counter_lock:
                    self._observed_count += 1
            else:
                with self._counter_lock:
                    self._skipped_count += 1
        except Exception:  # noqa: BLE001 - learning must never stop capture
            with self._counter_lock:
                self._skipped_count += 1
            logger.warning("Baseline feature extraction failed; capture continues")

    # -- flushing ---------------------------------------------------------

    def flush_due(self, *, now: float | None = None) -> int:
        """Write every window that has ended, and return how many were written.

        Args:
            now: Override the current time, for tests.

        Returns:
            How many window rows reached the database.
        """
        timestamp = now if now is not None else self._clock()
        closed = self._aggregator.close_expired(now=timestamp)
        return self._write(closed)

    def flush_all(self) -> int:
        """Drain every open window, including the current one, and write it.

        Used on graceful shutdown (M21.5). A partial window is still real
        observation, so it is kept rather than discarded — only a window that
        observed nothing is dropped, and the store enforces that.

        Returns:
            How many window rows reached the database.
        """
        return self._write(self._aggregator.drain())

    def _write(self, windows: Sequence[WindowCounters]) -> int:
        """Persist a batch of closed windows, containing any failure."""
        if not windows:
            return 0
        batch = list(windows)[: self._max_windows_per_flush]
        with self._flush_lock:
            try:
                written = self._store.write_windows(batch)
            except Exception:  # noqa: BLE001 - a write must not stop the flush loop
                with self._counter_lock:
                    self._persist_error_count += 1
                    self._flush_pass_count += 1
                logger.exception(
                    "Baseline flush failed for %d window(s); continuing", len(batch)
                )
                return 0
            with self._counter_lock:
                self._persisted_window_count += written
                self._flush_pass_count += 1
            if written:
                self._last_flush_at = self._clock()
        # Outside the flush lock: a consumer must not extend the window during
        # which a concurrent pass is blocked from writing.
        if written:
            self._notify_listener(batch)
        return written

    def _notify_listener(self, windows: Sequence[WindowCounters]) -> None:
        """Hand committed windows to the downstream consumer (M22.8).

        The rows are already in the database, so a consumer that reads them back
        finds them. Any failure is counted and logged here and goes no further:
        M21 learning must survive a broken consumer.
        """
        listener = self._window_listener
        if listener is None:
            return
        try:
            listener(list(windows))
        except Exception:  # noqa: BLE001 - a consumer must not break learning
            with self._counter_lock:
                self._listener_error_count += 1
            logger.exception(
                "Baseline window listener failed for %d window(s); learning continues",
                len(windows),
            )

    def attach_window_listener(
        self, listener: Callable[[list[WindowCounters]], None] | None
    ) -> None:
        """Set the consumer that receives committed windows (M22.8).

        The application lifespan calls this before :meth:`start`, so the learner
        never has to know which consumer exists — or that one exists at all. A
        later call replaces the listener; ``None`` detaches it.
        """
        self._window_listener = listener

    # -- lifecycle --------------------------------------------------------

    def start(self) -> bool:
        """Start the flush thread, returning whether it was started."""
        with self._lifecycle_lock:
            if self.is_running:
                return False
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._loop, name="baseline-flush", daemon=True
            )
            self._thread = thread
            thread.start()
        logger.info(
            "Baseline engine started: %.0fs window, flushing every %.0fs",
            self._window_seconds,
            self._flush_interval,
        )
        return True

    def stop(self, *, flush: bool = True) -> int:
        """Stop the flush thread, optionally draining pending windows first.

        Args:
            flush: When True the remaining windows are written before returning.

        Returns:
            How many rows the final flush wrote.
        """
        self._stop_event.set()
        with self._lifecycle_lock:
            thread = self._thread
            self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=self._flush_interval + STOP_GRACE_SECONDS)
            if thread.is_alive():
                # The thread is a daemon, so this cannot hold the process open,
                # but an operator should know the final flush may be incomplete.
                logger.warning("Baseline flush thread did not stop in time")
        if not flush:
            return 0
        written = self.flush_all()
        if written:
            logger.info("Flushed %d baseline window(s) on stop", written)
        return written

    def shutdown(self) -> None:
        """Stop the engine and write everything it still holds (M21.5).

        The application lifespan calls this. It is guarded by its callers and is
        safe to call twice.
        """
        self.stop(flush=True)

    def _loop(self) -> None:
        """Flush on an interval until stopped."""
        while not self._stop_event.wait(self._flush_interval):
            try:
                self.flush_due()
            except Exception:  # noqa: BLE001 - the loop must survive any failure
                logger.exception("Baseline flush pass failed; continuing")

    # -- reads ------------------------------------------------------------

    def get_profile(self, device_key: str) -> ProfileSnapshot | None:
        """Return one device's profile, delegating to the store."""
        return self._store.get_profile(device_key)

    def list_profiles(
        self,
        *,
        learning_state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ProfileSnapshot]:
        """Return baseline profiles, delegating to the store."""
        return self._store.list_profiles(
            learning_state=learning_state, limit=limit, offset=offset
        )

    def count_profiles(self, *, learning_state: str | None = None) -> int:
        """Return how many profiles match a filter, delegating to the store."""
        return self._store.count_profiles(learning_state=learning_state)

    def reset_device(self, device_key: str) -> tuple[int, bool]:
        """Delete one device's baseline and let learning restart (M21.10).

        Clears the persisted rows *and* the in-memory window and remembered
        conversations, so a device that starts behaving again is genuinely new
        rather than continuing from a partial window that survived the delete.

        Returns:
            ``(windows_deleted, profile_deleted)``.
        """
        deleted = self._store.reset_device(device_key)
        self._aggregator.forget_device(device_key)
        return deleted

    # -- diagnostics ------------------------------------------------------

    def get_observed_packet_count(self) -> int:
        """Return how many packets contributed to a window."""
        with self._counter_lock:
            return self._observed_count

    def get_skipped_packet_count(self) -> int:
        """Return how many packets could not be attributed to a device."""
        with self._counter_lock:
            return self._skipped_count

    def get_persisted_window_count(self) -> int:
        """Return how many window rows have been written."""
        with self._counter_lock:
            return self._persisted_window_count

    def get_persist_error_count(self) -> int:
        """Return how many flush writes failed."""
        with self._counter_lock:
            return self._persist_error_count

    def get_flush_pass_count(self) -> int:
        """Return how many flush passes have run."""
        with self._counter_lock:
            return self._flush_pass_count

    def get_listener_error_count(self) -> int:
        """Return how many times the window listener raised."""
        with self._counter_lock:
            return self._listener_error_count

    def get_last_flush_at(self) -> float | None:
        """Return when a flush last wrote rows, or ``None``."""
        return self._last_flush_at

    def get_aggregator(self) -> WindowAggregator:
        """Return the in-memory aggregation, for diagnostics and tests."""
        return self._aggregator

    @property
    def aggregator(self) -> WindowAggregator:
        """Return the in-memory aggregation."""
        return self._aggregator

    # -- reset ------------------------------------------------------------

    def reset(self) -> None:
        """Drop all in-memory state and diagnostic counters (tests)."""
        self._aggregator.reset()
        with self._counter_lock:
            self._observed_count = 0
            self._skipped_count = 0
            self._persisted_window_count = 0
            self._persist_error_count = 0
            self._flush_pass_count = 0
            self._listener_error_count = 0
            self._last_flush_at = None


# Shared singleton used by the application at runtime.
_baseline_engine: BaselineEngine | None = None
_engine_lock = threading.Lock()


def get_baseline_engine() -> BaselineEngine:
    """Return the process-wide baseline engine, building it once (M21.9).

    Built with ``autostart=False`` so the caller decides when the flush thread
    starts: the capture pipeline wires it in and the application lifespan starts
    it, and a test can ask for the same object and drive ``flush_due`` by hand.
    """
    global _baseline_engine
    with _engine_lock:
        if _baseline_engine is None:
            _baseline_engine = BaselineEngine(
                store=BaselineStore(
                    statistics_max_windows=settings.baseline_statistics_max_windows,
                    provisional_min_samples=settings.baseline_provisional_min_samples,
                    established_min_samples=settings.baseline_established_min_samples,
                ),
                window_seconds=settings.baseline_window_seconds,
                flush_interval=settings.baseline_flush_interval_seconds,
                max_windows_per_flush=settings.baseline_max_windows_per_flush,
                aggregator=WindowAggregator(
                    window_seconds=settings.baseline_window_seconds,
                    max_devices=settings.baseline_max_tracked_devices,
                    max_peers=settings.baseline_max_peers_per_window,
                    max_ports=settings.baseline_max_ports_per_window,
                    max_connection_keys=settings.baseline_max_connection_keys,
                ),
                autostart=False,
            )
        return _baseline_engine


def reset_baseline_engine() -> None:
    """Drop the cached engine, stopping it first. For tests and reloads."""
    global _baseline_engine
    with _engine_lock:
        current = _baseline_engine
        _baseline_engine = None
    if current is not None:
        current.stop(flush=False)


__all__ = [
    "DEFAULT_FLUSH_INTERVAL_SECONDS",
    "DEFAULT_MAX_WINDOWS_PER_FLUSH",
    "DEFAULT_WINDOW_SECONDS",
    "STOP_GRACE_SECONDS",
    "BaselineEngine",
    "get_baseline_engine",
    "reset_baseline_engine",
]
