"""The M22 runtime consumer of completed M21 observation windows (M22.8).

A pipeline consumer like every other: M21 hands it a closed window, it records the
ask and returns immediately. The expensive part — training a forest, scoring a
window — happens on this module's own thread, never in the capture path and never
in M21's flush loop.

## Why an evaluation is queued rather than done inline

M21's flush thread writes windows under a lock on a batched schedule. A
train-and-score inside that call would put model fitting between a closed window
and its row, and a slow fit would lengthen the interval every *other* device's
windows wait for. The queue is bounded: when it is full the oldest pending
evaluation is dropped and counted, because a stale evaluation is worth less than
the newest one and unbounded growth is what M22.14 forbids outright.

## Idempotency

Every window is identified by ``(device_key, window_start)``. A repeated flush, a
service retry, a restart and a WebSocket reconnect all reduce to "does a row
already exist for this key", and the store answers that with the row it already
has rather than creating a second verdict (M22.8).

## Failure isolation

A failure to train, to score or to persist is caught and counted here. It cannot
stop M21 learning, packet capture, detection, alerting or the API — every symptom
of it is a missing or ``failed`` evaluation row, which is the honest report.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from app.anomaly_detection.dataset import TrainingDatasetReader
from app.anomaly_detection.evaluation_store import (
    SKIP_NO_MODEL,
    STATUS_FAILED,
    STATUS_SCORED,
    STATUS_SKIPPED,
    EvaluationSnapshot,
    EvaluationStore,
)
from app.anomaly_detection.inference import evaluate_window
from app.anomaly_detection.lifecycle import ModelLifecycle
from app.anomaly_detection.model import ALGORITHM_ISOLATION_FOREST
from app.anomaly_detection.model_store import ModelStore
from app.baselines.aggregation import window_start_datetime

logger = logging.getLogger(__name__)

#: Detector identifier used for ML-generated findings. Distinct from every
#: deterministic rule, so an operator can tell which layer raised a finding and
#: the existing rule thresholds are never touched (M22.11).
ML_ANOMALY_RULE_ID = "ml_anomaly"

#: Most completed windows one pass may evaluate.
DEFAULT_MAX_WINDOWS_PER_PASS = 25

#: How long ``stop`` waits for the worker to finish its current pass.
STOP_GRACE_SECONDS = 5.0

#: Seconds the worker sleeps when the queue is empty.
IDLE_SLEEP_SECONDS = 1.0


@dataclass(frozen=True)
class PendingWindow:
    """One closed observation window awaiting evaluation (M22.8)."""

    device_key: str
    window_start: float
    window_seconds: float

    @property
    def window_start_datetime(self) -> datetime:
        """Return the window start as the naive UTC datetime M21 stores."""
        return window_start_datetime(self.window_start)


class AnomalyEngine:
    """Consumes completed M21 windows and evaluates them (M22.8)."""

    def __init__(
        self,
        *,
        lifecycle: ModelLifecycle,
        evaluation_store: EvaluationStore,
        dataset_reader: TrainingDatasetReader,
        model_store: ModelStore,
        alert_sink: Callable[[list], list] | None = None,
        max_queue: int = 1024,
        max_windows_per_pass: int = DEFAULT_MAX_WINDOWS_PER_PASS,
        autostart: bool = True,
    ) -> None:
        """Create the engine.

        Raises:
            ValueError: If the queue cap is below one.
        """
        if max_queue < 1:
            raise ValueError("max_queue must be at least 1")
        self._lifecycle = lifecycle
        self._evaluations = evaluation_store
        self._datasets = dataset_reader
        self._models = model_store
        self._alert_sink = alert_sink
        self._max_windows_per_pass = max_windows_per_pass
        self._queue: queue.Queue[PendingWindow] = queue.Queue(maxsize=max_queue)

        self._counter_lock = threading.Lock()
        self._evaluated_count = 0
        self._anomaly_count = 0
        self._skipped_count = 0
        self._error_count = 0
        self._dropped_count = 0
        self._alert_count = 0

        self._lifecycle_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        if autostart:
            self.start()

    # -- properties -------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Return whether the worker thread is alive."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def lifecycle(self) -> ModelLifecycle:
        """Return the lifecycle manager this engine drives."""
        return self._lifecycle

    @property
    def store(self) -> EvaluationStore:
        """Return the evaluation store this engine writes through."""
        return self._evaluations

    @property
    def model_store(self) -> ModelStore:
        """Return the model metadata store, for the read-only model surfaces."""
        return self._models

    @property
    def dataset_reader(self) -> TrainingDatasetReader:
        """Return the historical reader, so a caller can count usable history."""
        return self._datasets

    # -- ingestion --------------------------------------------------------

    def enqueue(self, windows: Iterable[PendingWindow]) -> int:
        """Queue completed windows for evaluation, returning how many were taken.

        Never raises and never blocks: a full queue drops its oldest entry, which
        is the least harmful loss and keeps memory bounded (M22.14).
        """
        accepted = 0
        for window in windows:
            try:
                self._queue.put_nowait(window)
                accepted += 1
            except queue.Full:
                self._replace_oldest(window)
                accepted += 1
        return accepted

    def _replace_oldest(self, window: PendingWindow) -> None:
        """Drop the oldest queued evaluation and enqueue ``window`` instead."""
        try:
            dropped = self._queue.get_nowait()
            self._queue.task_done()
            self._note_drop(dropped)
        except queue.Empty:
            pass
        try:
            self._queue.put_nowait(window)
        except queue.Full:
            # Another producer refilled it between the drop and the put. This
            # window is the one lost, and it is counted rather than hidden.
            self._note_drop(window)

    def offer_window(
        self, device_key: str, window_start: float, window_seconds: float
    ) -> bool:
        """Queue one completed window, returning whether it was accepted."""
        return (
            self.enqueue([PendingWindow(device_key, window_start, window_seconds)]) == 1
        )

    def pending(self) -> int:
        """Return how many windows are waiting to be evaluated."""
        return self._queue.qsize()

    # -- evaluation -------------------------------------------------------

    def drain_once(self, *, limit: int | None = None) -> int:
        """Evaluate queued windows, returning how many were processed.

        Args:
            limit: Most windows to process this pass. Defaults to the configured
                per-pass cap, so a backlog drains gradually.

        Returns:
            How many windows were evaluated — successfully or not.
        """
        budget = self._max_windows_per_pass if limit is None else max(limit, 0)
        processed = 0
        while processed < budget:
            try:
                window = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self.evaluate(window)
            except Exception:  # noqa: BLE001 - one window must not stop the pass
                self._note_error()
                logger.exception(
                    "Anomaly evaluation failed for %s at %s",
                    window.device_key,
                    window.window_start,
                )
            finally:
                self._queue.task_done()
            processed += 1
        return processed

    def evaluate(self, pending: PendingWindow) -> EvaluationSnapshot | None:
        """Evaluate one completed window and persist the outcome (M22.8/M22.9).

        Returns:
            The stored evaluation, or ``None`` when the window could not be read.
        """
        window_start = pending.window_start_datetime
        existing = self._evaluations.for_window(pending.device_key, window_start)
        if existing is not None:
            # Already evaluated. A re-flush, a retry and a reconnect all land
            # here, and none of them may produce a second verdict (M22.8).
            return existing

        window = self._datasets.get_window(pending.device_key, window_start)
        if window is None:
            # The row is gone — retention removed it between the flush and this
            # evaluation. Nothing can honestly be said about it.
            self._note_skip()
            return None

        identity_kind = "mac" if pending.device_key.startswith("mac:") else "ip"
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        outcome = self._lifecycle.ensure_model(
            pending.device_key,
            identity_kind=identity_kind,
            before=window_start,
            now=now,
        )
        if outcome.cached is None:
            self._note_skip()
            return self._record_skip(
                pending, reason=outcome.reason or SKIP_NO_MODEL, now=now
            )

        cached = outcome.cached
        try:
            result = evaluate_window(
                window, model=cached.model, training_vectors=cached.training_vectors
            )
        except Exception:  # noqa: BLE001 - a scoring failure is a failed verdict
            self._note_error()
            logger.exception(
                "Could not score window %s for %s", window_start, pending.device_key
            )
            return self._record_skip(
                pending, reason="scoring_failed", now=now, status=STATUS_FAILED
            )

        snapshot, created = self._evaluations.write(
            device_key=pending.device_key,
            window_start=window_start,
            window_seconds=pending.window_seconds,
            algorithm=ALGORITHM_ISOLATION_FOREST,
            model_version=cached.model_version,
            model_trained_at=cached.trained_at,
            training_sample_count=cached.training_sample_count,
            contamination=cached.model.config.contamination,
            decision_score=result.decision_score,
            is_anomaly=result.is_anomaly,
            status=STATUS_SCORED if result.scored else STATUS_SKIPPED,
            skip_reason=None if result.scored else result.reason,
            feature_context=result.context_documents(),
        )
        self._models.mark_evaluated(pending.device_key, at=now)
        with self._counter_lock:
            self._evaluated_count += 1
            if result.is_anomaly:
                self._anomaly_count += 1
        if not result.scored:
            self._note_skip()

        self._lifecycle.note_window(pending.device_key)
        if created and snapshot is not None and result.is_anomaly:
            self._raise_finding(snapshot, pending)
        return snapshot

    # -- lifecycle --------------------------------------------------------

    def start(self) -> bool:
        """Start the evaluation thread, returning whether it was started."""
        with self._lifecycle_lock:
            if self.is_running:
                return False
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._loop, name="anomaly-evaluation", daemon=True
            )
            self._thread = thread
            thread.start()
        logger.info("Anomaly detection engine started")
        return True

    def stop(self, *, drain: bool = True) -> int:
        """Stop the worker, optionally draining what it still holds.

        Returns:
            How many windows the final drain evaluated.
        """
        self._stop_event.set()
        with self._lifecycle_lock:
            thread = self._thread
            self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=STOP_GRACE_SECONDS)
            if thread.is_alive():
                logger.warning("Anomaly evaluation thread did not stop in time")
        if not drain:
            return 0
        written = self.drain_once()
        if written:
            logger.info("Evaluated %d window(s) on stop", written)
        return written

    def shutdown(self) -> None:
        """Stop the worker and drain what it holds. Safe to call twice."""
        self.stop(drain=True)

    def _loop(self) -> None:
        """Evaluate queued windows until stopped."""
        while not self._stop_event.is_set():
            try:
                processed = self.drain_once()
            except Exception:  # noqa: BLE001 - the loop must survive any failure
                logger.exception("Anomaly evaluation pass failed; continuing")
                processed = 0
            if processed == 0:
                # Nothing to do: wait rather than spin. `Event.wait` returns as
                # soon as a stop is requested, so shutdown is not delayed.
                self._stop_event.wait(IDLE_SLEEP_SECONDS)

    # -- findings ---------------------------------------------------------

    def _raise_finding(
        self, snapshot: EvaluationSnapshot, pending: PendingWindow
    ) -> None:
        """Turn an anomalous verdict into an M10 finding and hand it to alerting.

        The finding is the bridge the existing pipeline already understands: M11
        maps it, deduplicates it and stores the alert with its evidence, while the
        anomaly record keeps the underlying model output regardless of what
        alerting does with it (M22.11).

        No automatic action is taken. Nothing is blocked, quarantined or modified
        — the operator retains control.
        """
        if self._alert_sink is None:
            return
        try:
            from app.detection.finding import DetectionFinding

            finding = DetectionFinding(
                rule_id=ML_ANOMALY_RULE_ID,
                rule_name="ML Behaviour Anomaly",
                timestamp=pending.window_start,
                source_device_id=pending.device_key,
                description=(
                    "Isolation Forest flagged this observation window as differing "
                    "from the device's learned behaviour"
                ),
                evidence={
                    "decision_score": float(snapshot.decision_score or 0.0),
                    "is_anomaly": 1,
                    "training_sample_count": snapshot.training_sample_count,
                    "model_version": snapshot.model_version,
                    "contamination": float(snapshot.contamination or 0.0),
                },
                metadata={
                    "algorithm": snapshot.algorithm,
                    "detector": ML_ANOMALY_RULE_ID,
                    "note": (
                        "a deviation from learned behaviour, not proof of "
                        "malicious activity"
                    ),
                },
            )
            outcomes = self._alert_sink([finding])
        except Exception:  # noqa: BLE001 - alerting must not break the verdict
            logger.exception(
                "Could not raise an alert for anomaly evaluation %s",
                snapshot.evaluation_id,
            )
            return
        for outcome in outcomes:
            alert = getattr(outcome, "alert", None)
            if alert is None:
                continue
            self._evaluations.set_alert_id(
                snapshot.evaluation_id, getattr(alert, "alert_id", None)
            )
            with self._counter_lock:
                self._alert_count += 1

    def _record_skip(
        self,
        pending: PendingWindow,
        *,
        reason: str,
        now: datetime,
        status: str = STATUS_SKIPPED,
    ) -> EvaluationSnapshot | None:
        """Persist a non-verdict so the absence of a score is visible (M22.8)."""
        snapshot, _created = self._evaluations.write(
            device_key=pending.device_key,
            window_start=pending.window_start_datetime,
            window_seconds=pending.window_seconds,
            algorithm=ALGORITHM_ISOLATION_FOREST,
            model_version=0,
            model_trained_at=None,
            training_sample_count=0,
            contamination=None,
            decision_score=None,
            is_anomaly=False,
            status=status,
            skip_reason=reason or SKIP_NO_MODEL,
        )
        return snapshot

    # -- diagnostics ------------------------------------------------------

    def get_evaluated_count(self) -> int:
        """Return how many windows produced a verdict."""
        with self._counter_lock:
            return self._evaluated_count

    def get_anomaly_count(self) -> int:
        """Return how many evaluated windows were classified as anomalous."""
        with self._counter_lock:
            return self._anomaly_count

    def get_skipped_count(self) -> int:
        """Return how many windows could not be evaluated."""
        with self._counter_lock:
            return self._skipped_count

    def get_error_count(self) -> int:
        """Return how many evaluations raised an unexpected failure."""
        with self._counter_lock:
            return self._error_count

    def get_dropped_count(self) -> int:
        """Return how many queued windows were dropped by the queue cap."""
        with self._counter_lock:
            return self._dropped_count

    def get_alert_count(self) -> int:
        """Return how many anomalies produced an alert."""
        with self._counter_lock:
            return self._alert_count

    def _note_error(self) -> None:
        with self._counter_lock:
            self._error_count += 1

    def _note_skip(self) -> None:
        with self._counter_lock:
            self._skipped_count += 1

    def _note_drop(self, window: PendingWindow) -> None:
        with self._counter_lock:
            self._dropped_count += 1
        logger.debug(
            "Dropped a queued anomaly evaluation for %s at %s",
            window.device_key,
            window.window_start,
        )


def windows_from_counters(windows: Iterable[object]) -> list[PendingWindow]:
    """Convert M21's closed counter objects into evaluation requests.

    Structural rather than a concrete import, so the M21 flush can hand over its
    own ``WindowCounters`` without M22 importing the aggregation module's private
    state.
    """
    pending: list[PendingWindow] = []
    for window in windows:
        device_key = getattr(window, "device_key", None)
        start = getattr(window, "window_start", None)
        if not isinstance(device_key, str) or not isinstance(start, (int, float)):
            continue
        pending.append(
            PendingWindow(
                device_key=device_key,
                window_start=float(start),
                window_seconds=float(getattr(window, "window_seconds", 60.0) or 60.0),
            )
        )
    return pending


__all__ = [
    "DEFAULT_MAX_WINDOWS_PER_PASS",
    "IDLE_SLEEP_SECONDS",
    "ML_ANOMALY_RULE_ID",
    "STOP_GRACE_SECONDS",
    "AnomalyEngine",
    "PendingWindow",
    "windows_from_counters",
]
