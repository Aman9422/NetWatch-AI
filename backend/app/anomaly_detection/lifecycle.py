"""Model lifecycle: cache lookup, training orchestration and refresh (M22.7).

Everything that decides *when* a forest is built lives here. Training is
expensive, a device produces a window a minute, and an engine that retrained on
every window would spend its life fitting models and none of it scoring them.

* **Cache first.** :meth:`ModelLifecycle.ensure_model` consults the bounded cache,
  then the stored plan, then trains. A stored plan plus retained history rebuilds
  a forest deterministically — the seed is stored — which is how a restart
  recovers without a pickle.
* **Refresh counts windows, not seconds.** ``refresh_interval`` is new *usable
  windows* since the last fit. A device silent for a day has not fallen behind;
  one that produced thirty new minutes has.
* **A failed refresh keeps the working model.** The state becomes ``failed`` with
  a safe sentence, but the cached forest stays and keeps scoring, and
  ``model_version`` is not advanced. A detector that degrades beats one that goes
  blind.
* **Manual retraining is the same path**, with the interval bypassed and a
  per-device lock refusing concurrent runs.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime

from app.anomaly_detection.cache import CachedModel, ModelCache
from app.anomaly_detection.dataset import TrainingDataset, TrainingDatasetReader
from app.anomaly_detection.model import ModelConfig, build_model
from app.anomaly_detection.model_store import ModelSnapshot, ModelStore
from app.anomaly_detection.preprocessing import to_matrix
from app.anomaly_detection.states import (
    ModelState,
    can_score,
    next_state_after_training,
)
from app.anomaly_detection.training import (
    TrainingResult,
    build_vectors,
    train_model,
)

logger = logging.getLogger(__name__)

#: Stable codes describing why no model is available.
SKIP_DISABLED = "disabled"
SKIP_INSUFFICIENT_DATA = "insufficient_training_data"
SKIP_INSUFFICIENT_FEATURES = "insufficient_features"
SKIP_ALREADY_TRAINING = "training_already_in_progress"
SKIP_TRAINING_FAILED = "training_failed"

#: Training-result reasons that mean "not enough features", for reporting.
_FEATURE_REASONS = frozenset({"insufficient_usable_features"})


@dataclass(frozen=True)
class LifecycleResult:
    """The outcome of asking for a device's model (M22.7)."""

    device_key: str
    cached: CachedModel | None
    state: str
    reason: str | None = None
    training_sample_count: int = 0
    model_version: int = 0
    trained_at: datetime | None = None
    retrained: bool = False
    previous_retained: bool = False

    @property
    def available(self) -> bool:
        """Return True when a trained model may be used for inference."""
        return self.cached is not None


def _available(entry: CachedModel) -> LifecycleResult:
    """Describe a cached model that can score."""
    return LifecycleResult(
        device_key=entry.device_key,
        cached=entry,
        state=entry.state,
        training_sample_count=entry.training_sample_count,
        model_version=entry.model_version,
        trained_at=entry.trained_at,
    )


class ModelLifecycle:
    """Trains, caches and refreshes per-device anomaly models (M22.7)."""

    def __init__(
        self,
        *,
        model_store: ModelStore,
        dataset_reader: TrainingDatasetReader,
        config: ModelConfig,
        min_training_windows: int = 100,
        max_training_windows: int = 1440,
        refresh_interval: int = 30,
        min_availability: float = 0.8,
        cache: ModelCache | None = None,
        enabled: bool = True,
    ) -> None:
        """Create the lifecycle manager.

        Raises:
            ValueError: If the minimum window count is below one or the refresh
                interval is negative.
        """
        if min_training_windows < 1:
            raise ValueError("min_training_windows must be at least 1")
        if refresh_interval < 0:
            raise ValueError("refresh_interval must not be negative")
        self._model_store = model_store
        self._dataset_reader = dataset_reader
        self._config = config
        self._min_training_windows = min_training_windows
        self._max_training_windows = max_training_windows
        self._refresh_interval = refresh_interval
        self._min_availability = min_availability
        self._cache = cache or ModelCache()
        self._enabled = bool(enabled)
        self._device_locks: dict[str, threading.Lock] = {}
        self._device_locks_guard = threading.Lock()
        self._train_count = 0
        self._failure_count = 0
        self._skip_count = 0

    # -- properties -------------------------------------------------------

    @property
    def cache(self) -> ModelCache:
        """Return the model cache."""
        return self._cache

    @property
    def refresh_interval(self) -> int:
        """Return the configured refresh interval in new usable windows."""
        return self._refresh_interval

    @property
    def min_training_windows(self) -> int:
        """Return the configured minimum training-window requirement."""
        return self._min_training_windows

    @property
    def enabled(self) -> bool:
        """Return whether models are trained at all."""
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Turn training and inference on or off without discarding the cache."""
        self._enabled = bool(enabled)

    # -- public API -------------------------------------------------------

    def ensure_model(
        self, device_key: str, *, identity_kind: str, before: datetime, now: datetime
    ) -> LifecycleResult:
        """Return a model able to score a window starting at ``before``.

        Args:
            device_key: The device identity.
            identity_kind: ``mac`` or ``ip``, recorded for the API.
            before: The evaluated window's start. Every training query is bounded
                by it, which is what prevents self-training (M22.8).
            now: The instant to record as the training time.
        """
        if not self._enabled:
            return LifecycleResult(
                device_key=device_key,
                cached=None,
                state=ModelState.DISABLED.value,
                reason=SKIP_DISABLED,
            )
        entry = self._cache.get(device_key)
        if entry is not None and can_score(entry.state):
            return _available(entry)
        snapshot = self._model_store.get(device_key)
        if snapshot is not None and snapshot.has_model and can_score(snapshot.state):
            rebuilt = self._rebuild(snapshot, before=before)
            if rebuilt is not None:
                return rebuilt
        return self._train(
            device_key,
            identity_kind=identity_kind,
            before=before,
            now=now,
            previous=None,
        )

    def retrain(
        self, device_key: str, *, identity_kind: str, before: datetime, now: datetime
    ) -> LifecycleResult:
        """Force a training pass, preserving the previous model on failure (M22.12).

        Concurrent calls for one device are refused rather than queued: two
        operator clicks must not build two forests for the same device.
        """
        if not self._enabled:
            return LifecycleResult(
                device_key=device_key,
                cached=None,
                state=ModelState.DISABLED.value,
                reason=SKIP_DISABLED,
            )
        lock = self._lock_for(device_key)
        if not lock.acquire(blocking=False):
            previous = self._cache.get(device_key)
            return LifecycleResult(
                device_key=device_key,
                cached=previous,
                state=(
                    previous.state
                    if previous is not None
                    else ModelState.TRAINING.value
                ),
                reason=SKIP_ALREADY_TRAINING,
                training_sample_count=(
                    previous.training_sample_count if previous else 0
                ),
                model_version=(previous.model_version if previous else 0),
                trained_at=previous.trained_at if previous else None,
            )
        try:
            return self._train(
                device_key,
                identity_kind=identity_kind,
                before=before,
                now=now,
                previous=self._cache.get(device_key),
            )
        finally:
            lock.release()

    def note_window(self, device_key: str) -> None:
        """Record that one more usable window exists for a device.

        Called after a successful evaluation. The counter lives on the cached
        entry, so this path costs no database write.
        """
        entry = self._cache.get(device_key)
        if entry is None:
            return
        self._cache.put(
            CachedModel(
                device_key=entry.device_key,
                model=entry.model,
                model_version=entry.model_version,
                trained_at=entry.trained_at,
                training_sample_count=entry.training_sample_count,
                training_vectors=entry.training_vectors,
                windows_since_training=entry.windows_since_training + 1,
                state=entry.state,
            )
        )

    def is_stale(self, device_key: str) -> bool:
        """Return True when a device's model has fallen behind its data."""
        entry = self._cache.get(device_key)
        if entry is None or self._refresh_interval <= 0:
            return False
        return entry.windows_since_training >= self._refresh_interval

    def forget(self, device_key: str) -> None:
        """Drop one device's cached model."""
        self._cache.forget(device_key)

    def get_train_count(self) -> int:
        """Return how many training passes have succeeded."""
        return self._train_count

    def get_failure_count(self) -> int:
        """Return how many training passes have failed."""
        return self._failure_count

    def get_skip_count(self) -> int:
        """Return how many calls found no model to train on."""
        return self._skip_count

    def reset(self) -> None:
        """Drop cached models and counters. For tests."""
        self._cache.clear()
        self._train_count = 0
        self._failure_count = 0
        self._skip_count = 0

    # -- internals --------------------------------------------------------

    def _lock_for(self, device_key: str) -> threading.Lock:
        """Return the per-device training lock, creating it once."""
        with self._device_locks_guard:
            lock = self._device_locks.get(device_key)
            if lock is None:
                lock = threading.Lock()
                self._device_locks[device_key] = lock
            return lock

    def _select(self, device_key: str, *, before: datetime) -> TrainingDataset:
        """Fetch a bounded historical dataset strictly before ``before``."""
        return self._dataset_reader.select(
            device_key,
            before=before,
            max_windows=self._max_training_windows,
            exclude_anomalies=True,
            min_windows=self._min_training_windows,
        )

    def _rebuild(
        self, snapshot: ModelSnapshot, *, before: datetime
    ) -> LifecycleResult | None:
        """Reconstruct a stored model from retained history (M22.7).

        Returns ``None`` when reconstruction is impossible — an unreadable plan, a
        missing configuration or too little retained history — so the caller falls
        back to a fresh pass rather than scoring with a half-known model.
        """
        plan = snapshot.preprocessing
        config = snapshot.config
        if plan is None or config is None:
            return None
        dataset = self._select(snapshot.device_key, before=before)
        vectors = build_vectors(dataset.windows)
        if len(vectors) < self._min_training_windows:
            return None
        try:
            model = build_model(config=config, plan=plan)
            model.fit(to_matrix(vectors, plan))
        except Exception:  # noqa: BLE001 - fall back to a fresh training pass
            logger.warning(
                "Could not reconstruct the anomaly model for %s", snapshot.device_key
            )
            return None
        entry = CachedModel(
            device_key=snapshot.device_key,
            model=model,
            model_version=snapshot.model_version,
            trained_at=snapshot.trained_at,
            training_sample_count=len(vectors),
            training_vectors=vectors,
            windows_since_training=snapshot.windows_since_training,
            state=snapshot.state,
        )
        self._cache.put(entry)
        logger.info(
            "Reconstructed anomaly model v%d for %s from %d window(s)",
            snapshot.model_version,
            snapshot.device_key,
            len(vectors),
        )
        return _available(entry)

    def _train(
        self,
        device_key: str,
        *,
        identity_kind: str,
        before: datetime,
        now: datetime,
        previous: CachedModel | None,
    ) -> LifecycleResult:
        """Run one training pass and persist its outcome (M22.7)."""
        dataset = self._select(device_key, before=before)
        snapshot = self._model_store.get(device_key)
        stored_plan = snapshot.preprocessing if snapshot is not None else None
        try:
            result = train_model(
                dataset,
                config=self._config,
                min_training_windows=self._min_training_windows,
                min_availability=self._min_availability,
                plan=stored_plan,
            )
        except Exception:  # noqa: BLE001 - a failed pass keeps the old model
            self._failure_count += 1
            logger.exception("Anomaly model training failed for %s", device_key)
            return self._failed(
                device_key,
                identity_kind=identity_kind,
                dataset=dataset,
                previous=previous,
                message="the training pass raised an unexpected failure",
            )
        if not result.succeeded:
            self._skip_count += 1
            return self._insufficient(
                device_key,
                identity_kind=identity_kind,
                dataset=dataset,
                result=result,
                previous=previous,
            )
        return self._persist(
            device_key,
            identity_kind=identity_kind,
            dataset=dataset,
            result=result,
            now=now,
            previous=previous,
        )

    def _persist(
        self,
        device_key: str,
        *,
        identity_kind: str,
        dataset: TrainingDataset,
        result: TrainingResult,
        now: datetime,
        previous: CachedModel | None,
    ) -> LifecycleResult:
        """Store a successful training pass and cache its model."""
        model = result.model
        if model is None:  # pragma: no cover - narrowed by result.succeeded
            return self._failed(
                device_key,
                identity_kind=identity_kind,
                dataset=dataset,
                previous=previous,
                message="the training pass produced no model",
            )
        version = (previous.model_version if previous is not None else 0) + 1
        state = next_state_after_training(succeeded=True, windows_since=0)
        try:
            self._model_store.save(
                device_key=device_key,
                identity_kind=identity_kind,
                state=state.value,
                model_version=version,
                plan=result.plan,
                config=self._config,
                training_sample_count=result.training_sample_count,
                training_window_count=result.training_window_count,
                min_training_windows=self._min_training_windows,
                windows_since_training=0,
                trained_at=now,
                last_error=None,
            )
        except Exception:  # noqa: BLE001 - a trained model may fail to persist
            self._failure_count += 1
            logger.exception("Could not persist the anomaly model for %s", device_key)
            return self._failed(
                device_key,
                identity_kind=identity_kind,
                dataset=dataset,
                previous=previous,
                message="the trained model could not be stored",
            )
        entry = CachedModel(
            device_key=device_key,
            model=model,
            model_version=version,
            trained_at=now,
            training_sample_count=result.training_sample_count,
            training_vectors=build_vectors(dataset.windows),
            windows_since_training=0,
            state=state.value,
        )
        self._cache.put(entry)
        self._train_count += 1
        logger.info(
            "Trained anomaly model v%d for %s on %d window(s)",
            version,
            device_key,
            result.training_sample_count,
        )
        return LifecycleResult(
            device_key=device_key,
            cached=entry,
            state=state.value,
            training_sample_count=result.training_sample_count,
            model_version=version,
            trained_at=now,
            retrained=True,
        )

    def _insufficient(
        self,
        device_key: str,
        *,
        identity_kind: str,
        dataset: TrainingDataset,
        result: TrainingResult,
        previous: CachedModel | None,
    ) -> LifecycleResult:
        """Report a pass that could not train, without fabricating a model."""
        reason = (
            SKIP_INSUFFICIENT_FEATURES
            if result.reason in _FEATURE_REASONS
            else SKIP_INSUFFICIENT_DATA
        )
        self._record_state(
            device_key,
            identity_kind=identity_kind,
            state=ModelState.COLLECTING_DATA.value,
            dataset=dataset,
            result=result,
            previous=previous,
            message=result.reason,
        )
        if previous is not None and can_score(previous.state):
            # A device that already has a working model and has simply not
            # accumulated a refresh yet keeps scoring with what exists: a
            # transient dip in available history must not blind the detector.
            return LifecycleResult(
                device_key=device_key,
                cached=previous,
                state=previous.state,
                training_sample_count=previous.training_sample_count,
                model_version=previous.model_version,
                trained_at=previous.trained_at,
            )
        return LifecycleResult(
            device_key=device_key,
            cached=None,
            state=ModelState.COLLECTING_DATA.value,
            reason=reason,
            training_sample_count=result.training_sample_count,
        )

    def _failed(
        self,
        device_key: str,
        *,
        identity_kind: str,
        dataset: TrainingDataset | None,
        previous: CachedModel | None,
        message: str,
    ) -> LifecycleResult:
        """Record a failure while preserving the previous working model."""
        self._record_state(
            device_key,
            identity_kind=identity_kind,
            state=ModelState.FAILED.value,
            dataset=dataset,
            result=None,
            previous=previous,
            message=message,
        )
        if previous is not None and can_score(previous.state):
            return LifecycleResult(
                device_key=device_key,
                cached=previous,
                state=ModelState.FAILED.value,
                reason=SKIP_TRAINING_FAILED,
                training_sample_count=previous.training_sample_count,
                model_version=previous.model_version,
                trained_at=previous.trained_at,
                previous_retained=True,
            )
        return LifecycleResult(
            device_key=device_key,
            cached=None,
            state=ModelState.FAILED.value,
            reason=SKIP_TRAINING_FAILED,
        )

    def _record_state(
        self,
        device_key: str,
        *,
        identity_kind: str,
        state: str,
        dataset: TrainingDataset | None,
        result: TrainingResult | None,
        previous: CachedModel | None,
        message: str | None,
    ) -> None:
        """Persist a non-ready state, keeping whatever model data exists.

        A persistence failure is logged rather than raised: the state is
        diagnostic, and losing it must not turn "not enough data yet" into an
        exception on the evaluation path.
        """
        try:
            self._model_store.save(
                device_key=device_key,
                identity_kind=identity_kind,
                state=state,
                model_version=previous.model_version if previous is not None else 0,
                plan=result.plan if result is not None else None,
                training_sample_count=(
                    result.training_sample_count
                    if result is not None
                    else (previous.training_sample_count if previous is not None else 0)
                ),
                training_window_count=dataset.offered if dataset is not None else 0,
                min_training_windows=self._min_training_windows,
                last_error=message,
            )
        except Exception:  # noqa: BLE001 - state recording is diagnostic
            logger.warning("Could not record the anomaly state for %s", device_key)


__all__ = [
    "SKIP_ALREADY_TRAINING",
    "SKIP_DISABLED",
    "SKIP_INSUFFICIENT_DATA",
    "SKIP_INSUFFICIENT_FEATURES",
    "SKIP_TRAINING_FAILED",
    "LifecycleResult",
    "ModelLifecycle",
]
