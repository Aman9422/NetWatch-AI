"""Local machine-learning anomaly detection (M22).

One algorithm, run locally on CPU, over the behavioural windows M21 persists. Each
responsibility lives in its own module:

* :mod:`app.anomaly_detection.states` — model lifecycle vocabulary (M22.5).
* :mod:`app.anomaly_detection.features` — a window's feature vector (M22.6).
* :mod:`app.anomaly_detection.preprocessing` — eligibility and imputation; the
  plan that keeps training and inference identical (M22.6).
* :mod:`app.anomaly_detection.model` — Isolation Forest construction and scoring
  (M22.4).
* :mod:`app.anomaly_detection.dataset` — historical selection and the strict
  cutoff that stops a window training on itself (M22.5/M22.8).
* :mod:`app.anomaly_detection.training` — one training pass (M22.5).
* :mod:`app.anomaly_detection.inference` — one verdict plus its context (M22.9).
* :mod:`app.anomaly_detection.cache` — the bounded model cache (M22.7).
* :mod:`app.anomaly_detection.lifecycle` — when a model is trained and refreshed
  (M22.7).
* :mod:`app.anomaly_detection.model_store` and ``evaluation_store`` —
  persistence (M22.10).
* :mod:`app.anomaly_detection.engine` — the runtime consumer of completed M21
  windows (M22.8).
* :mod:`app.anomaly_detection.retention` — the M19-driven retention policy
  (M22.10).

**What this package does not do.** No LLM, no generated explanation, no blocking or
quarantine, no cloud call. It fits one algorithm locally, scores completed
observation windows, and records what it decided. An anomaly is a deviation from
learned behaviour — not proof of malicious activity — and every payload carrying a
verdict says so.
"""

from __future__ import annotations

import logging
import threading

from app.anomaly_detection.cache import CachedModel, ModelCache
from app.anomaly_detection.dataset import TrainingDataset, TrainingDatasetReader
from app.anomaly_detection.engine import (
    ML_ANOMALY_RULE_ID,
    AnomalyEngine,
    PendingWindow,
    windows_from_counters,
)
from app.anomaly_detection.evaluation_store import (
    EVALUATION_STATUSES,
    STATUS_FAILED,
    STATUS_SCORED,
    STATUS_SKIPPED,
    EvaluationSnapshot,
    EvaluationStore,
)
from app.anomaly_detection.features import (
    FEATURE_SCHEMA_VERSION,
    FeatureVector,
    build_feature_vector,
)
from app.anomaly_detection.inference import (
    FeatureContext,
    InferenceResult,
    evaluate_window,
)
from app.anomaly_detection.lifecycle import LifecycleResult, ModelLifecycle
from app.anomaly_detection.model import (
    ALGORITHM_ISOLATION_FOREST,
    FittedModel,
    ModelConfig,
    ScoreResult,
    build_model,
)
from app.anomaly_detection.model_store import ModelSnapshot, ModelStore
from app.anomaly_detection.preprocessing import (
    PreprocessingPlan,
    build_plan,
    to_matrix,
    to_row,
)
from app.anomaly_detection.retention import (
    AnomalyRetentionOutcome,
    AnomalyRetentionService,
    get_anomaly_retention_service,
    reset_anomaly_retention_service,
)
from app.anomaly_detection.states import (
    MODEL_STATES,
    ModelState,
    can_score,
    describe_state,
    normalize_state,
)
from app.anomaly_detection.training import TrainingResult, train_model

logger = logging.getLogger(__name__)

__all__ = [
    "ALGORITHM_ISOLATION_FOREST",
    "AnomalyEngine",
    "AnomalyRetentionOutcome",
    "AnomalyRetentionService",
    "CachedModel",
    "EVALUATION_STATUSES",
    "EvaluationSnapshot",
    "EvaluationStore",
    "FEATURE_SCHEMA_VERSION",
    "FeatureContext",
    "FeatureVector",
    "FittedModel",
    "InferenceResult",
    "LifecycleResult",
    "ML_ANOMALY_RULE_ID",
    "MODEL_STATES",
    "ModelCache",
    "ModelConfig",
    "ModelLifecycle",
    "ModelSnapshot",
    "ModelState",
    "ModelStore",
    "PendingWindow",
    "PreprocessingPlan",
    "STATUS_FAILED",
    "STATUS_SCORED",
    "STATUS_SKIPPED",
    "ScoreResult",
    "TrainingDataset",
    "TrainingDatasetReader",
    "TrainingResult",
    "build_feature_vector",
    "build_model",
    "build_plan",
    "can_score",
    "describe_state",
    "evaluate_window",
    "get_anomaly_engine",
    "get_anomaly_retention_service",
    "normalize_state",
    "reset_anomaly_engine",
    "reset_anomaly_retention_service",
    "to_matrix",
    "to_row",
    "train_model",
    "windows_from_counters",
]

# Shared singleton used by the application at runtime.
_anomaly_engine: AnomalyEngine | None = None
_engine_lock = threading.Lock()


def _build_engine() -> AnomalyEngine:
    """Construct the process-wide engine from application settings.

    Imports are local so importing this package never opens a database or reads
    the environment as a side effect.
    """
    from app.alerts import get_alert_engine
    from app.config.settings import settings
    from app.persistence.session_factory import app_session_factory

    config = ModelConfig(
        n_estimators=settings.anomaly_model_n_estimators,
        contamination=settings.anomaly_model_contamination,
        random_state=settings.anomaly_model_random_state,
    )
    model_store = ModelStore(session_factory=app_session_factory)
    evaluation_store = EvaluationStore(session_factory=app_session_factory)
    dataset_reader = TrainingDatasetReader(session_factory=app_session_factory)
    lifecycle = ModelLifecycle(
        model_store=model_store,
        dataset_reader=dataset_reader,
        config=config,
        min_training_windows=settings.anomaly_model_min_training_windows,
        max_training_windows=settings.anomaly_model_max_training_windows,
        refresh_interval=settings.anomaly_model_refresh_interval,
        min_availability=settings.anomaly_feature_min_availability,
        cache=ModelCache(max_size=settings.anomaly_model_cache_size),
        enabled=settings.anomaly_detection_enabled,
    )
    # The alert engine is reached through a callable rather than imported and
    # held, so an unavailable alert layer degrades to "no alert" while the anomaly
    # record is still written (M22.11).
    alert_sink = None
    if settings.alerts_enabled:
        try:
            alert_sink = get_alert_engine().process_findings
        except Exception:  # noqa: BLE001 - alerting is optional enrichment
            logger.exception(
                "Could not resolve the alert engine; ML findings will not alert"
            )
    return AnomalyEngine(
        lifecycle=lifecycle,
        evaluation_store=evaluation_store,
        dataset_reader=dataset_reader,
        model_store=model_store,
        alert_sink=alert_sink,
        max_queue=settings.anomaly_evaluation_queue_size,
        max_windows_per_pass=settings.anomaly_max_windows_per_pass,
        autostart=False,
    )


def get_anomaly_engine() -> AnomalyEngine:
    """Return the process-wide anomaly engine, building it once (M22.8).

    Built with ``autostart=False`` so the caller decides when the worker starts:
    the application lifespan starts it, and a test can ask for the same object and
    drive ``drain_once`` by hand.
    """
    global _anomaly_engine
    with _engine_lock:
        if _anomaly_engine is None:
            _anomaly_engine = _build_engine()
        return _anomaly_engine


def reset_anomaly_engine() -> None:
    """Drop the cached engine, stopping it first. For tests and reloads."""
    global _anomaly_engine
    with _engine_lock:
        current = _anomaly_engine
        _anomaly_engine = None
    if current is not None:
        current.stop(drain=False)
