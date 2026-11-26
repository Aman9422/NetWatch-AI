"""Persistent ML anomaly-detection models (M22.10).

Two tables, and the split mirrors M21's:

``anomaly_models``
    One row per device identity whose behaviour M22 has tried to model. It
    carries the model's lifecycle state, the algorithm and its configuration,
    the feature schema the model was trained on, and how many historical
    observation windows were used. This is what the model-listing endpoint and
    the Anomalies page read.

``anomaly_evaluations``
    One row per ``(device_key, window_start)`` — the outcome of scoring one
    completed M21 observation window. It keeps the raw Isolation Forest decision
    score, the classification, the model version that produced them, and the
    bounded feature context needed to inspect the decision.

**Why the uniqueness key is ``(device_key, window_start)`` and not
``(device_key, window_start, model_version)``.** M22 evaluates a completed window
exactly once. Retraining produces a new model version, but it deliberately does
*not* re-score historical windows: a second verdict on the same observation,
reached by a model trained on data that now includes it, is neither more truthful
nor comparable with the first. The version fields record *which* model reached
the stored verdict, so a later re-scoring milestone can key on
``(device_key, window_start, model_version)`` without rewriting these rows. The
narrower key is what makes a repeated flush, a retried evaluation, a backend
restart and a WebSocket reconnect all idempotent (M22.8).

**What is deliberately absent.** No packet, no payload, no peer address and no
port number is stored. A row holds counters, a score and statistics — the same
discipline M21 applied to its window table, and the reason an anomaly history can
be retained for a month at all.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.mixins import TimestampMixin, utcnow

#: Algorithm label stored on every model and evaluation row. Named as a constant
#: so a future milestone adding a second algorithm cannot silently make an old
#: row ambiguous about which one produced it.
ALGORITHM_ISOLATION_FOREST = "isolation_forest"


class AnomalyModel(TimestampMixin, Base):
    """The anomaly-detection model state of one device identity (M22.7).

    Attributes:
        id: Primary key.
        device_key: Stable M8 identity — ``mac:aa:bb:...`` or ``ip:1.2.3.4``.
            Unique, so one identity has exactly one model.
        identity_kind: ``mac`` or ``ip``, carried from the M21 profile so the UI
            can label a weaker identity without re-deriving it from the key.
        algorithm: Currently always ``isolation_forest``. Stored rather than
            hard-coded in the reader, because the milestone is explicit that
            additional algorithms may arrive later.
        state: ``collecting_data``, ``training``, ``ready``, ``stale``,
            ``failed`` or ``disabled`` (M22.5).
        model_version: Increments on every successful training, so a stored
            verdict can be attributed to the model that produced it.
        feature_names_json: The ordered feature list the model consumes. Order is
            part of the model's identity: training and inference must use the
            same sequence or the matrix columns would silently disagree (M22.6).
        feature_schema_version: Version of the extraction rules that produced
            those features.
        preprocessing_json: The imputation plan — fill values per feature — so
            inference reproduces training preprocessing exactly, and so the model
            is reconstructible after a restart without a pickle.
        config_json: The Isolation Forest configuration the model was built with.
        training_sample_count: Usable historical windows used to fit the model.
        training_window_count: Windows *offered* to training, before feature
            eligibility and truncation excluded some.
        min_training_windows: The requirement in force when the model was
            trained, so a later configuration change does not retroactively make
            a stored model look under-trained.
        contamination: The Isolation Forest contamination parameter actually used.
        trained_at: UTC instant of the last successful training, or ``None``.
        last_evaluated_at: UTC instant of the most recent evaluation, or ``None``.
        windows_since_training: Usable windows observed since the last training
            pass. This is what the refresh interval is measured against (M22.7).
        last_error: A safe sentence describing the last training failure, or
            ``None``. Never a traceback and never a file path (M22.12).
    """

    __tablename__ = "anomaly_models"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_key: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    identity_kind: Mapped[str] = mapped_column(String(8), nullable=False, default="ip")
    algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ALGORITHM_ISOLATION_FOREST
    )
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="collecting_data"
    )
    model_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    feature_names_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    feature_schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    preprocessing_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    training_sample_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    training_window_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    min_training_windows: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    contamination: Mapped[float | None] = mapped_column(Float, nullable=True)
    trained_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    windows_since_training: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_anomaly_models_state", "state"),
        Index("idx_anomaly_models_last_evaluated", "last_evaluated_at"),
    )


class AnomalyEvaluation(Base):
    """The outcome of scoring one completed observation window (M22.9/M22.10).

    Attributes:
        id: Primary key, and the identifier the API exposes.
        device_key: The device whose behaviour was evaluated.
        window_start: UTC start of the evaluated M21 window. With ``device_key``
            it is unique, which is what makes a repeated evaluation a no-op
            rather than a duplicate finding (M22.8).
        window_seconds: Length of the evaluated window.
        algorithm: ``isolation_forest``.
        model_version: Which version of the device's model scored this window.
        model_trained_at: When that model was fitted.
        feature_schema_version: The extraction-schema version in force.
        training_sample_count: How many historical windows trained the model.
        contamination: The contamination parameter the model was configured with.
        decision_score: Isolation Forest's raw ``decision_function`` output.
            **Lower means more unusual, and it is not a probability.** Stored
            unmodified so no reader can mistake a display transformation for the
            model's own answer (M22.9).
        is_anomaly: The model's binary classification. ``False`` means the window
            was not classified as an outlier — never that it was benign.
        status: ``scored``, ``skipped`` (not enough history, or no usable
            feature) or ``failed`` (the model raised). A skipped or failed
            evaluation is a recorded fact rather than a missing row, because
            "could not be evaluated" and "was evaluated as normal" are different
            answers and only one of them is a claim about the traffic.
        skip_reason: A short stable code explaining a non-``scored`` status.
        feature_context_json: The bounded per-feature comparison against the
            *training* windows, serialised. Present only for ``scored`` rows.
        alert_id: The M11 alert this evaluation produced, when alerting was
            available and the window was classified as anomalous. The anomaly
            record survives even when no alert was created (M22.11).
        created_at: UTC instant the evaluation was recorded.
    """

    __tablename__ = "anomaly_evaluations"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_key: Mapped[str] = mapped_column(String(80), nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )
    window_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=60.0)
    algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ALGORITHM_ISOLATION_FOREST
    )
    model_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    model_trained_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    feature_schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    training_sample_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    contamination: Mapped[float | None] = mapped_column(Float, nullable=True)
    decision_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="scored")
    skip_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    feature_context_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )

    __table_args__ = (
        # One verdict per device per observation window (M22.8).
        UniqueConstraint(
            "device_key",
            "window_start",
            name="uq_anomaly_evaluations_device_window",
        ),
        # Retention deletes by record age, so the age column is indexed alone.
        Index("idx_anomaly_evaluations_created", "created_at"),
        # The listing reads one device's newest verdicts, newest first.
        Index(
            "idx_anomaly_evaluations_device_window",
            "device_key",
            "window_start",
        ),
        # The classification filter and the newest-first ordering.
        Index("idx_anomaly_evaluations_anomaly", "is_anomaly", "window_start"),
    )


__all__ = [
    "ALGORITHM_ISOLATION_FOREST",
    "AnomalyEvaluation",
    "AnomalyModel",
]
