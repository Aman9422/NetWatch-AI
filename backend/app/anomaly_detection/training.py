"""Training a device-specific Isolation Forest from history (M22.5/M22.7).

This module is the seam between *data* and *model*: it takes the historical
windows the dataset reader selected, decides eligibility, builds the matrix
through the preprocessing plan, and fits the forest. It owns no clock, no database
and no cache — the lifecycle module above decides *when* to call it, which is what
keeps retraining out of the packet path.

## The minimum is M22's own, not M21's

A device whose M21 baseline is ``established`` has enough windows for a robust
statistical profile at 30 samples. That is not a model. M22 requires its own,
configurable minimum — 100 by default — so a device can legitimately be
``established`` in M21 and ``collecting_data`` here. Both facts are true, and
conflating them would present a forest fitted on twenty minutes of traffic as a
description of a device's behaviour.

## What a training pass returns

:class:`TrainingResult` is a value rather than an exception, because "not enough
data" is an expected answer about a real device, not a fault. Only a genuine
library failure raises, and the lifecycle module converts that into a ``failed``
state while preserving the previous working model.

## Cold-start honesty

The initial dataset has no trusted anomaly history, so it may contain behaviour
M22 would later recognise as unusual. Isolation Forest cannot guarantee that its
first training set is benign, and neither does this module: it fits exactly the
data it was given and records how many windows that was.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.anomaly_detection.dataset import TrainingDataset
from app.anomaly_detection.features import (
    FEATURE_SCHEMA_VERSION,
    FeatureVector,
    build_feature_vector,
)
from app.anomaly_detection.model import FittedModel, ModelConfig, build_model
from app.anomaly_detection.preprocessing import (
    DEFAULT_MIN_AVAILABILITY,
    PreprocessingPlan,
    build_plan,
    to_matrix,
)

#: Stable codes explaining why a training pass produced no model.
REASON_INSUFFICIENT_WINDOWS = "insufficient_training_windows"
REASON_INSUFFICIENT_FEATURES = "insufficient_usable_features"
REASON_EMPTY_DATASET = "no_historical_windows"


@dataclass(frozen=True)
class TrainingResult:
    """What one training pass produced (M22.7).

    Attributes:
        model: The fitted forest, or ``None`` when the pass could not train.
        plan: The preprocessing plan the model consumes, or the plan that was
            rejected when training stopped for lack of features.
        reason: A stable code naming why no model was produced, or ``None``.
        training_sample_count: Usable windows the forest was fitted on.
        training_window_count: Windows the dataset reader offered.
        excluded_anomalies: Previously flagged windows withheld from training.
        algorithm: The algorithm label, so a caller never has to guess.
        feature_availability: Per-feature share of windows that carried a value,
            so the API can show *why* a feature was dropped.
    """

    model: FittedModel | None
    plan: PreprocessingPlan
    reason: str | None = None
    training_sample_count: int = 0
    training_window_count: int = 0
    excluded_anomalies: int = 0
    algorithm: str = "isolation_forest"
    feature_availability: dict[str, float] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        """Return True when this pass produced a usable model."""
        return self.model is not None


def build_vectors(windows: list[Any]) -> list[FeatureVector]:
    """Extract a feature vector for each window, skipping unusable windows.

    A window that yielded no feature at all is dropped rather than kept as an
    all-imputed row: a training set padded with entirely fabricated samples would
    teach the forest that "unknown" is the most normal behaviour there is.

    Args:
        windows: The historical observation windows.

    Returns:
        One vector per window that carried at least one feature.
    """
    vectors: list[FeatureVector] = []
    for window in windows:
        vector = build_feature_vector(window)
        if vector.values:
            vectors.append(vector)
    return vectors


def train_model(
    dataset: TrainingDataset,
    *,
    config: ModelConfig,
    min_training_windows: int,
    min_availability: float = DEFAULT_MIN_AVAILABILITY,
    plan: PreprocessingPlan | None = None,
) -> TrainingResult:
    """Fit a device's Isolation Forest from its historical windows (M22.5).

    Args:
        dataset: The windows the reader selected, strictly before the evaluated
            window. The cutoff is the reader's responsibility, because it is a
            property of the query rather than of the fitting.
        config: The Isolation Forest configuration.
        min_training_windows: M22's own minimum usable-window requirement.
        min_availability: Share of windows that must carry a feature for it to be
            used.
        plan: A previously stored plan to reuse. Supplying one keeps the model's
            columns stable across a refresh, so a retrain cannot silently change
            what the forest is looking at. When ``None`` a plan is built from the
            data.

    Returns:
        The pass result. ``reason`` is set and ``model`` is ``None`` when the
        device does not yet have enough usable history — an expected answer
        rather than a failure.

    Raises:
        ValueError: If ``min_training_windows`` is below one, which would produce
            a model from nothing.
    """
    if min_training_windows < 1:
        raise ValueError("min_training_windows must be at least 1")

    vectors = build_vectors(dataset.windows)
    if not vectors:
        fallback = plan or PreprocessingPlan(min_availability=min_availability)
        return TrainingResult(
            model=None,
            plan=fallback,
            reason=REASON_EMPTY_DATASET,
            training_window_count=dataset.offered,
            excluded_anomalies=dataset.excluded_anomalies,
            algorithm=config.algorithm,
            feature_availability=dict(fallback.availability),
        )

    active_plan = (
        plan
        if plan is not None and plan.is_usable
        else build_plan(vectors, min_availability=min_availability)
    )
    if not active_plan.is_usable:
        return TrainingResult(
            model=None,
            plan=active_plan,
            reason=REASON_INSUFFICIENT_FEATURES,
            training_window_count=dataset.offered,
            excluded_anomalies=dataset.excluded_anomalies,
            algorithm=config.algorithm,
            feature_availability=dict(active_plan.availability),
        )

    if len(vectors) < min_training_windows:
        return TrainingResult(
            model=None,
            plan=active_plan,
            reason=REASON_INSUFFICIENT_WINDOWS,
            training_sample_count=len(vectors),
            training_window_count=dataset.offered,
            excluded_anomalies=dataset.excluded_anomalies,
            algorithm=config.algorithm,
            feature_availability=dict(active_plan.availability),
        )

    matrix = to_matrix(vectors, active_plan)
    model = build_model(config=config, plan=active_plan)
    model.fit(matrix)
    return TrainingResult(
        model=model,
        plan=active_plan,
        training_sample_count=len(matrix),
        training_window_count=dataset.offered,
        excluded_anomalies=dataset.excluded_anomalies,
        algorithm=config.algorithm,
        feature_availability=dict(active_plan.availability),
    )


def rebuild_vectors(
    windows: list[Any], plan: PreprocessingPlan
) -> list[FeatureVector]:
    """Extract vectors for windows, retaining those the plan can handle.

    Used when reconstructing a model after a restart: the stored plan defines the
    columns, so a window that carries none of them contributes nothing.
    """
    vectors: list[FeatureVector] = []
    for window in windows:
        vector = build_feature_vector(window)
        if any(name in vector.values for name in plan.feature_names):
            vectors.append(vector)
    return vectors


def to_naive_utc(when: datetime) -> datetime:
    """Return ``when`` as a naive UTC datetime.

    Windows and model rows are stored as naive UTC throughout the project, so the
    value written here matches what a reader compares it against.
    """
    if when.tzinfo is None:
        return when
    return when.astimezone(timezone.utc).replace(tzinfo=None)


__all__ = [
    "FEATURE_SCHEMA_VERSION",
    "REASON_EMPTY_DATASET",
    "REASON_INSUFFICIENT_FEATURES",
    "REASON_INSUFFICIENT_WINDOWS",
    "TrainingResult",
    "build_vectors",
    "rebuild_vectors",
    "to_naive_utc",
    "train_model",
]
