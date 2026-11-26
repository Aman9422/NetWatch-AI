"""Scoring one completed observation window (M22.8/M22.9).

Two things happen here, and they must stay visually and structurally distinct:

* **the model's own verdict** — the raw Isolation Forest decision score and its
  binary classification, stored unmodified;
* **a statistical comparison against the training set** — the observed value, the
  training median, the scaled MAD, and the difference, per feature.

The second is *context for a human*, not feature attribution. Isolation Forest
does not identify which feature caused a prediction, and no validated explanation
method is implemented here, so this module never claims that it does (M22.9).

## What the context can and cannot say

For each feature the model actually consumes, the context records:

* the observed value for this window, or that it was not measured / truncated;
* the median of the training windows and their scaled MAD;
* the difference from that median;
* whether the deviation is large relative to the training spread.

A large deviation is reported as *far from the training centre*, which is a
statement about the data. It is **not** reported as "the cause" of the anomaly
flag: a window can be flagged on the interaction of several mildly unusual
features, and a feature can be far from its median without the model reacting to
it at all. The wording in the API and the UI keeps that distinction.

## Why the cutoff lives one level up

:func:`evaluate_window` receives an already-fitted model and an already-selected
training set. It deliberately cannot fetch either, because fetching is where a
self-training leak could be introduced (M22.8) and the query that prevents it
belongs in one place — :mod:`app.anomaly_detection.dataset`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median
from typing import Any

from app.anomaly_detection.features import (
    FeatureVector,
    build_feature_vector,
)
from app.anomaly_detection.model import FittedModel
from app.anomaly_detection.preprocessing import to_row

#: Multiplier that turns a raw MAD into a consistent sigma estimate for normal
#: data. The same constant M21 reports, repeated here so a reader comparing a
#: profile figure with a context figure is comparing like with like.
MAD_TO_STDEV = 1.4826

#: How far from the training median, in scaled MADs, a value must sit before the
#: context calls it *far from the training centre*. Deliberately a descriptive
#: threshold rather than a decision boundary: the model's own label decides
#: whether a window is anomalous, and this only decides how a comparison is
#: described in words.
FAR_FROM_CENTRE_MADS = 3.0

#: Reported when a feature is so tightly clustered that any difference would be an
#: infinite number of MADs. A zero MAD is a real state (every training window had
#: exactly the same value), so it is described rather than divided by.
ZERO_SPREAD_LABEL = "no_spread_in_training"


@dataclass(frozen=True)
class FeatureContext:
    """One feature's comparison against the training set (M22.9).

    Attributes:
        feature: The feature name.
        observed: This window's value, or ``None`` when it was not measured.
        training_median: Median of the training windows for this feature.
        training_mad: Median absolute deviation of the training windows.
        training_mad_scaled: ``mad * 1.4826``, a robust sigma estimate.
        difference: ``observed - training_median``, or ``None``.
        deviation_mads: ``|difference| / mad_scaled``, or ``None`` when the
            training spread is zero and the ratio would be meaningless.
        missing_reason: Why the observed value is absent, when it is.
        far_from_centre: True when the deviation is large relative to the
            training spread. **A description of the data, not a cause.**
    """

    feature: str
    observed: float | None
    training_median: float
    training_mad: float
    training_mad_scaled: float
    difference: float | None
    deviation_mads: float | None
    missing_reason: str | None = None
    far_from_centre: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Render as the JSON document stored on the evaluation row."""
        return {
            "feature": self.feature,
            "observed": self.observed,
            "training_median": self.training_median,
            "training_mad": self.training_mad,
            "training_mad_scaled": self.training_mad_scaled,
            "difference": self.difference,
            "deviation_mads": self.deviation_mads,
            "missing_reason": self.missing_reason,
            "far_from_centre": self.far_from_centre,
        }


@dataclass(frozen=True)
class InferenceResult:
    """The outcome of scoring one window (M22.9).

    Attributes:
        scored: True when the model produced a verdict.
        decision_score: Raw ``decision_function`` output; lower is more unusual.
            ``None`` when no verdict was produced. **Never a probability.**
        is_anomaly: The model's binary classification.
        feature_context: The bounded per-feature comparison, one entry per model
            feature.
        reason: Why no verdict was produced, when none was.
    """

    scored: bool
    decision_score: float | None = None
    is_anomaly: bool = False
    feature_context: list[FeatureContext] = field(default_factory=list)
    reason: str | None = None

    def context_documents(self) -> list[dict[str, Any]]:
        """Render the feature context for persistence."""
        return [entry.to_dict() for entry in self.feature_context]


def build_context(
    vector: FeatureVector,
    training_vectors: list[FeatureVector],
    *,
    feature_names: tuple[str, ...],
) -> list[FeatureContext]:
    """Compare one window against the training windows, feature by feature.

    Args:
        vector: The window being evaluated.
        training_vectors: The windows the model was fitted on, used as the
            reference distribution.
        feature_names: The model's feature order. Only features the model
            actually consumes are described, because a comparison for a feature
            the model ignores would invite a reader to attribute the verdict to
            it.

    Returns:
        One entry per model feature, in the model's order so two evaluations
        present the same sequence.
    """
    contexts: list[FeatureContext] = []
    for name in feature_names:
        observed = vector.values.get(name)
        observed_values = [
            item.values[name] for item in training_vectors if name in item.values
        ]
        if not observed_values:
            # The model has this column but no training window carried it. The
            # plan's fill value was used at fit time, so there is nothing honest
            # to compare against.
            contexts.append(
                FeatureContext(
                    feature=name,
                    observed=observed,
                    training_median=0.0,
                    training_mad=0.0,
                    training_mad_scaled=0.0,
                    difference=None,
                    deviation_mads=None,
                    missing_reason="no_training_values",
                )
            )
            continue
        centre = float(median(observed_values))
        mad = float(median([abs(value - centre) for value in observed_values]))
        scaled = mad * MAD_TO_STDEV
        difference = None if observed is None else observed - centre
        deviation = None
        far = False
        if difference is not None and scaled > 0:
            deviation = abs(difference) / scaled
            far = deviation >= FAR_FROM_CENTRE_MADS
        elif difference is not None and difference != 0:
            # Every training window had the same value and this one differs. The
            # ratio would be infinite, so the fact is described rather than
            # divided by zero.
            far = True
        contexts.append(
            FeatureContext(
                feature=name,
                observed=observed,
                training_median=centre,
                training_mad=mad,
                training_mad_scaled=scaled,
                difference=difference,
                deviation_mads=deviation,
                missing_reason=(
                    None if observed is not None else vector.missing_reasons.get(name)
                ),
                far_from_centre=far,
            )
        )
    return contexts


def evaluate_window(
    window: Any,
    *,
    model: FittedModel,
    training_vectors: list[FeatureVector],
) -> InferenceResult:
    """Score one completed window and describe it (M22.9).

    Args:
        window: The completed M21 observation window.
        model: The fitted forest to score with. Its plan defines the columns.
        training_vectors: The windows it was fitted on, used only to describe the
            values the window is being compared with.

    Returns:
        The verdict and its context. A window that carries none of the model's
        features is reported as unscored rather than scored against a row of pure
        imputation: an all-imputed row is not a measurement of anything.
    """
    vector = build_feature_vector(window)
    if not any(name in vector.values for name in model.feature_names):
        return InferenceResult(
            scored=False, reason="no_usable_features_for_model"
        )
    row = to_row(vector, model.plan)
    result = model.score(row)
    return InferenceResult(
        scored=True,
        decision_score=result.decision_score,
        is_anomaly=result.is_anomaly,
        feature_context=build_context(
            vector, training_vectors, feature_names=model.feature_names
        ),
    )


__all__ = [
    "FAR_FROM_CENTRE_MADS",
    "MAD_TO_STDEV",
    "ZERO_SPREAD_LABEL",
    "FeatureContext",
    "InferenceResult",
    "build_context",
    "evaluate_window",
]
