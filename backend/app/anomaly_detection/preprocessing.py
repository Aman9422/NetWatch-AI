"""Feature eligibility and imputation (M22.6).

Training and inference must see the same numbers in the same columns, or the
model answers a different question at scoring time than it learned at fitting
time. This module is the single plan that guarantees that: it decides which
features are usable at all and — for the ones that are — what value to substitute
when a single window happens not to carry one.

## Eligibility

A feature is retained only when it is present in at least ``min_availability`` of
the training windows (default 0.8). Below that threshold the feature is mostly
absent, and imputing the missing 40% of a column would mean the model is largely
trained on the imputed value rather than on the measurement. ``new_connections``
is the realistic case: M21 stores it as NULL for every window the connection
tracker could not measure.

A model needs at least :data:`MIN_MODEL_FEATURES` usable features. One column is
not a behavioural description of a device, and an Isolation Forest fitted to a
single feature is a threshold detector wearing a model's name.

## Imputation

The strategy is deliberately the simplest one that cannot invent behaviour: the
**median of the available training values**. It is documented, it is robust to
the outlier that makes a mean imputation wrong in exactly this domain, and —
because it is computed from the training set and stored *with the model* —
inference uses the identical number. A zero fill is explicitly rejected: zero is
a real measurement (a quiet minute), so filling a missing packet count with zero
would assert "this device sent nothing", a claim the data does not support.

## Why the plan is persisted

The plan is stored on the model row as JSON, so a restart reconstructs the model
from M21's retained windows plus this plan. No Python pickle is written, read or
trusted — M22.7 forbids loading a model artifact from an untrusted path, and this
is how that requirement is met without giving up restart recovery.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from typing import Any

from app.anomaly_detection.features import FEATURE_NAMES, FeatureVector

#: A feature must be present in at least this share of training windows.
DEFAULT_MIN_AVAILABILITY = 0.8

#: A model needs at least this many usable features.
MIN_MODEL_FEATURES = 2

#: Version of the preprocessing rules themselves, stored beside the feature
#: schema version so a model can refuse a plan produced by different rules.
PREPROCESSING_VERSION = 1

#: Why a feature was excluded from a model, as a stable code.
EXCLUDED_TOO_MISSING = "insufficient_availability"


@dataclass(frozen=True)
class PreprocessingPlan:
    """Which features a model uses, and what to substitute when one is missing.

    Attributes:
        feature_names: The ordered feature list. **Order is part of the model's
            identity** — training and inference build their matrix in this
            sequence, so a reordered list would silently swap columns.
        fill_values: Feature name → the imputation value, computed from the
            training windows as their median.
        availability: Feature name → the share of training windows that carried
            it, so a reader can see how much of a column was measured.
        excluded: Feature name → the reason it was dropped. Recorded rather than
            discarded, because "this device's connection counts were too often
            unmeasurable to model" is a real statement about the data.
        min_availability: The threshold the plan was built with.
        version: The preprocessing rule version.
    """

    feature_names: tuple[str, ...] = ()
    fill_values: dict[str, float] = field(default_factory=dict)
    availability: dict[str, float] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)
    min_availability: float = DEFAULT_MIN_AVAILABILITY
    version: int = PREPROCESSING_VERSION

    @property
    def is_usable(self) -> bool:
        """Return True when this plan can support a model at all."""
        return len(self.feature_names) >= MIN_MODEL_FEATURES

    def to_dict(self) -> dict[str, object]:
        """Render the plan as the JSON document stored on the model row."""
        return {
            "feature_names": list(self.feature_names),
            "fill_values": dict(self.fill_values),
            "availability": dict(self.availability),
            "excluded": dict(self.excluded),
            "min_availability": self.min_availability,
            "version": self.version,
        }

    def to_json(self) -> str:
        """Serialise the plan for persistence."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(
        cls, document: dict[str, Any] | None
    ) -> "PreprocessingPlan | None":
        """Rebuild a stored plan, or ``None`` when it cannot be read.

        Tolerant by design: a row written by an earlier run must remain readable,
        and a plan that cannot be reconstructed is reported as absent — the
        caller then retrains rather than scoring with a plan it does not have. A
        stored feature name this build no longer knows is dropped, because a
        model whose columns this build cannot name cannot be fed correctly.
        """
        if not isinstance(document, dict):
            return None
        raw_names = document.get("feature_names")
        if not isinstance(raw_names, list):
            return None
        names = tuple(str(name) for name in raw_names if str(name) in FEATURE_NAMES)
        if not names:
            return None
        raw_fills = document.get("fill_values")
        if not isinstance(raw_fills, dict):
            return None
        fills: dict[str, float] = {}
        for name in names:
            try:
                fills[name] = float(raw_fills[name])
            except (KeyError, TypeError, ValueError):
                # A feature without a stored fill cannot be imputed, so the whole
                # plan is unusable rather than half of it.
                return None
        availability: dict[str, float] = {}
        raw_availability = document.get("availability")
        if isinstance(raw_availability, dict):
            for name, value in raw_availability.items():
                try:
                    availability[str(name)] = float(value)
                except (TypeError, ValueError):
                    continue
        excluded: dict[str, str] = {}
        raw_excluded = document.get("excluded")
        if isinstance(raw_excluded, dict):
            excluded = {str(key): str(value) for key, value in raw_excluded.items()}
        try:
            min_availability = float(
                document.get("min_availability", DEFAULT_MIN_AVAILABILITY)
            )
        except (TypeError, ValueError):
            min_availability = DEFAULT_MIN_AVAILABILITY
        try:
            version = int(document.get("version", PREPROCESSING_VERSION))
        except (TypeError, ValueError):
            version = PREPROCESSING_VERSION
        return cls(
            feature_names=names,
            fill_values=fills,
            availability=availability,
            excluded=excluded,
            min_availability=min_availability,
            version=version,
        )

    @classmethod
    def from_json(cls, raw: str | None) -> "PreprocessingPlan | None":
        """Rebuild a plan from its stored JSON, or ``None``."""
        if not raw:
            return None
        try:
            document = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return cls.from_dict(document)


def build_plan(
    vectors: list[FeatureVector],
    *,
    min_availability: float = DEFAULT_MIN_AVAILABILITY,
) -> PreprocessingPlan:
    """Choose the features a model may use and the value to impute each with.

    Args:
        vectors: The training windows, already extracted.
        min_availability: Share of windows that must carry a feature for it to be
            retained, in ``[0, 1]``.

    Returns:
        The plan, with ``feature_names`` in canonical order, so two runs over the
        same data produce the same matrix.

    Raises:
        ValueError: If ``min_availability`` is outside ``[0, 1]``. A threshold
            above 1 would exclude everything and one below 0 would retain a
            feature with no values at all, and neither should be accepted
            silently.
    """
    if not 0.0 <= min_availability <= 1.0:
        raise ValueError("min_availability must be between 0 and 1")
    total = len(vectors)
    if total == 0:
        return PreprocessingPlan(min_availability=min_availability)

    names: list[str] = []
    fills: dict[str, float] = {}
    availability: dict[str, float] = {}
    excluded: dict[str, str] = {}
    for name in FEATURE_NAMES:
        observed = [vector.values[name] for vector in vectors if name in vector.values]
        share = len(observed) / total
        availability[name] = share
        if not observed or share < min_availability:
            excluded[name] = EXCLUDED_TOO_MISSING
            continue
        names.append(name)
        # The median, not the mean: the outlier that drags a mean is exactly the
        # burst this detector exists to notice.
        fills[name] = float(statistics.median(observed))
    return PreprocessingPlan(
        feature_names=tuple(names),
        fill_values=fills,
        availability=availability,
        excluded=excluded,
        min_availability=min_availability,
    )


def to_matrix(
    vectors: list[FeatureVector], plan: PreprocessingPlan
) -> list[list[float]]:
    """Build the positional model matrix for a list of vectors.

    Applies exactly the plan's feature order and imputation, so the training
    matrix and an inference row come from one code path — the property M22.6
    requires ("use precisely the same preprocessing during inference").

    Args:
        vectors: The windows to convert.
        plan: The plan to apply. Its order defines the column meaning.

    Returns:
        One row per vector, one value per planned feature.
    """
    return [to_row(vector, plan) for vector in vectors]


def to_row(vector: FeatureVector, plan: PreprocessingPlan) -> list[float]:
    """Build one positional model row. The inference counterpart of a matrix."""
    return [
        vector.values[name] if name in vector.values else plan.fill_values[name]
        for name in plan.feature_names
    ]


__all__ = [
    "DEFAULT_MIN_AVAILABILITY",
    "EXCLUDED_TOO_MISSING",
    "MIN_MODEL_FEATURES",
    "PREPROCESSING_VERSION",
    "PreprocessingPlan",
    "build_plan",
    "to_matrix",
    "to_row",
]
