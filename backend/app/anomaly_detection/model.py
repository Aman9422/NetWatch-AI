"""Isolation Forest construction and scoring (M22.4/M22.9).

One algorithm, wrapped once. Everything above this module talks to
:class:`FittedModel` and never to scikit-learn directly, which is what M22.4 asks
for: construction sits behind a dedicated interface, so a later milestone can add
a second algorithm without touching the packet pipeline, the store or the API.

## What the model is allowed to say

``predict()`` returns ``-1`` for an outlier and ``1`` for an inlier;
``decision_function()`` returns a score where **lower means more unusual**.
:meth:`FittedModel.score` returns both, unmodified and unlabelled:

* the score is **not** a probability and is never converted into one here;
* the classification is "differs from what was learned", never "malicious".

A caller wanting a display transformation must do it above this module and
document it, so the raw value stored in the database stays the model's own
answer (M22.9).

## Reproducibility

``random_state`` is stored with the configuration, so two runs over the same
training matrix produce the same forest. That is what makes the milestone's
numbers reproducible rather than anecdotal.

## Why the estimator is not persisted

No pickle is written to disk (M22.7). A model is reconstructed by retraining from
the retained M21 windows plus the stored preprocessing plan, and until that
succeeds the device is reported as unavailable rather than as having a model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.anomaly_detection.preprocessing import PreprocessingPlan

#: Algorithm label used throughout M22.
ALGORITHM_ISOLATION_FOREST = "isolation_forest"

#: The configuration the milestone suggests as a starting point. Defaults, not
#: tuned values: the project has no labelled production dataset, so claiming an
#: optimum would be claiming evidence that does not exist (M22.16).
DEFAULT_N_ESTIMATORS = 100
DEFAULT_CONTAMINATION = 0.02
DEFAULT_RANDOM_STATE = 42

#: ``predict`` returns this for an outlier, and its negation for an inlier.
OUTLIER_LABEL = -1

#: Smallest training set scikit-learn can fit an Isolation Forest to. M22.5's own
#: minimum is far higher; this is the library's floor, checked so the failure is
#: ours and says why.
MIN_FIT_SAMPLES = 2


@dataclass(frozen=True)
class ModelConfig:
    """The Isolation Forest configuration stored with a model (M22.4).

    Attributes:
        n_estimators: Number of trees in the forest.
        contamination: The proportion of the training set the model expects to be
            unusual. Passed through unmodified, because it defines where
            ``predict`` places its boundary, and a silently clamped value would
            make the stored configuration disagree with the behaviour.
        random_state: Seed, so a training run is reproducible.
        algorithm: The algorithm name, stored rather than assumed.
    """

    n_estimators: int = DEFAULT_N_ESTIMATORS
    contamination: float = DEFAULT_CONTAMINATION
    random_state: int = DEFAULT_RANDOM_STATE
    algorithm: str = ALGORITHM_ISOLATION_FOREST

    def __post_init__(self) -> None:
        """Validate the configuration.

        Raises:
            ValueError: If the tree count is below one or the contamination is
                outside ``(0, 0.5]``. A contamination of zero would make every
                window an inlier — a detector that never fires — and above 0.5
                the "unusual" class would be the majority.
        """
        if self.n_estimators < 1:
            raise ValueError("n_estimators must be at least 1")
        if not 0.0 < self.contamination <= 0.5:
            raise ValueError("contamination must be in (0, 0.5]")

    def to_dict(self) -> dict[str, object]:
        """Render the configuration as the JSON document stored on the model."""
        return {
            "algorithm": self.algorithm,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any] | None) -> "ModelConfig | None":
        """Rebuild a stored configuration, or ``None`` when unreadable.

        A stored config that no longer validates is reported as absent rather
        than coerced into something valid: a model trained with a parameter this
        build would not accept is a model whose behaviour cannot be reproduced.
        """
        if not isinstance(document, dict):
            return None
        try:
            return cls(
                n_estimators=int(document.get("n_estimators", DEFAULT_N_ESTIMATORS)),
                contamination=float(
                    document.get("contamination", DEFAULT_CONTAMINATION)
                ),
                random_state=int(document.get("random_state", DEFAULT_RANDOM_STATE)),
                algorithm=str(document.get("algorithm", ALGORITHM_ISOLATION_FOREST)),
            )
        except (TypeError, ValueError):
            return None


@dataclass(frozen=True)
class ScoreResult:
    """One window's model output, exactly as the model produced it (M22.9).

    Attributes:
        decision_score: ``decision_function`` output. Lower is more unusual.
            **Not a probability**, and never presented as one.
        is_anomaly: ``predict`` returned the outlier label.
    """

    decision_score: float
    is_anomaly: bool


def _import_isolation_forest() -> Any:
    """Return scikit-learn's ``IsolationForest``, importing it lazily.

    The import is inside the function so importing the anomaly package — for its
    vocabulary, its feature extraction or its store — never loads scikit-learn and
    its numeric stack. Only a caller that actually trains or scores pays that
    cost.

    Raises:
        RuntimeError: If scikit-learn is not installed. The message names the
            missing dependency, because an operator needs to know that anomaly
            detection is unavailable for an environment reason rather than
            because the traffic looked fine.
    """
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "scikit-learn is required for anomaly detection and is not installed"
        ) from exc
    return IsolationForest


class FittedModel:
    """A fitted Isolation Forest together with the plan that feeds it (M22.4).

    The two travel together deliberately: a matrix built with one plan and scored
    by a forest fitted on another is the quietest possible bug in this milestone,
    and holding them in one object makes it impossible to have one without the
    other.
    """

    def __init__(self, *, config: ModelConfig, plan: PreprocessingPlan) -> None:
        """Create an unfitted model.

        Args:
            config: The Isolation Forest configuration.
            plan: The preprocessing plan defining feature order and fill values.

        Raises:
            ValueError: If the plan has fewer than two features, which cannot
                describe behaviour (see
                :data:`app.anomaly_detection.preprocessing.MIN_MODEL_FEATURES`).
        """
        if not plan.is_usable:
            raise ValueError(
                "a preprocessing plan with fewer than two features cannot support a model"
            )
        self._config = config
        self._plan = plan
        self._estimator: Any = None
        self._training_sample_count = 0

    # -- properties -------------------------------------------------------

    @property
    def config(self) -> ModelConfig:
        """Return the configuration this model was built with."""
        return self._config

    @property
    def plan(self) -> PreprocessingPlan:
        """Return the preprocessing plan defining its columns."""
        return self._plan

    @property
    def feature_names(self) -> tuple[str, ...]:
        """Return the ordered feature list this model consumes."""
        return self._plan.feature_names

    @property
    def is_fitted(self) -> bool:
        """Return True once a forest has been fitted."""
        return self._estimator is not None

    @property
    def training_sample_count(self) -> int:
        """Return how many rows the forest was fitted on."""
        return self._training_sample_count

    # -- fitting ----------------------------------------------------------

    def fit(self, matrix: list[list[float]]) -> None:
        """Fit the forest to a positional matrix.

        Args:
            matrix: One row per training window, one column per planned feature.

        Raises:
            ValueError: If there are too few rows, or a row's width disagrees
                with the plan. A width mismatch means the matrix was not built by
                this plan, and fitting anyway would silently mislabel columns.
        """
        if len(matrix) < MIN_FIT_SAMPLES:
            raise ValueError(
                f"an Isolation Forest needs at least {MIN_FIT_SAMPLES} samples"
            )
        width = len(self._plan.feature_names)
        for row in matrix:
            if len(row) != width:
                raise ValueError(
                    f"training row has {len(row)} values, expected {width}"
                )
        estimator_class = _import_isolation_forest()
        estimator = estimator_class(
            n_estimators=self._config.n_estimators,
            contamination=self._config.contamination,
            random_state=self._config.random_state,
            # One thread: this runs on a background consumer beside packet
            # capture, and a thread pool competing with the capture thread for
            # cores is a real cost for a hundred trees over ~1,400 rows.
            n_jobs=1,
        )
        estimator.fit(matrix)
        self._estimator = estimator
        self._training_sample_count = len(matrix)

    # -- scoring ----------------------------------------------------------

    def score(self, row: list[float]) -> ScoreResult:
        """Score one window and return the model's own output (M22.9).

        Args:
            row: One row in this model's feature order, from
                :func:`app.anomaly_detection.preprocessing.to_row`.

        Returns:
            The raw decision score and the outlier classification.

        Raises:
            RuntimeError: If the model has not been fitted.
            ValueError: If the row's width disagrees with the plan.
        """
        if self._estimator is None:
            raise RuntimeError("the model has not been fitted")
        width = len(self._plan.feature_names)
        if len(row) != width:
            raise ValueError(f"inference row has {len(row)} values, expected {width}")
        scores = self._estimator.decision_function([row])
        labels = self._estimator.predict([row])
        return ScoreResult(
            decision_score=float(scores[0]),
            is_anomaly=int(labels[0]) == OUTLIER_LABEL,
        )

    def decision_scores(self, matrix: list[list[float]]) -> list[float]:
        """Return the raw decision score of each row, for verification scripts.

        Lets a harness report what the model actually said about a synthetic set
        rather than paraphrasing it.
        """
        if self._estimator is None:
            raise RuntimeError("the model has not been fitted")
        return [float(value) for value in self._estimator.decision_function(matrix)]


def build_model(*, config: ModelConfig, plan: PreprocessingPlan) -> FittedModel:
    """Construct an unfitted model for a configuration and plan (M22.4)."""
    return FittedModel(config=config, plan=plan)


__all__ = [
    "ALGORITHM_ISOLATION_FOREST",
    "DEFAULT_CONTAMINATION",
    "DEFAULT_N_ESTIMATORS",
    "DEFAULT_RANDOM_STATE",
    "MIN_FIT_SAMPLES",
    "OUTLIER_LABEL",
    "FittedModel",
    "ModelConfig",
    "ScoreResult",
    "build_model",
]
