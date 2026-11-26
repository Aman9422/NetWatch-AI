"""Wire schemas for ML anomaly detection (M22.12/M22.13).

These models are the serialisable projection of an
:class:`app.anomaly_detection.evaluation_store.EvaluationSnapshot` and an
:class:`app.anomaly_detection.model_store.ModelSnapshot`.

Three claims this module refuses to make:

* **No probability.** The stored field is ``decision_score`` — the raw output of
  ``IsolationForest.decision_function`` — documented in the field description and
  in the disclaimer as *not* a probability, a confidence or a calibrated risk.
  Nothing here is called ``probability``, ``confidence`` or ``likelihood``.
* **No attribution.** Feature context entries compare an observed value against
  M21's statistical profile (median, difference, scaled MADs). Isolation Forest
  does not report which feature caused a prediction, so no field here claims it
  does.
* **No verdict of malice.** Every anomaly payload carries the disclaimer stating
  that a deviation from learned behaviour is not confirmation of an attack.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.anomaly_detection.evaluation_store import EvaluationSnapshot
from app.anomaly_detection.model_store import ModelSnapshot
from app.anomaly_detection.states import describe_state
from app.schemas.baseline import to_iso

#: The sentence every anomaly payload carries (M22.13). Stated once so the API,
#: the page and the documentation cannot drift apart.
ANOMALY_DISCLAIMER = (
    "An anomaly indicates a deviation from previously observed network behaviour. "
    "It is not confirmation of malicious activity."
)

#: What the decision score is, and is not (M22.9).
DECISION_SCORE_NOTE = (
    "Raw Isolation Forest decision_function output. Lower is more unusual. It is "
    "not a probability, not a calibrated confidence, and not comparable between "
    "models trained on different devices."
)

#: Human labels for the nine M21 features.
FEATURE_LABELS: dict[str, str] = {
    "packet_count": "Packets per window",
    "byte_count": "Bytes per window",
    "tcp_packets": "TCP packets per window",
    "udp_packets": "UDP packets per window",
    "icmp_packets": "ICMP packets per window",
    "dns_packets": "DNS packets per window",
    "unique_peers": "Distinct peers per window",
    "unique_destination_ports": "Distinct destination ports per window",
    "new_connections": "New conversations per window",
}

#: Short badge text per model state, for the frontend (M22.13).
STATE_LABELS: dict[str, str] = {
    "collecting_data": "Collecting data",
    "training": "Training",
    "ready": "Ready",
    "stale": "Stale",
    "failed": "Failed",
    "disabled": "Disabled",
}

#: States in which a model may legitimately score a window.
_SCORING_STATES = frozenset({"ready", "stale"})


class FeatureContextView(BaseModel):
    """One feature's observed value next to M21's baseline statistics (M22.9).

    This is a *statistical comparison*, not model feature attribution. The field
    descriptions say so, because a reader who sees a large deviation will
    otherwise assume the forest used it.
    """

    feature: str
    label: str
    observed: float | None = Field(
        default=None, description="The value observed in the evaluated window"
    )
    baseline_median: float | None = Field(
        default=None,
        description="M21 profile median for this feature, when a profile exists",
    )
    difference: float | None = Field(
        default=None,
        description="observed minus baseline median; a comparison, not an attribution",
    )
    deviation_mads: float | None = Field(
        default=None,
        description="difference in scaled MADs, when the deviation is non-zero",
    )
    far_from_centre: bool = Field(
        default=False,
        description="True when the deviation exceeds the documented threshold",
    )
    missing: bool = Field(
        default=False, description="True when the feature was absent from the window"
    )
    truncated: bool = Field(
        default=False,
        description="True when a cardinality hit a cap, so the value is a floor",
    )


class AnomalyView(BaseModel):
    """One evaluated observation window (M22.12).

    Attributes:
        evaluation_id: Stable identifier of this verdict.
        device_key: The M8 identity the window belongs to.
        window_start / window_seconds: The evaluated window.
        algorithm: ``isolation_forest``.
        model_version: Which fitted model produced the score. ``0`` means no model
            was involved because the row is a skip or a failure.
        model_trained_at: When that model was trained.
        training_sample_count: How many historical windows it was trained on.
        contamination: The contamination the model was fitted with.
        decision_score: Raw decision_function output, or ``None`` when not scored.
        is_anomaly: The model's classification. Only meaningful when scored.
        status: ``scored``, ``skipped`` or ``failed``. A skip is not a "normal"
            verdict — it is the absence of one, and the frontend must never render
            it as healthy.
        skip_reason: Stable code explaining a skip.
        feature_context: Per-feature comparison against the M21 profile.
        alert_id: The alert this verdict produced, when one was created.
        created_at: When the verdict was recorded.
    """

    evaluation_id: int
    device_key: str
    window_start: str
    window_seconds: float
    algorithm: str
    model_version: int
    model_trained_at: str | None = None
    training_sample_count: int
    contamination: float | None = None
    decision_score: float | None = None
    is_anomaly: bool
    status: str
    skip_reason: str | None = None
    feature_context: list[FeatureContextView] = Field(default_factory=list)
    alert_id: int | None = None
    created_at: str | None = None
    decision_score_note: str = DECISION_SCORE_NOTE
    disclaimer: str = ANOMALY_DISCLAIMER

    @classmethod
    def from_snapshot(
        cls, snapshot: EvaluationSnapshot, *, include_context: bool = True
    ) -> "AnomalyView":
        """Project a stored evaluation onto the wire shape.

        Args:
            snapshot: The verdict as the store read it.
            include_context: Whether to carry the per-feature comparison. Omitted
                from the listing, which shows many windows and needs only the
                verdict itself.
        """
        context = (
            [_to_context_view(entry) for entry in snapshot.feature_context]
            if include_context
            else []
        )
        context.sort(key=lambda view: _feature_rank(view.feature))
        return cls(
            evaluation_id=snapshot.evaluation_id,
            device_key=snapshot.device_key,
            window_start=to_iso(snapshot.window_start) or "",
            window_seconds=snapshot.window_seconds,
            algorithm=snapshot.algorithm,
            model_version=snapshot.model_version,
            model_trained_at=to_iso(snapshot.model_trained_at),
            training_sample_count=snapshot.training_sample_count,
            contamination=snapshot.contamination,
            decision_score=snapshot.decision_score,
            is_anomaly=snapshot.is_anomaly,
            status=snapshot.status,
            skip_reason=snapshot.skip_reason,
            feature_context=context,
            alert_id=snapshot.alert_id,
            created_at=to_iso(snapshot.created_at),
        )


class AnomalyModelView(BaseModel):
    """One device's model lifecycle (M22.12/M22.13).

    ``state`` is the closed vocabulary from :mod:`app.anomaly_detection.states`;
    ``state_description`` explains it in one sentence and ``state_label`` is the
    short badge text. A device in ``collecting_data`` is deliberately *not*
    presented as healthy.
    """

    device_key: str
    identity_kind: str
    algorithm: str
    state: str
    state_label: str
    state_description: str
    model_version: int
    feature_names: list[str] = Field(default_factory=list)
    feature_schema_version: int = 0
    training_sample_count: int = 0
    training_window_count: int = 0
    min_training_windows: int = 0
    contamination: float | None = None
    trained_at: str | None = None
    last_evaluated_at: str | None = None
    windows_since_training: int = 0
    ready: bool = Field(
        default=False, description="True only when this model can score a window"
    )
    last_error: str | None = None
    disclaimer: str = ANOMALY_DISCLAIMER

    @classmethod
    def from_snapshot(cls, snapshot: ModelSnapshot) -> "AnomalyModelView":
        """Project a stored model row onto the wire shape."""
        return cls(
            device_key=snapshot.device_key,
            identity_kind=snapshot.identity_kind,
            algorithm=snapshot.algorithm,
            state=snapshot.state,
            state_label=STATE_LABELS.get(snapshot.state, snapshot.state),
            state_description=describe_state(snapshot.state),
            model_version=snapshot.model_version,
            feature_names=list(snapshot.feature_names),
            feature_schema_version=snapshot.feature_schema_version,
            training_sample_count=snapshot.training_sample_count,
            training_window_count=snapshot.training_window_count,
            min_training_windows=snapshot.min_training_windows,
            contamination=snapshot.contamination,
            trained_at=to_iso(snapshot.trained_at),
            last_evaluated_at=to_iso(snapshot.last_evaluated_at),
            windows_since_training=snapshot.windows_since_training,
            ready=snapshot.has_model and snapshot.state in _SCORING_STATES,
            last_error=snapshot.last_error,
        )


class AnomalySummaryView(BaseModel):
    """Counted totals for the page tiles (M22.13)."""

    evaluations: int = 0
    anomalies: int = 0
    affected_devices: int = 0
    scored: int = 0
    skipped: int = 0


class AnomalyListData(BaseModel):
    """Payload of the anomaly-collection endpoint (M13.24)."""

    count: int = 0
    limit: int | None = None
    offset: int = 0
    total: int | None = None
    has_more: bool | None = None
    anomalies: list[AnomalyView] = Field(default_factory=list)
    summary: AnomalySummaryView = Field(default_factory=AnomalySummaryView)
    disclaimer: str = ANOMALY_DISCLAIMER


class AnomalyModelListData(BaseModel):
    """Payload of the model-collection endpoint (M22.12)."""

    count: int = 0
    limit: int | None = None
    offset: int = 0
    total: int | None = None
    has_more: bool | None = None
    models: list[AnomalyModelView] = Field(default_factory=list)
    disclaimer: str = ANOMALY_DISCLAIMER


class AnomalyRetrainData(BaseModel):
    """Payload of the manual retraining endpoint (M22.12).

    Attributes:
        device_key: The device whose model was retrained.
        requested: Always True — the request reached the training path.
        trained: Whether a new model was produced.
        state: The model state after the attempt.
        state_description: One sentence explaining that state.
        model_version: The model version after the attempt. Unchanged when the
            attempt failed, because a failed retrain preserves the working model.
        training_sample_count: How many windows the current model was trained on.
        previous_model_retained: True when a failed pass kept the previous model
            rather than leaving the device without one.
        reason: A stable code explaining a refusal or failure, when applicable.
        message: A sentence describing the outcome.
    """

    device_key: str
    requested: bool = True
    trained: bool
    state: str
    state_description: str
    model_version: int = 0
    training_sample_count: int = 0
    previous_model_retained: bool = False
    reason: str | None = None
    message: str
    disclaimer: str = ANOMALY_DISCLAIMER


def _to_context_view(entry: dict[str, Any]) -> FeatureContextView:
    """Project one stored context document onto the wire shape.

    Tolerant by design: a stored entry from an older schema must not make an
    otherwise readable verdict unreadable, so unknown keys are dropped and the
    feature name is coerced to a string.
    """
    feature = str(entry.get("feature", ""))
    return FeatureContextView(
        feature=feature,
        label=FEATURE_LABELS.get(feature, feature),
        observed=_as_float(entry.get("observed")),
        baseline_median=_as_float(entry.get("training_median")),
        difference=_as_float(entry.get("difference")),
        deviation_mads=_as_float(entry.get("deviation_mads")),
        far_from_centre=bool(entry.get("far_from_centre", False)),
        missing=bool(entry.get("missing", False)),
        truncated=bool(entry.get("truncated", False)),
    )


def _as_float(value: object) -> float | None:
    """Return ``value`` as a float when it is a real number, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _feature_rank(feature: str) -> int:
    """Return the presentation rank of a feature name.

    An unknown feature sorts last rather than raising, so a verdict produced by a
    later version that added a feature is still renderable.
    """
    order = list(FEATURE_LABELS)
    try:
        return order.index(feature)
    except ValueError:
        return len(order)


__all__ = [
    "ANOMALY_DISCLAIMER",
    "DECISION_SCORE_NOTE",
    "FEATURE_LABELS",
    "STATE_LABELS",
    "AnomalyListData",
    "AnomalyModelListData",
    "AnomalyModelView",
    "AnomalyRetrainData",
    "AnomalySummaryView",
    "AnomalyView",
    "FeatureContextView",
]
