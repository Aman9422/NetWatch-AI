"""ML anomaly detection API (M22.12).

Five surfaces over the M22 engine:

* ``GET /anomalies`` — a page of evaluated observation windows, newest first.
* ``GET /anomalies/{evaluation_id}`` — one verdict, with its feature context.
* ``GET /anomalies/models`` — every device's model lifecycle.
* ``GET /anomalies/models/{device_key}`` — one device's model, or an honest
  "still collecting data" record.
* ``POST /anomalies/models/{device_key}/retrain`` — a controlled retraining.

**What these routes do not claim.** A ``decision_score`` is the raw
``IsolationForest.decision_function`` output: lower is more unusual, and it is
neither a probability nor a calibrated confidence (M22.9). Nothing here calls it
one, and every payload carries the sentence stating that an anomaly is a
deviation from learned behaviour rather than confirmation of an attack (M22.13).

**A skip is not a clean bill of health.** A window that could not be evaluated is
stored and returned as ``skipped`` with a stable reason, so "no model exists yet"
is never presented as "nothing unusual happened". Reading a ``skipped`` row as a
normal verdict would be the one mistake the model-status surface must not permit.

**Every response is bounded.** The listing pages through the M13 contract, the
detail carries at most one window's feature context, and the model listing pages
the same way — so no response can become a dump of the whole table.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query

from app.anomaly_detection import get_anomaly_engine
from app.anomaly_detection.engine import AnomalyEngine
from app.anomaly_detection.evaluation_store import EVALUATION_STATUSES
from app.anomaly_detection.states import describe_state
from app.api.common import (
    ErrorCode,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    parse_datetime_filter,
    success_payload,
    validate_choice,
    validate_time_range,
)
from app.schemas.anomaly import (
    ANOMALY_DISCLAIMER,
    AnomalyListData,
    AnomalyModelListData,
    AnomalyModelView,
    AnomalyRetrainData,
    AnomalySummaryView,
    AnomalyView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

#: The closed model-state vocabulary, mirrored from ``ModelState``. A Literal
#: lets FastAPI document it and reject an unknown value with a 422 before the
#: handler runs (M13.25).
ModelStateParam = Literal[
    "collecting_data", "training", "ready", "stale", "failed", "disabled"
]

#: The closed evaluation-status vocabulary.
EvaluationStatusParam = Literal["scored", "skipped", "failed"]


def get_engine() -> AnomalyEngine:
    """Return the process-wide anomaly engine as a FastAPI dependency (M22.12).

    A thin wrapper rather than passing ``get_anomaly_engine`` itself, so a test
    can override this one dependency and hand a route a known engine without
    patching a module global.
    """
    return get_anomaly_engine()


def _identity_kind(device_key: str) -> str:
    """Return ``mac`` or ``ip`` from an M8 identity string.

    The identity vocabulary is M8's, not a new one: a key beginning ``mac:`` is a
    hardware identity that survives an address change, and anything else is the
    weaker address-based fallback.
    """
    return "mac" if device_key.startswith("mac:") else "ip"


@router.get("", response_model=None)
def list_anomalies(
    device_key: str | None = Query(
        default=None, description="Keep only windows belonging to this device"
    ),
    is_anomaly: bool | None = Query(
        default=None,
        description="Keep only anomalous (true) or non-anomalous (false) verdicts",
    ),
    status: EvaluationStatusParam | None = Query(
        default=None, description="Keep only verdicts in this evaluation status"
    ),
    since: str | None = Query(
        default=None, description="Inclusive lower bound on window start (ISO-8601)"
    ),
    until: str | None = Query(
        default=None, description="Exclusive upper bound on window start (ISO-8601)"
    ),
    window: PageWindow = Depends(pagination_params),
    engine: AnomalyEngine = Depends(get_engine),
) -> dict:
    """Return a page of evaluated observation windows (M22.12).

    Ordering is ``window_start DESC, id DESC`` — a total order, so two identical
    requests return the same page and pagination can never repeat or skip a row
    (M13.24).

    The page also carries counted totals, so the frontend can render its tiles
    without a second round trip.

    Raises:
        InvalidFilterError: If a timestamp cannot be parsed or the range is
            inverted. An unparseable filter is a 400 naming the field rather than
            a silently widened window (M13.25).
    """
    try:
        since_at = parse_datetime_filter(since, "since")
        until_at = parse_datetime_filter(until, "until")
        validate_time_range(since_at, until_at)
        normalized_status = validate_choice(
            status, EVALUATION_STATUSES, "status"
        )
    except ValueError as exc:
        raise InvalidFilterError(str(exc)) from exc

    rows = engine.store.list(
        device_key=device_key,
        is_anomaly=is_anomaly,
        status=normalized_status,
        since=since_at,
        until=until_at,
        limit=window.limit,
        offset=window.offset,
    )
    total = engine.store.count(
        device_key=device_key,
        is_anomaly=is_anomaly,
        status=normalized_status,
        since=since_at,
        until=until_at,
    )
    summary = engine.store.summary()
    payload = AnomalyListData(
        **page_meta(len(rows), window, total=total),
        anomalies=[
            AnomalyView.from_snapshot(row, include_context=False) for row in rows
        ],
        summary=AnomalySummaryView(**summary),
    )
    logger.info("Returning %d of %d anomaly result(s) via API", payload.count, total)
    return success_payload(
        "Anomaly results retrieved", payload.model_dump(mode="json")
    )


@router.get("/models", response_model=None)
def list_models(
    state: ModelStateParam | None = Query(
        default=None, description="Keep only models in this lifecycle state"
    ),
    window: PageWindow = Depends(pagination_params),
    engine: AnomalyEngine = Depends(get_engine),
) -> dict:
    """Return a page of per-device model lifecycles (M22.12).

    A device still collecting history appears here in ``collecting_data``: "this
    device has no model yet" is a real answer to "which devices have models", and
    omitting it would make an unready device look like one that was never seen.
    """
    rows = engine.model_store.list(
        state=state, limit=window.limit, offset=window.offset
    )
    total = engine.model_store.count(state=state)
    payload = AnomalyModelListData(
        **page_meta(len(rows), window, total=total),
        models=[AnomalyModelView.from_snapshot(row) for row in rows],
    )
    return success_payload("Anomaly models retrieved", payload.model_dump(mode="json"))


@router.get("/models/{device_key}", response_model=None)
def get_model(
    device_key: str,
    engine: AnomalyEngine = Depends(get_engine),
) -> dict:
    """Return one device's model lifecycle (M22.12).

    Args:
        device_key: The M8 identity — ``mac:aa:bb:...`` or ``ip:1.2.3.4``. A colon
            is legal in a path segment, so the id is used as sent.
        engine: The anomaly engine.

    Raises:
        NotFoundError: If this device has no model row at all. A device that has
            produced no completed observation window yet has nothing to report,
            which is a real answer rather than a fault.
    """
    snapshot = engine.model_store.get(device_key)
    if snapshot is None:
        raise NotFoundError(
            "No anomaly model has been recorded for this device yet",
            code=ErrorCode.NOT_FOUND,
            field="device_key",
        )
    view = AnomalyModelView.from_snapshot(snapshot)
    return success_payload("Anomaly model retrieved", view.model_dump(mode="json"))


@router.get("/{evaluation_id}", response_model=None)
def get_anomaly(
    evaluation_id: int,
    engine: AnomalyEngine = Depends(get_engine),
) -> dict:
    """Return one evaluated window, with its feature context (M22.12).

    The feature context is a comparison against M21's statistical profile — the
    observed value, the profile median, the difference and how many scaled MADs
    that difference is. It is explicitly **not** model feature attribution:
    Isolation Forest does not report which feature caused a prediction, and the
    response says so in the field descriptions.

    Raises:
        NotFoundError: If no verdict with this identifier exists.
    """
    snapshot = engine.store.get(evaluation_id)
    if snapshot is None:
        raise NotFoundError(
            "No anomaly result exists with this identifier",
            code=ErrorCode.NOT_FOUND,
            field="evaluation_id",
        )
    view = AnomalyView.from_snapshot(snapshot, include_context=True)
    return success_payload("Anomaly result retrieved", view.model_dump(mode="json"))


@router.post("/models/{device_key}/retrain", response_model=None)
def retrain_model(
    device_key: str,
    engine: AnomalyEngine = Depends(get_engine),
) -> dict:
    """Force a training pass for one device (M22.12).

    The retrain is bounded by the same rules as an automatic one:

    * **History only.** Training reads windows strictly *before* the latest one
      on record, so it cannot fit on the very window it will be asked to score.
    * **A minimum requirement.** Fewer usable windows than the configured minimum
      is a refusal, not a fabricated model.
    * **One pass at a time.** A concurrent request for the same device is refused
      rather than queued, so two clicks cannot build two forests.
    * **The previous model survives a failure.** A failed pass leaves the working
      model in place and reports ``previous_model_retained``.
    * **M21 history is never touched.** Nothing is deleted or rewritten; a retrain
      only reads observation windows and writes one model row.

    Answers ``200`` in every non-exceptional case, including a refusal: the
    outcome — trained, refused or failed — is in the payload, and a caller reads
    ``trained`` rather than inferring it from a status code.

    Raises:
        NotFoundError: If this device has no observation history at all, so there
            is nothing a retrain could be trained from.
    """
    latest = engine.dataset_reader.latest_window_start(device_key)
    if latest is None:
        raise NotFoundError(
            "No behavioural observation windows have been recorded for this device",
            code=ErrorCode.NOT_FOUND,
            field="device_key",
        )
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    outcome = engine.lifecycle.retrain(
        device_key,
        identity_kind=_identity_kind(device_key),
        before=latest,
        now=now,
    )
    trained = outcome.retrained
    payload = AnomalyRetrainData(
        device_key=device_key,
        trained=trained,
        state=outcome.state,
        state_description=describe_state(outcome.state),
        model_version=outcome.model_version,
        training_sample_count=outcome.training_sample_count,
        previous_model_retained=outcome.previous_retained,
        reason=outcome.reason,
        message=_retrain_message(trained=trained, reason=outcome.reason),
    )
    logger.info(
        "Manual anomaly retrain for %r: %s",
        device_key,
        "trained" if trained else f"not trained ({outcome.reason or 'unknown'})",
    )
    return success_payload("Anomaly model retraining attempted", payload.model_dump(mode="json"))


def _retrain_message(*, trained: bool, reason: str | None) -> str:
    """Return a sentence describing a retraining attempt (M22.12).

    Args:
        trained: Whether a new model was produced.
        reason: A stable code explaining a refusal or failure.
    """
    if trained:
        return (
            "A new model was trained from the device's historical observation "
            "windows. The previous model was replaced and evaluations will use "
            "the new one. This does not change M21's behavioural history."
        )
    if reason == "insufficient_training_data":
        return (
            "The device does not yet have enough usable observation windows to "
            "train a model. No model was created, and no evaluation is possible "
            "for this device yet."
        )
    if reason == "insufficient_features":
        return (
            "Too many of the behavioural features are unavailable for this "
            "device's history to train a model. No model was created."
        )
    if reason == "training_already_in_progress":
        return (
            "A training pass for this device is already running. This request "
            "was refused rather than queued; the working model is unchanged."
        )
    if reason == "disabled":
        return (
            "ML anomaly detection is switched off by configuration, so no model "
            "was trained and nothing is being evaluated."
        )
    return (
        "The training pass did not produce a model. Any previous working model "
        f"was kept, so evaluation is unchanged. Reason: {reason or 'unknown'}."
    )


__all__ = [
    "ANOMALY_DISCLAIMER",
    "EvaluationStatusParam",
    "ModelStateParam",
    "get_engine",
    "router",
]
