"""Incident API endpoints for NetWatch AI (M13.15/M13.16).

Exposes the correlated incidents M12's
:class:`~app.correlation.engine.CorrelationEngine` holds. An incident is what
several related events add up to, so the read surface reports *facts about the
membership* — the member ids, the reason trail, the correlation confidence and
the risk score — and computes nothing of its own.

Two boundaries are load-bearing:

* **No risk is recalculated here.** ``risk_score`` and ``risk_band`` are read
  from the incident. Scoring belongs to
  :class:`~app.risk.engine.RiskScoringEngine` and reaches an incident only
  through ``with_risk`` (M12.13/M12.14); an API layer that recomputed it could
  disagree with the stored value and with the alert rows it was written onto
  (M12.24).
* **No lifecycle rule is written here.** ``investigate``/``resolve``/``dismiss``
  all delegate to ``CorrelationEngine.set_status``, so
  :data:`app.correlation.status.VALID_TRANSITIONS` remains the only authority. An
  invalid transition is a ``409``, not a second implementation of the table
  (M13.16).

Three distinct confidences stay distinct (M12.16): ``correlation_confidence`` is
how strongly the events were judged related, ``alert_confidence`` is the mean of
the member alerts' own evidence strengths, and ``risk_score`` is the bounded
prioritisation metric. A client can read all three without one masquerading as
another.
"""

from __future__ import annotations

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query

from app.api.common import (
    ConflictError,
    ErrorCode,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    page_meta,
    parse_epoch_filter,
    success_payload,
    validate_risk_range,
    validate_time_range,
)
from app.api.common.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.config.settings import settings
from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.correlation.incident import CorrelatedIncident
from app.correlation.registry import IncidentOrder, IncidentQuery
from app.correlation.status import (
    ACTIVE_STATUSES,
    InvalidIncidentTransition,
    STATUS_VALUES,
)
from app.schemas.incident import (
    IncidentListData,
    IncidentSummaryView,
    IncidentView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Lifecycle states an incident may be filtered by (M12.9). A closed Literal, so
# FastAPI documents it and rejects an unknown value with a 422 before the handler
# runs, rather than silently selecting every incident.
IncidentStatusParam = Literal["open", "investigating", "resolved", "dismissed"]

# Listing order. ``recent`` is the default; ``risk`` orders by score.
IncidentOrderParam = Literal["recent", "risk"]

#: Cap on the page a client may request, so an over-large page is a 422 produced
#: by request validation rather than a ValueError from the store (M13.24).
#:
#: Two bounds apply and the smaller one wins: the API-wide maximum, and the
#: correlation store's own ``correlation_max_page_size``. ``IncidentQuery``
#: enforces the latter by raising from ``__post_init__``, so a page this router
#: accepted but the store refused would surface as a ``500`` for what is a client
#: mistake. Naming the bound here is what keeps that failure in request
#: validation where it belongs (M13.6/M13.24).
MAX_INCIDENT_PAGE_SIZE = min(MAX_PAGE_SIZE, settings.correlation_max_page_size)


def incident_page_window(
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_INCIDENT_PAGE_SIZE,
            description="Maximum number of incidents to return",
        ),
    ] = DEFAULT_PAGE_SIZE,
    offset: Annotated[
        int, Query(ge=0, description="Number of matching incidents to skip")
    ] = 0,
) -> PageWindow:
    """Resolve the incident page window against the store's own cap (M13.24).

    The shared :func:`pagination_params` would allow a page the correlation store
    itself rejects, so this router declares its own narrower maximum. The effect
    is that ``limit`` is validated once, at the boundary, against the number the
    store will actually honour.
    """
    return PageWindow(limit=int(limit), offset=int(offset))


def _build_query(
    *,
    status: str | None,
    active_only: bool,
    source: str | None,
    device_id: str | None,
    connection_id: str | None,
    rule_id: str | None,
    correlation_rule_id: str | None,
    min_risk_score: float | None,
    max_risk_score: float | None,
    min_confidence: float | None,
    since: str | None,
    until: str | None,
    window: PageWindow,
    order: str,
) -> IncidentQuery:
    """Validate the filters and build the store query (M13.15/M13.25).

    The store validates too — :meth:`IncidentQuery.__post_init__` rejects an
    inverted range as well — but validating here first means the error names the
    query parameter the caller actually got wrong rather than the store's
    internal field name.

    Raises:
        InvalidFilterError: If any filter cannot be honoured.
    """
    try:
        risk_min, risk_max = validate_risk_range(min_risk_score, max_risk_score)
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="min_risk_score") from exc

    if min_confidence is not None and not 0.0 <= float(min_confidence) <= 1.0:
        raise InvalidFilterError(
            "min_confidence must be between 0 and 1", field="min_confidence"
        )

    # Each parse is wrapped on its own so the error names the parameter the
    # caller actually got wrong. ``parse_epoch_filter`` raises a plain
    # ``ValueError``, and an unwrapped one would escape this function and become
    # an opaque 500 rather than the 400 M13.25 requires — a typo must never look
    # like a server fault.
    try:
        since_value = parse_epoch_filter(since, "since")
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="since") from exc
    try:
        until_value = parse_epoch_filter(until, "until")
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="until") from exc
    try:
        validate_time_range(since_value, until_value)
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="since") from exc

    return IncidentQuery(
        statuses=(status,) if status else (),
        active_only=active_only,
        device_id=device_id,
        connection_id=connection_id,
        source_ip=source,
        rule_id=rule_id,
        correlation_rule_id=correlation_rule_id,
        min_risk_score=None if risk_min is None else int(risk_min),
        max_risk_score=None if risk_max is None else int(risk_max),
        min_confidence=min_confidence,
        since=since_value,
        until=until_value,
        limit=window.limit,
        offset=window.offset,
        order=IncidentOrder(order),
    )


def _list_incidents(
    engine: CorrelationEngine,
    query: IncidentQuery,
) -> IncidentListData:
    """Run one page query and project it onto the wire model.

    The total comes from ``count_incidents`` with the *same* query object, so a
    page and its total can never disagree about which incidents match (M13.24).
    """
    incidents = engine.get_incidents(query)
    total = engine.count_incidents(query)
    return IncidentListData(
        **page_meta(len(incidents), PageWindow(query.limit, query.offset), total=total),
        incidents=[IncidentSummaryView.from_incident(item) for item in incidents],
    )


@router.get("", response_model=None)
def list_incidents(
    status: IncidentStatusParam | None = Query(
        default=None, description="Keep only incidents in this lifecycle state"
    ),
    active_only: bool = Query(
        default=False,
        description="Keep only incidents still needing attention (open, investigating)",
    ),
    source: str | None = Query(
        default=None, description="Keep only incidents with this source address"
    ),
    device_id: str | None = Query(
        default=None, description="Keep only incidents involving this M8 device"
    ),
    connection_id: str | None = Query(
        default=None, description="Keep only incidents involving this M9 conversation"
    ),
    rule_id: str | None = Query(
        default=None, description="Keep only incidents this detector rule contributed to"
    ),
    correlation_rule_id: str | None = Query(
        default=None, description="Keep only incidents this M12 correlation rule grouped"
    ),
    min_risk_score: float | None = Query(
        default=None, ge=0, le=100, description="Lowest risk score to include"
    ),
    max_risk_score: float | None = Query(
        default=None, ge=0, le=100, description="Highest risk score to include"
    ),
    min_confidence: float | None = Query(
        default=None,
        ge=0.0,
        le=1.0,
        description="Lowest correlation confidence to include",
    ),
    since: str | None = Query(
        default=None,
        description="Keep incidents whose extent overlaps at or after this ISO-8601 time",
    ),
    until: str | None = Query(
        default=None, description="Keep incidents overlapping before this ISO-8601 time"
    ),
    order: IncidentOrderParam = Query(
        default="recent", description="Listing order: most recent, or highest risk"
    ),
    window: PageWindow = Depends(incident_page_window),
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Return correlated incidents matching the filters (M13.15).

    ``since``/``until`` select an incident whose ``[start_time, last_seen]``
    extent *overlaps* the window, so an incident that began before ``since`` but
    was still active inside it is included. An unusable filter is a ``400``
    naming the parameter, never a silently wider result.
    """
    query = _build_query(
        status=status,
        active_only=active_only,
        source=source,
        device_id=device_id,
        connection_id=connection_id,
        rule_id=rule_id,
        correlation_rule_id=correlation_rule_id,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
        min_confidence=min_confidence,
        since=since,
        until=until,
        window=window,
        order=order,
    )
    payload = _list_incidents(engine, query)
    logger.info(
        "Returning %d of %d incident(s) via API", payload.count, payload.total
    )
    return success_payload("Incidents retrieved", payload.model_dump(mode="json"))


@router.get("/open", response_model=None)
def list_open_incidents(
    window: PageWindow = Depends(incident_page_window),
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Return the incidents still needing attention, riskiest first (M13.15).

    Registered before the ``/{incident_id}`` route so ``open`` can never be read
    as an incident identifier. "Open" means :data:`ACTIVE_STATUSES` — ``open`` and
    ``investigating`` — which is the same definition the store's ``active_only``
    filter uses, so the two views cannot disagree.
    """
    listed = engine.open_incidents(limit=window.end)
    total = engine.count_incidents(IncidentQuery(active_only=True))
    page = window.slice(listed)
    payload = IncidentListData(
        **page_meta(len(page), window, total=total),
        incidents=[IncidentSummaryView.from_incident(item) for item in page],
    )
    logger.info("Returning %d open incident(s) via API", payload.count)
    return success_payload(
        "Open incidents retrieved", payload.model_dump(mode="json")
    )


@router.get("/{incident_id}", response_model=None)
def get_incident(
    incident_id: str,
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Return one correlated incident with its full membership (M13.15).

    The detail view carries what the listing omits: every member alert, finding,
    device and conversation reference, plus the correlation reason trail that
    explains *why* the events were judged related.
    """
    incident = engine.get_incident(incident_id)
    if incident is None:
        logger.info("Incident lookup failed for id %r", incident_id)
        raise NotFoundError(
            "Incident not found",
            code=ErrorCode.INCIDENT_NOT_FOUND,
            field="incident_id",
        )
    return success_payload(
        "Incident retrieved",
        IncidentView.from_incident(incident).model_dump(mode="json"),
    )


def _transition(
    engine: CorrelationEngine, incident_id: str, status: str
) -> CorrelatedIncident:
    """Apply one lifecycle move through the M12 transition table (M13.16).

    Args:
        engine: The correlation engine, which owns the registry.
        incident_id: The incident to move.
        status: The target state.

    Returns:
        The updated incident.

    Raises:
        ConflictError: If the transition is not allowed.
        NotFoundError: If no such incident exists.
    """
    try:
        updated = engine.set_status(incident_id, status)
    except InvalidIncidentTransition as exc:
        logger.info("Rejected incident %r transition: %s", incident_id, exc)
        raise ConflictError(
            str(exc), code=ErrorCode.INVALID_TRANSITION, field="status"
        ) from exc
    except ValueError as exc:
        raise InvalidFilterError(
            str(exc), code=ErrorCode.INVALID_LIFECYCLE, field="status"
        ) from exc
    if updated is None:
        raise NotFoundError(
            "Incident not found",
            code=ErrorCode.INCIDENT_NOT_FOUND,
            field="incident_id",
        )
    return updated


@router.post("/{incident_id}/investigate", response_model=None)
def investigate_incident(
    incident_id: str,
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Move an incident to ``investigating`` (M13.16).

    Allowed from ``open`` only. Any other current state — including a terminal
    one — is a ``409`` and leaves the incident untouched.
    """
    updated = _transition(engine, incident_id, "investigating")
    return success_payload(
        "Incident marked as investigating",
        IncidentView.from_incident(updated).model_dump(mode="json"),
    )


@router.post("/{incident_id}/resolve", response_model=None)
def resolve_incident(
    incident_id: str,
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Resolve an incident (M13.16).

    A terminal move: M12.9 offers no reopen, because reopening means editing a
    conclusion that was already recorded.
    """
    updated = _transition(engine, incident_id, "resolved")
    return success_payload(
        "Incident resolved",
        IncidentView.from_incident(updated).model_dump(mode="json"),
    )


@router.post("/{incident_id}/dismiss", response_model=None)
def dismiss_incident(
    incident_id: str,
    engine: CorrelationEngine = Depends(get_correlation_engine),
) -> dict:
    """Dismiss an incident (M13.16). Also terminal, like ``resolved``."""
    updated = _transition(engine, incident_id, "dismissed")
    return success_payload(
        "Incident dismissed",
        IncidentView.from_incident(updated).model_dump(mode="json"),
    )


__all__ = [
    "ACTIVE_STATUSES",
    "MAX_INCIDENT_PAGE_SIZE",
    "STATUS_VALUES",
    "router",
]
