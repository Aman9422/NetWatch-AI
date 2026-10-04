"""Alert API endpoints for NetWatch AI (M11.18/M11.19, consolidated by M13.13).

The read surface, the lifecycle surface and the aggregation surface for M11's
stored alerts. Two properties are the whole point of the module:

* **Reads never mutate.** The only verbs that change anything are the lifecycle
  actions, and every one of them goes through
  :meth:`~app.alerts.service.AlertService.set_status`, which validates the move
  against :data:`app.alerts.status.VALID_TRANSITIONS`. No transition rule is
  written here. An illegal move — or any move out of a terminal state — is a
  ``409 INVALID_TRANSITION`` naming the states that *are* reachable, and the
  stored alert is left exactly as it was (M11.19).
* **A rejected filter is never ignored.** An unknown severity, an unknown
  status, a blank rule key or an unparseable timestamp is a ``400`` rather than a
  silently wider result set, so a typo can never look like "no alerts".

M13.13 asks for named lifecycle routes (``acknowledge``/``resolve``/``dismiss``/
``false-positive``) beside the body-carrying ``POST /{id}/status`` M11 already
shipped. Both spellings are served and both delegate to the same validated
transition table, so there is one rule set and two ways to express the same
request rather than two implementations of it.

The field name in a filter error stays ``filter`` rather than the individual
parameter: that is the contract M11 already published, and M13.4/M13.6 say to
keep established semantics rather than rename a working one.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query

from app.alerts import get_alert_engine
from app.alerts.engine import AlertEngine
from app.alerts.queries import AlertQueries, AlertQuery
from app.alerts.status import InvalidStatusTransition
from app.api.common import (
    ErrorCode,
    ConflictError,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    page_meta,
    success_payload,
    parse_epoch_filter,
    validate_choice,
    validate_time_range,
)
from app.api.v1.deps import get_alert_queries
from app.config.settings import settings
from app.schemas.alert import (
    AlertDetailData,
    AlertDiagnosticsData,
    AlertEvidenceView,
    AlertLifecycleRequest,
    AlertListData,
    AlertView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Severities accepted by the filter, ordered least to most serious.
SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

# Lifecycle states accepted by the transition endpoints (M11.6).
STATUSES: tuple[str, ...] = (
    "open",
    "acknowledged",
    "resolved",
    "dismissed",
    "false_positive",
)

# Evidence types a caller may filter by (M11.11).
EVIDENCE_TYPES: tuple[str, ...] = (
    "rule",
    "behavioral",
    "packet",
    "connection",
    "device",
)


def _list_page(
    queries: AlertQueries,
    *,
    severity: str | None,
    min_severity: str | None,
    status: list[str] | None,
    rule_id: int | None,
    rule_key: str | None,
    source_ip: str | None,
    destination_ip: str | None,
    since: str | None,
    until: str | None,
    limit: int | None,
    offset: int,
):
    """Validate the filters, then run the listing.

    The validation is what turns a typo into a ``400``: the query service is the
    authority on what it can honour, and this helper only translates its
    ``ValueError`` into the documented error. Every message a validator produces
    already names the parameter it rejected.
    """
    severity_value = validate_choice(severity, SEVERITIES, "severity")
    min_severity_value = validate_choice(min_severity, SEVERITIES, "min_severity")
    statuses = tuple(
        value
        for value in (
            validate_choice(entry, STATUSES, "status") for entry in (status or [])
        )
        if value is not None
    )
    since_value = parse_epoch_filter(since, "since")
    until_value = parse_epoch_filter(until, "until")
    validate_time_range(since_value, until_value)
    return queries.list_alerts(
        AlertQuery(
            severity=severity_value,
            min_severity=min_severity_value,
            statuses=statuses or None,
            rule_id=rule_id,
            rule_key=rule_key,
            source_ip=source_ip,
            destination_ip=destination_ip,
            since=since_value,
            until=until_value,
            limit=limit if limit is not None else settings.alert_default_page_size,
            offset=offset,
        )
    )


def _transition(
    engine: AlertEngine, alert_id: int, status: str
):
    """Apply one lifecycle move, translating the service's refusals (M11.19).

    The transition table belongs to :mod:`app.alerts.status`; this helper only
    maps its two refusal modes onto the documented responses:

    * a move the table forbids → ``409 INVALID_TRANSITION``;
    * an id the store does not hold → ``404 ALERT_NOT_FOUND``;
    * a value that is not a state at all → ``400 INVALID_LIFECYCLE``.

    Args:
        engine: The alert engine, whose ``service`` owns the write path.
        alert_id: The alert to move.
        status: The target state, as validated by ``AlertStatus``.

    Returns:
        The updated alert.

    Raises:
        ConflictError: If the transition is not allowed.
        NotFoundError: If no such alert exists.
        InvalidFilterError: If the target is not a lifecycle state.
    """
    try:
        updated = engine.service.set_status(alert_id, status)
    except InvalidStatusTransition as exc:
        logger.info("Rejected alert %d transition: %s", alert_id, exc)
        raise ConflictError(
            str(exc), code=ErrorCode.INVALID_TRANSITION, field="status"
        ) from exc
    except ValueError as exc:
        raise InvalidFilterError(
            str(exc), code=ErrorCode.INVALID_LIFECYCLE, field="status"
        ) from exc
    if updated is None:
        raise NotFoundError(
            "Alert not found", code=ErrorCode.ALERT_NOT_FOUND, field="alert_id"
        )
    return updated


@router.get("", response_model=None)
def list_alerts(
    severity: str | None = Query(
        default=None, description="Keep only alerts at exactly this severity"
    ),
    min_severity: str | None = Query(
        default=None,
        description="Keep only alerts at or above this severity (M11.4)",
    ),
    status: list[str] | None = Query(
        default=None, description="Keep only alerts in these lifecycle states"
    ),
    rule_id: int | None = Query(
        default=None, description="Keep only alerts triggered by this catalogue rule"
    ),
    rule_key: str | None = Query(
        default=None,
        description="Keep only alerts raised by this detector's stable rule id",
    ),
    source_ip: str | None = Query(default=None, description="Source address filter"),
    destination_ip: str | None = Query(
        default=None, description="Destination address filter"
    ),
    since: str | None = Query(
        default=None, description="Keep only alerts observed at or after this time"
    ),
    until: str | None = Query(
        default=None, description="Keep only alerts observed strictly before this time"
    ),
    limit: int | None = Query(
        default=None,
        ge=1,
        le=settings.alert_max_page_size,
        description="Maximum number of alerts to return",
    ),
    offset: int = Query(default=0, ge=0, description="Number of alerts to skip"),
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict:
    """Return stored alerts, newest first (M11.18).

    Filters combine with AND. ``since`` is inclusive and ``until`` exclusive, so a
    window has an explicit start and end. ``rule_id`` matches the catalogue
    foreign key while ``rule_key`` matches the detector's string id, which is what
    makes a detector with no catalogue row still queryable.
    """
    try:
        page = _list_page(
            queries,
            severity=severity,
            min_severity=min_severity,
            status=status,
            rule_id=rule_id,
            rule_key=rule_key,
            source_ip=source_ip,
            destination_ip=destination_ip,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="filter") from exc

    views = [AlertView.from_alert(alert) for alert in page.alerts]
    # The page block comes from the shared helper rather than being written out
    # here, so this collection reports the same window fields — including
    # ``has_more`` — as every other paginated route (M13.24).
    payload = AlertListData(
        **page_meta(
            len(views), PageWindow(page.limit, page.offset), total=page.total
        ),
        alerts=views,
    )
    logger.info("Returning %d alert(s) of %d via API", payload.count, payload.total)
    return success_payload("Alerts retrieved", payload.model_dump(mode="json"))


@router.get("/summary", response_model=None)
def alert_summary(
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict:
    """Return alert counts by severity and status (M11.18).

    Registered before the ``/{alert_id}`` route so ``summary`` can never be
    parsed as an alert id. Every severity is reported even when its count is
    zero, so a client never has to treat a missing key as "none".
    """
    summary = queries.summary()
    logger.info("Returning alert summary via API")
    return success_payload("Alert summary retrieved", summary)


@router.get("/diagnostics", response_model=None)
def alert_diagnostics(
    queries: AlertQueries = Depends(get_alert_queries),
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict:
    """Return the alert engine's execution counters (M11.31).

    Counters come from the shared engine, so this reports the *process-wide*
    behaviour: how many findings were seen, how many alerts were created or
    folded, and how many findings had no alert mapping. Stored-alert totals come
    from the database instead, so the two sides of the picture are both present.
    """
    counters = engine.get_counters()
    stored = queries.summary()
    payload = AlertDiagnosticsData(
        enabled=engine.enabled,
        findings_seen=counters.findings_seen,
        alerts_created=counters.alerts_created,
        duplicates_folded=counters.duplicates_folded,
        unsupported_findings=counters.unsupported_findings,
        errors=counters.errors,
        transitions=counters.transitions,
        total=stored["total"],
        by_severity=stored["by_severity"],
        by_status=stored["by_status"],
    )
    return success_payload(
        "Alert diagnostics retrieved", payload.model_dump(mode="json")
    )


@router.get("/{alert_id}", response_model=None)
def get_alert(
    alert_id: int,
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict:
    """Return one alert with its evidence, or 404 when it does not exist."""
    detail = queries.get_detail(alert_id)
    if detail is None:
        logger.info("Alert lookup failed for id %d", alert_id)
        raise NotFoundError(
            "Alert not found", code=ErrorCode.ALERT_NOT_FOUND, field="alert_id"
        )
    payload = AlertDetailData(
        alert=AlertView.from_alert(detail.alert),
        evidence=[
            AlertEvidenceView.from_record(record) for record in detail.evidence
        ],
        evidence_by_type=detail.evidence_by_type,
    )
    return success_payload("Alert retrieved", payload.model_dump(mode="json"))


@router.get("/{alert_id}/evidence", response_model=None)
def get_alert_evidence(
    alert_id: int,
    evidence_type: str | None = Query(
        default=None, description="Keep only evidence of this kind"
    ),
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict:
    """Return one alert's evidence, optionally filtered by type (M11.18).

    A missing alert is a 404 rather than an empty list, so a caller can tell
    "this alert has no evidence of that kind" apart from "there is no such
    alert".
    """
    try:
        type_value = validate_choice(evidence_type, EVIDENCE_TYPES, "evidence_type")
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="evidence_type") from exc

    if queries.get_alert(alert_id) is None:
        raise NotFoundError(
            "Alert not found", code=ErrorCode.ALERT_NOT_FOUND, field="alert_id"
        )
    records = queries.get_evidence(alert_id, evidence_type=type_value)
    views = [AlertEvidenceView.from_record(record) for record in records]
    return success_payload(
        "Alert evidence retrieved",
        {
            "alert_id": alert_id,
            "count": len(views),
            "evidence": [view.model_dump(mode="json") for view in views],
        },
    )


@router.post("/{alert_id}/status", response_model=None)
def set_alert_status(
    alert_id: int,
    body: AlertLifecycleRequest,
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict:
    """Move an alert to another lifecycle state (M11.19).

    The move is validated against the lifecycle table, so an illegal transition
    (or any move out of a terminal state) returns 409 with the states that *are*
    reachable, and the stored alert is left untouched. A move to the state it is
    already in is accepted as a no-op.
    """
    updated = _transition(engine, alert_id, body.status)
    return success_payload(
        "Alert status updated", AlertView.from_alert(updated).model_dump(mode="json")
    )


@router.post("/{alert_id}/acknowledge", response_model=None)
def acknowledge_alert(
    alert_id: int,
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict:
    """Mark an alert as acknowledged (M13.13).

    A named spelling of ``POST /{id}/status {"status": "acknowledged"}``. It
    delegates to the same validated transition table, so it cannot accept a move
    the status endpoint would refuse.
    """
    updated = _transition(engine, alert_id, "acknowledged")
    return success_payload(
        "Alert acknowledged", AlertView.from_alert(updated).model_dump(mode="json")
    )


@router.post("/{alert_id}/resolve", response_model=None)
def resolve_alert(
    alert_id: int,
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict:
    """Mark an alert as resolved (M13.13)."""
    updated = _transition(engine, alert_id, "resolved")
    return success_payload(
        "Alert resolved", AlertView.from_alert(updated).model_dump(mode="json")
    )


@router.post("/{alert_id}/dismiss", response_model=None)
def dismiss_alert(
    alert_id: int,
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict:
    """Dismiss an alert (M13.13)."""
    updated = _transition(engine, alert_id, "dismissed")
    return success_payload(
        "Alert dismissed", AlertView.from_alert(updated).model_dump(mode="json")
    )


@router.post("/{alert_id}/false-positive", response_model=None)
def mark_alert_false_positive(
    alert_id: int,
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict:
    """Mark an alert as a false positive (M13.13).

    A terminal state like ``resolved`` and ``dismissed``: M11.19 deliberately
    offers no reopen, because reopening means editing a conclusion already
    recorded. The route reports that refusal as a 409 rather than inventing one.
    """
    updated = _transition(engine, alert_id, "false_positive")
    return success_payload(
        "Alert marked as false positive",
        AlertView.from_alert(updated).model_dump(mode="json"),
    )
