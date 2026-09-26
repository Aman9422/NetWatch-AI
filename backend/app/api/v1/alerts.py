"""Alert API endpoints for NetWatch AI (M11.18/M11.19).

These endpoints expose the alerts M11 stores: a filtered, pageable listing, one
alert with its evidence, its evidence alone, the lifecycle transition, and the
aggregation/diagnostics view. They are deliberately *not* the complete public
API — that is M13 — but they are the full alert surface, and they exist so the
alert layer can be verified end to end against a running application.

Two rules the endpoints keep:

* **Reads never mutate.** Only ``POST /alerts/{id}/status`` changes anything, and
  it changes only the lifecycle, through the validated transition table (M11.19).
* **A rejected filter is never ignored.** An unknown severity or an empty rule
  key returns 400 rather than a silently wider result set, so a typo can never
  look like "no alerts".

Responses follow the same envelope as the rest of the API::

    {"success": true,  "message": "...", "data": {...}}
    {"success": false, "message": "...", "errors": [{"field": ..., "code": ...}]}
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app.alerts import get_alert_engine
from app.alerts.engine import AlertEngine
from app.alerts.queries import AlertQueries, AlertQuery
from app.alerts.status import InvalidStatusTransition
from app.config.settings import settings
from app.persistence.session_factory import app_session_factory
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

# Error codes returned in the error envelope.
_CODE_INVALID_FILTER = "INVALID_FILTER"
_CODE_ALERT_NOT_FOUND = "ALERT_NOT_FOUND"
_CODE_INVALID_TRANSITION = "INVALID_TRANSITION"
_CODE_INVALID_LIFECYCLE = "INVALID_LIFECYCLE"

# Severities accepted by the filter, ordered least to most serious. The list is a
# literal here for the same reason the repository's is: the API layer must be
# able to reject a bad value before it reaches the query.
_SEVERITIES = ("low", "medium", "high", "critical")

# Lifecycle states accepted by the transition endpoint (M11.6).
_STATUSES = ("open", "acknowledged", "resolved", "dismissed", "false_positive")

# Evidence types a caller may filter by (M11.11).
_EVIDENCE_TYPES = ("rule", "behavioral", "packet", "connection", "device")

# Shared query service. It holds no session, so it is safe to reuse across
# requests; a session is opened per call inside it.
_alert_queries: AlertQueries | None = None


def get_alert_queries() -> AlertQueries:
    """FastAPI dependency returning the shared alert query service."""
    global _alert_queries
    if _alert_queries is None:
        _alert_queries = AlertQueries(session_factory=app_session_factory)
    return _alert_queries


def _error_response(
    status_code: int, message: str, field: str, code: str
) -> JSONResponse:
    """Build the standard error envelope used across the API."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "message": message,
            "errors": [{"field": field, "code": code}],
        },
    )


def _parse_timestamp(value: str | None, field: str) -> float | None:
    """Parse an ISO-8601 query timestamp into epoch seconds.

    The API speaks ISO-8601 while an alert filter is expressed in epoch seconds
    (to match M10's findings), so the conversion happens here — the one place
    that owns the boundary.

    Raises:
        ValueError: If ``value`` is present but not a usable timestamp. A typo
            must fail loudly rather than silently widening the window.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"'{value}' is not a valid ISO-8601 timestamp for {field}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _validate_choice(value: str | None, allowed: tuple[str, ...], field: str) -> str | None:
    """Fold and validate a closed-vocabulary query value.

    Raises:
        ValueError: If ``value`` is not one of ``allowed``. Returning the folded
            value means the caller may spell it in any case and still get the
            canonical form the query expects.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if text not in allowed:
        raise ValueError(
            f"'{value}' is not a valid {field} (expected one of: {', '.join(allowed)})"
        )
    return text


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
    limit: int = Query(
        default=None,
        ge=1,
        le=settings.alert_max_page_size,
        description="Maximum number of alerts to return",
    ),
    offset: int = Query(default=0, ge=0, description="Number of alerts to skip"),
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict | JSONResponse:
    """Return stored alerts, newest first (M11.18).

    Filters combine with AND. ``since`` is inclusive and ``until`` exclusive, so a
    window has an explicit start and end. ``rule_id`` matches the catalogue
    foreign key while ``rule_key`` matches the detector's string id, which is what
    makes a detector with no catalogue row still queryable.
    """
    try:
        severity_value = _validate_choice(severity, _SEVERITIES, "severity")
        min_severity_value = _validate_choice(min_severity, _SEVERITIES, "min_severity")
        statuses = tuple(
            status_value
            for status_value in (
                _validate_choice(entry, _STATUSES, "status") for entry in (status or [])
            )
            if status_value is not None
        )
        since_value = _parse_timestamp(since, "since")
        until_value = _parse_timestamp(until, "until")
        page = queries.list_alerts(
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
    except ValueError as exc:
        return _error_response(400, str(exc), "filter", _CODE_INVALID_FILTER)

    views = [AlertView.from_alert(alert) for alert in page.alerts]
    payload = AlertListData(
        count=len(views),
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        alerts=views,
    )
    logger.info("Returning %d alert(s) of %d via API", payload.count, payload.total)
    return {
        "success": True,
        "message": "Alerts retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/summary", response_model=None)
def alert_summary(
    queries: AlertQueries = Depends(get_alert_queries),
    engine_enabled: bool = Query(
        default=True, description="Reported as the engine's enable state"
    ),
) -> dict:
    """Return alert counts by severity and status (M11.18).

    Registered before the ``/{alert_id}`` route so ``summary`` can never be
    parsed as an alert id. Every severity is reported even when its count is
    zero, so a client never has to treat a missing key as "none".
    """
    summary = queries.summary()
    logger.info("Returning alert summary via API")
    return {
        "success": True,
        "message": "Alert summary retrieved",
        "data": summary,
    }


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
    return {
        "success": True,
        "message": "Alert diagnostics retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/{alert_id}", response_model=None)
def get_alert(
    alert_id: int,
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict | JSONResponse:
    """Return one alert with its evidence, or 404 when it does not exist."""
    detail = queries.get_detail(alert_id)
    if detail is None:
        logger.info("Alert lookup failed for id %d", alert_id)
        return _error_response(
            404, "Alert not found", "alert_id", _CODE_ALERT_NOT_FOUND
        )
    payload = AlertDetailData(
        alert=AlertView.from_alert(detail.alert),
        evidence=[
            AlertEvidenceView.from_record(record) for record in detail.evidence
        ],
        evidence_by_type=detail.evidence_by_type,
    )
    return {
        "success": True,
        "message": "Alert retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/{alert_id}/evidence", response_model=None)
def get_alert_evidence(
    alert_id: int,
    evidence_type: str | None = Query(
        default=None, description="Keep only evidence of this kind"
    ),
    queries: AlertQueries = Depends(get_alert_queries),
) -> dict | JSONResponse:
    """Return one alert's evidence, optionally filtered by type (M11.18).

    A missing alert is a 404 rather than an empty list, so a caller can tell
    "this alert has no evidence of that kind" apart from "there is no such
    alert".
    """
    try:
        type_value = _validate_choice(evidence_type, _EVIDENCE_TYPES, "evidence_type")
    except ValueError as exc:
        return _error_response(400, str(exc), "evidence_type", _CODE_INVALID_FILTER)

    if queries.get_alert(alert_id) is None:
        return _error_response(
            404, "Alert not found", "alert_id", _CODE_ALERT_NOT_FOUND
        )
    records = queries.get_evidence(alert_id, evidence_type=type_value)
    views = [AlertEvidenceView.from_record(record) for record in records]
    return {
        "success": True,
        "message": "Alert evidence retrieved",
        "data": {"count": len(views), "evidence": [view.model_dump(mode="json") for view in views]},
    }


@router.post("/{alert_id}/status", response_model=None)
def set_alert_status(
    alert_id: int,
    body: AlertLifecycleRequest,
    queries: AlertQueries = Depends(get_alert_queries),
    engine: AlertEngine = Depends(get_alert_engine),
) -> dict | JSONResponse:
    """Move an alert to another lifecycle state (M11.19).

    The move is validated against the lifecycle table, so an illegal transition
    (or any move out of a terminal state) returns 409 with the states that *are*
    reachable, and the stored alert is left untouched. A move to the state it is
    already in is accepted as a no-op.
    """
    try:
        updated = engine.service.set_status(alert_id, body.status)
    except InvalidStatusTransition as exc:
        logger.info("Rejected alert %d transition: %s", alert_id, exc)
        return _error_response(
            409, str(exc), "status", _CODE_INVALID_TRANSITION
        )
    except ValueError as exc:
        return _error_response(400, str(exc), "status", _CODE_INVALID_LIFECYCLE)

    if updated is None:
        return _error_response(
            404, "Alert not found", "alert_id", _CODE_ALERT_NOT_FOUND
        )
    return {
        "success": True,
        "message": "Alert status updated",
        "data": AlertView.from_alert(updated).model_dump(mode="json"),
    }
