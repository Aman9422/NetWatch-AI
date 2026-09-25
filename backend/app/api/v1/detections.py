"""Read-only detection finding API endpoints for NetWatch AI (M10.22).

These endpoints expose what the M10 :class:`~app.detection.engine.DetectionEngine`
observed. A finding is an *observation*, not an alert: there is no severity, no
risk score, no assignment and no lifecycle here, so nothing in this module can
acknowledge, suppress or escalate anything. Those belong to M11 and M12.

This is deliberately *not* the complete alert API — that is M11 — and not the
master REST API, which is M13. The endpoints exist so the detection layer can be
verified end to end against a running application.

Responses follow the same envelope as the rest of the API::

    {"success": true,  "message": "...", "data": {...}}
    {"success": false, "message": "...", "errors": [{"field": ..., "code": ...}]}
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app.detection import DetectionEngine, get_detection_engine
from app.schemas.detection import (
    DetectionFindingListData,
    DetectionFindingView,
    DetectionRuleListData,
    DetectionRuleView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Bounds for the ``limit`` query parameter, so a response stays bounded even
# when a detector has been firing continuously.
_MIN_LIMIT = 1
_MAX_LIMIT = 1000
DEFAULT_FINDING_LIMIT = 100

# Error codes returned in the error envelope.
_CODE_INVALID_FILTER = "INVALID_FILTER"


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

    The API speaks ISO-8601 (like devices and connections) while a finding is
    timed in epoch seconds (like packets), so the conversion happens here — the
    one place that owns the boundary.

    Raises:
        ValueError: If ``value`` is present but not a usable timestamp. A typo
            must fail loudly rather than silently widen the window.
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


def _rule_view(rule: object) -> DetectionRuleView:
    """Project one registered rule onto the wire model (M10.22)."""
    return DetectionRuleView(
        rule_id=rule.rule_id,  # type: ignore[attr-defined]
        rule_name=rule.rule_name,  # type: ignore[attr-defined]
        description=rule.description,  # type: ignore[attr-defined]
        enabled=rule.enabled,  # type: ignore[attr-defined]
        window_seconds=rule.window_seconds,  # type: ignore[attr-defined]
        state_size=rule.state_size(),  # type: ignore[attr-defined]
    )


@router.get("", response_model=None)
def list_findings(
    rule_id: str | None = Query(
        default=None, description="Keep only findings produced by this rule"
    ),
    source_ip: str | None = Query(
        default=None, description="Keep only findings naming this source address"
    ),
    destination_ip: str | None = Query(
        default=None, description="Keep only findings naming this destination address"
    ),
    device_id: str | None = Query(
        default=None, description="Keep only findings attributed to this M8 device"
    ),
    since: str | None = Query(
        default=None,
        description="Keep only findings observed at or after this ISO-8601 time",
    ),
    until: str | None = Query(
        default=None,
        description="Keep only findings observed strictly before this ISO-8601 time",
    ),
    limit: int = Query(
        default=DEFAULT_FINDING_LIMIT,
        ge=_MIN_LIMIT,
        le=_MAX_LIMIT,
        description="Maximum number of findings to return",
    ),
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict | JSONResponse:
    """Return retained detection findings, newest first (M10.22).

    Filters combine with AND. ``since`` is inclusive and ``until`` exclusive, so
    a query window has an explicit start and end (M10.13). An unusable filter is
    rejected with 400 rather than being ignored.
    """
    # Each bound is parsed separately so the error names the field the caller
    # actually got wrong, rather than blaming ``since`` for a bad ``until``.
    try:
        since_value = _parse_timestamp(since, "since")
    except ValueError as exc:
        return _error_response(400, str(exc), "since", _CODE_INVALID_FILTER)
    try:
        until_value = _parse_timestamp(until, "until")
    except ValueError as exc:
        return _error_response(400, str(exc), "until", _CODE_INVALID_FILTER)

    findings = engine.get_findings(
        rule_id=rule_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        device_id=device_id,
        since=since_value,
        until=until_value,
        limit=limit,
    )
    views: list[DetectionFindingView] = [finding.to_view() for finding in findings]
    payload = DetectionFindingListData(count=len(views), findings=views)
    logger.info("Returning %d detection finding(s) via API", payload.count)
    return {
        "success": True,
        "message": "Detection findings retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/rules", response_model=None)
def list_rules(
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict:
    """Return the registered detectors and their diagnostics (M10.22).

    This is the discoverability surface for the detection layer: it names every
    detector, whether it is enabled, the window it reasons over, and how many
    subjects it currently holds. It exposes no thresholds, because a threshold
    is configuration rather than a runtime observation.
    """
    views = [_rule_view(rule) for rule in engine.get_rules()]
    diagnostics = engine.get_diagnostics()
    payload = DetectionRuleListData(count=len(views), rules=views)
    logger.info("Returning %d detection rule(s) via API", payload.count)
    return {
        "success": True,
        "message": "Detection rules retrieved",
        "data": {
            **payload.model_dump(mode="json"),
            "diagnostics": diagnostics.model_dump(mode="json"),
        },
    }


@router.post("/reset", response_model=None)
def reset_detection(
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict:
    """Discard retained findings and detector state (M10.22 dev helper).

    The only non-read verb M10 exposes, and it exists solely so detection can be
    verified against a running application from a clean slate. It clears
    in-memory observations; it mutates no persisted record, because M10 persists
    no finding.
    """
    engine.reset()
    logger.info("Detection state reset via API")
    return {
        "success": True,
        "message": "Detection state reset",
        "data": engine.get_diagnostics().model_dump(mode="json"),
    }
