"""Detection finding API endpoints for NetWatch AI (M13.12).

Exposes the findings the M10 :class:`~app.detection.engine.DetectionEngine`
observed. A finding is an *observation*: it has no severity, no risk score and no
lifecycle, so nothing here can acknowledge, suppress or escalate anything. Those
belong to M11 and M12.

The engine *observes*; this router only reports. There is deliberately no
"run the rules now" endpoint, because that would put detection on a request path
(M13.12).

Findings live in the engine's bounded runtime history (M10.19), so
``GET /detections/{finding_id}`` answers a finding that has aged out of the cap
with a ``404``. That is the honest answer: it is no longer retained.
"""

import logging

from fastapi import APIRouter, Depends, Query

from app.api.common import (
    ErrorCode,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    parse_epoch_filter,
    success_payload,
    validate_time_range,
)
from app.api.common.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.detection import DetectionEngine, get_detection_engine
from app.schemas.detection import (
    DetectionFindingListData,
    DetectionFindingView,
    DetectionRuleListData,
    DetectionRuleView,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# The finding collection serves the shared page window (M13.24). These names
# remain because the detection tests import them, but they now *mirror* the one
# pagination contract rather than restating its numbers — two copies of
# "default 100, maximum 1000" is how the four pre-M13 routers drifted apart.
MIN_FINDING_LIMIT = 1
MAX_FINDING_LIMIT = MAX_PAGE_SIZE
DEFAULT_FINDING_LIMIT = DEFAULT_PAGE_SIZE


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
    window: PageWindow = Depends(pagination_params),
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict:
    """Return retained detection findings, newest first (M10.22).

    Filters combine with AND. ``since`` is inclusive and ``until`` exclusive, so a
    query window has an explicit start and end (M10.13). An unusable filter is
    rejected with 400 rather than being ignored, and the error names the field the
    caller actually got wrong.
    """
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

    filters: dict = {
        "rule_id": rule_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "device_id": device_id,
        "since": since_value,
        "until": until_value,
    }
    # The engine's history orders newest first and accepts a limit but no offset
    # (M10.22), so this reads as far as the page ends and slices. Reading
    # ``window.end`` rather than only ``window.limit`` is what makes the second
    # page and beyond reachable at all — without it, a client asking for
    # ``offset=100`` silently received page one forever (M13.24).
    findings = engine.get_findings(**filters, limit=window.end)
    page = window.slice(findings)
    views: list[DetectionFindingView] = [finding.to_view() for finding in page]
    payload = DetectionFindingListData(
        **page_meta(
            len(views), window, total=engine.count_findings(**filters)
        ),
        findings=views,
    )
    logger.info("Returning %d detection finding(s) via API", payload.count)
    return success_payload(
        "Detection findings retrieved",
        payload.model_dump(mode="json", exclude_none=True),
    )


@router.get("/rules", response_model=None)
def list_rules(
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict:
    """Return every registered detector with its state and the engine diagnostics.

    Declared before ``/{finding_id}`` so ``rules`` can never be read as a finding
    identifier (M13.12). A disabled detector is still listed, because "which
    detectors exist" and "which are running" are two different questions and the
    payload answers both.
    """
    rules = [_rule_view(rule) for rule in engine.get_rules()]
    payload = DetectionRuleListData(
        count=len(rules),
        rules=rules,
        diagnostics=engine.get_diagnostics(),
    )
    logger.info("Returning %d detection rule(s) via API", payload.count)
    return success_payload(
        "Detection rules retrieved", payload.model_dump(mode="json")
    )


@router.post("/reset", response_model=None)
def reset_detection(
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict:
    """Discard retained findings, counters and detector state (M10.22 helper).

    The pre-existing development helper: it clears only in-memory observation
    state and turns nothing on or off, so a verification run can start from a
    known point. Declared before ``/{finding_id}``, and it is the only ``POST``
    this router accepts because a finding has no mutation to offer.
    """
    engine.reset()
    diagnostics = engine.get_diagnostics()
    logger.info("Detection state reset via API")
    return success_payload(
        "Detection state reset", diagnostics.model_dump(mode="json")
    )


@router.get("/{finding_id}", response_model=None)
def get_finding(
    finding_id: str,
    engine: DetectionEngine = Depends(get_detection_engine),
) -> dict:
    """Return one retained detection finding (M13.12).

    Findings live in the engine's bounded runtime history and are never
    persisted, so an identifier that has aged out of the cap is a ``404`` rather
    than an empty object. That is the honest answer: the finding is no longer
    retained, and returning a placeholder would invent an observation.
    """
    finding = engine.get_finding(finding_id)
    if finding is None:
        logger.info("Detection finding lookup failed for id %r", finding_id)
        raise NotFoundError(
            "Detection finding not found or no longer retained",
            code=ErrorCode.FINDING_NOT_FOUND,
            field="finding_id",
        )
    return success_payload(
        "Detection finding retrieved", finding.to_view().model_dump(mode="json")
    )
