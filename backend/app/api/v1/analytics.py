"""Analytics API endpoints for NetWatch AI (M13.18, hardened by M16).

Analytics is a *derived view* over the services M6–M12 already provide. It is not
a second statistics engine and it is not a place where numbers are extrapolated:
every figure is read from the object that owns it, and the only arithmetic is
presentation — an average, a share, a sort (M16.1).

What M16 changed here is the shape of the routes, not what they mean:

**Every route now takes a window.** ``since`` and ``until`` are ISO-8601 UTC with
``since`` inclusive and ``until`` exclusive (M13.26), ``bucket_seconds`` selects
the series resolution from the documented sizes, and the resolved window is
published on the response as its ``period``. A request that names no bounds gets
a one-hour window and is told so (``period.defaulted``) rather than being left to
infer it from timestamps it never sent (M16.7).

**A window that cannot be honoured is refused.** An inverted range, an unknown
bucket, or a range longer than ``MAX_WINDOW_SECONDS`` is a ``400`` naming what was
wrong — never a silently narrower or wider answer than the one asked for (M16.7).

**The routes stay thin.** Each handler resolves its window, calls one method on
:class:`~app.analytics.service.AnalyticsService` and returns the M13 envelope.
The service puts the live and persisted halves together, so no route decides what
a number means (M16.1). Where a database-derived block could not be read, the
response says so in an availability section rather than reporting a zero nobody
measured (M16.8).
"""

from __future__ import annotations

import logging
import time
from typing import Literal

from fastapi import APIRouter, Depends, Query

from app.analytics.alert_view import SEVERITY_KEYS
from app.analytics.metrics import DEFAULT_RANK_METRIC, MAX_GROUPS, RankMetric
from app.analytics.service import DEFAULT_RATE_WINDOW, AnalyticsService
from app.analytics.window import (
    BUCKET_SIZES,
    AnalyticsWindow,
    resolve_window,
)
from app.api.common import success_payload
from app.api.common.errors import InvalidFilterError
from app.api.common.validation import parse_epoch_filter, validate_time_range
from app.api.v1.deps import get_analytics_service

logger = logging.getLogger(__name__)

router = APIRouter()

#: Rate window accepted by ``analytics/traffic``, mirroring M6's own labels.
RateWindowLabel = Literal["1s", "10s", "60s"]

#: How many ranked entries a request gets when it does not ask for a number.
DEFAULT_TOP_LIMIT = 10
#: Largest ranking one request may ask for. The ceiling is the analytics layer's
#: own group cap (M16.2), not a second number invented here.
MAX_TOP_LIMIT = MAX_GROUPS

#: The severities the threat block always names, so a client renders fixed rows.
#: Taken from M11's vocabulary rather than re-spelled (M16.6).
SEVERITIES: tuple[str, ...] = SEVERITY_KEYS

#: The supported series resolutions, rendered once for the parameter help.
_BUCKET_HELP = ", ".join(str(size) for size in BUCKET_SIZES)

_SINCE_DESCRIPTION = (
    "Inclusive lower bound, ISO-8601 UTC. Defaults to one hour before 'until'."
)
_UNTIL_DESCRIPTION = "Exclusive upper bound, ISO-8601 UTC. Defaults to now."
_BUCKET_DESCRIPTION = (
    f"Series resolution in seconds; one of {_BUCKET_HELP}. "
    "Defaults to the smallest size that keeps the series bounded."
)


def analytics_window(
    since: str | None,
    until: str | None,
    bucket_seconds: int | None,
) -> AnalyticsWindow:
    """Resolve the request's window bounds into one bounded window (M16.7).

    Raises:
        InvalidFilterError: If a bound is not ISO-8601, the range is inverted,
            the bucket is not a documented size, or the range is longer than
            ``MAX_WINDOW_SECONDS``. Each of those is a request that cannot be
            honoured, so it is refused with the reason rather than adjusted into
            an answer to a different question.
    """
    try:
        lower = parse_epoch_filter(since, "since")
        upper = parse_epoch_filter(until, "until")
        validate_time_range(lower, upper)
        return resolve_window(
            since=lower,
            until=upper,
            bucket_seconds=bucket_seconds,
            now=time.time(),
        )
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="window") from exc


@router.get("/traffic", response_model=None)
def get_traffic_analytics(
    since: str | None = Query(default=None, description=_SINCE_DESCRIPTION),
    until: str | None = Query(default=None, description=_UNTIL_DESCRIPTION),
    bucket_seconds: int | None = Query(
        default=None, ge=1, description=_BUCKET_DESCRIPTION
    ),
    window: RateWindowLabel = Query(
        default=DEFAULT_RATE_WINDOW,
        description="Rate window used for the live per-second figures",
    ),
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=1,
        le=MAX_TOP_LIMIT,
        description="How many entries each ranking carries",
    ),
    by: RankMetric = Query(
        default=DEFAULT_RANK_METRIC, description="Metric the rankings are ordered by"
    ),
    service: AnalyticsService = Depends(get_analytics_service),
) -> dict:
    """Return traffic analytics: live totals, derived ratios and stored traffic.

    The live block is M13's unchanged view of the M6 snapshot — read once, so the
    totals, the rates and the protocol list all describe the same instant.
    ``stored`` is M16's: the same questions asked of the persisted packet table
    over this request's window. The two are deliberately different figures, which
    is why both are reported instead of one standing in for the other (M16.2).
    """
    period_window = analytics_window(since, until, bucket_seconds)
    payload = service.traffic(
        window=period_window, rate_window=window, limit=limit, by=by
    )
    logger.info(
        "Traffic analytics served (%d packet(s) live over a %s window)",
        payload.total_packets,
        payload.period.since,
    )
    return success_payload(
        "Traffic analytics retrieved", payload.model_dump(mode="json")
    )


@router.get("/protocols", response_model=None)
def get_protocol_analytics(
    since: str | None = Query(default=None, description=_SINCE_DESCRIPTION),
    until: str | None = Query(default=None, description=_UNTIL_DESCRIPTION),
    bucket_seconds: int | None = Query(
        default=None, ge=1, description=_BUCKET_DESCRIPTION
    ),
    by: RankMetric = Query(
        default=DEFAULT_RANK_METRIC,
        description="Metric the protocol list is ordered by",
    ),
    service: AnalyticsService = Depends(get_analytics_service),
) -> dict:
    """Return the protocol breakdown: the live distribution and the stored one.

    The live entries and their shares come from M6 as they are; ordering is the
    only thing this endpoint decides, and the name tie-break makes it total
    (M13.24). ``stored`` is M16's windowed breakdown of the packet table, whose
    percentages are taken against *that window's* packet count — the whole
    population the query selected — rather than against the returned rows
    (M16.3).
    """
    period_window = analytics_window(since, until, bucket_seconds)
    payload = service.protocols(window=period_window, by=by)
    logger.info("Protocol analytics served (%d protocol(s))", payload.count)
    return success_payload(
        "Protocol analytics retrieved", payload.model_dump(mode="json")
    )


@router.get("/devices", response_model=None)
def get_device_analytics(
    since: str | None = Query(default=None, description=_SINCE_DESCRIPTION),
    until: str | None = Query(default=None, description=_UNTIL_DESCRIPTION),
    bucket_seconds: int | None = Query(
        default=None, ge=1, description=_BUCKET_DESCRIPTION
    ),
    by: RankMetric = Query(
        default=DEFAULT_RANK_METRIC, description="Metric the ranking is ordered by"
    ),
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=1,
        le=MAX_TOP_LIMIT,
        description="How many devices the ranking carries",
    ),
    service: AnalyticsService = Depends(get_analytics_service),
) -> dict:
    """Return device analytics: registry totals and the devices seen this period.

    Both halves come from the M8 manager's own views, so the activity state is the
    one M8 computed rather than one guessed here. The ranking is over traffic
    totals, never a risk figure — M8 does not score risk, so there is none to rank
    by (M13.10). ``windowed`` lists the devices M8 last observed inside the
    period; it does not reconstruct what was observed then, because the registry
    holds no history and M16 does not invent one (M16.4).
    """
    period_window = analytics_window(since, until, bucket_seconds)
    payload = service.devices(window=period_window, limit=limit, by=by)
    logger.info(
        "Device analytics served (%d device(s), %d in period)",
        payload.total,
        payload.windowed.data.total if payload.windowed.data else 0,
    )
    return success_payload(
        "Device analytics retrieved", payload.model_dump(mode="json")
    )


@router.get("/connections", response_model=None)
def get_connection_analytics(
    since: str | None = Query(default=None, description=_SINCE_DESCRIPTION),
    until: str | None = Query(default=None, description=_UNTIL_DESCRIPTION),
    bucket_seconds: int | None = Query(
        default=None, ge=1, description=_BUCKET_DESCRIPTION
    ),
    by: RankMetric = Query(
        default="bytes", description="Metric the ranking is ordered by"
    ),
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=1,
        le=MAX_TOP_LIMIT,
        description="How many conversations the ranking carries",
    ),
    service: AnalyticsService = Depends(get_analytics_service),
) -> dict:
    """Return connection analytics: tracker counters and stored conversations.

    The counters are the tracker's own, so they agree with ``/connections``. The
    ranking deliberately includes retired conversations: the busiest conversation
    of a session is frequently one that has already closed, and omitting it would
    answer a narrower question than "which conversations carried the most
    traffic". ``stored`` is M16's windowed read of the ``connections`` table,
    selecting on ``start_time`` — M9's own rule for the same filter — so a
    conversation still in progress is never dropped from its own window (M16.5).
    """
    period_window = analytics_window(since, until, bucket_seconds)
    payload = service.connections(window=period_window, limit=limit, by=by)
    logger.info(
        "Connection analytics served (%d tracked, %d stored in period)",
        payload.tracked,
        payload.stored.data.total if payload.stored.data else 0,
    )
    return success_payload(
        "Connection analytics retrieved", payload.model_dump(mode="json")
    )


@router.get("/threats", response_model=None)
def get_threat_analytics(
    since: str | None = Query(default=None, description=_SINCE_DESCRIPTION),
    until: str | None = Query(default=None, description=_UNTIL_DESCRIPTION),
    bucket_seconds: int | None = Query(
        default=None, ge=1, description=_BUCKET_DESCRIPTION
    ),
    service: AnalyticsService = Depends(get_analytics_service),
) -> dict:
    """Return threat analytics across M10, M11 and M12, plus the stored window.

    Three layers are reported side by side and kept distinct, because collapsing
    them would invent a single "threat" number that no milestone produces:

    * M10's findings — what the detectors *observed*, with no judgement;
    * M11's alerts by severity and status — the evidence-based judgement;
    * M12's incidents by lifecycle state and by risk band — the bounded
      prioritisation metric.

    ``stored`` adds a fourth, orthogonal view rather than a fourth judgement: the
    same M11 alert table read over this request's period, so a client can ask "how
    did alerts break down in this window" instead of only "what is stored now".
    ``findings`` window-sums the retained M10 observations and ``incident_links``
    reports the alert-to-incident references M12 already holds (M16.6).

    No field here is a second risk score. ``incidents_by_risk_band`` and the
    stored alerts' ``by_risk_band`` both read M12's value, banded by the one table
    M12 defines (M12.27).
    """
    period_window = analytics_window(since, until, bucket_seconds)
    payload = service.threats(window=period_window)
    logger.info(
        "Threat analytics served (%d alert(s), %d incident(s), %d in period)",
        payload.alerts_total,
        payload.incidents_total,
        payload.stored.data.total if payload.stored.data else 0,
    )
    return success_payload(
        "Threat analytics retrieved", payload.model_dump(mode="json")
    )


__all__ = [
    "DEFAULT_TOP_LIMIT",
    "MAX_TOP_LIMIT",
    "SEVERITIES",
    "analytics_window",
    "router",
]
