"""Read-only traffic statistics API endpoints for NetWatch AI (M13.9).

These endpoints expose the aggregated output of the M6
:class:`~app.statistics.manager.TrafficStatisticsManager`. They are strictly
read-only except for the explicit development/testing reset endpoint, and they
never start, stop, or otherwise affect packet capture.

**Nothing is recalculated here.** A snapshot, a distribution and a ranking are all
the manager's own aggregates; the route only selects one and renders it. A route
that summed its own totals could disagree with the live counters it was reading
(M13.9).

**The ``limit`` on the ranking endpoints is not the shared page window.** A
ranking is a top-N over an aggregate the manager recomputes per call, not a table
a client pages through, so there is deliberately no ``offset`` — the "page" is
always the head of a freshly ordered list (M13.24). The ceiling is taken from the
shared contract anyway, so the API publishes one "largest response" number rather
than two that merely happen to agree.

**The envelope is not built here.** Successes go through :func:`success_payload`,
so this module carries no response shape of its own (M13.4).
"""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query

from app.api.common import success_payload
from app.api.common.pagination import MAX_PAGE_SIZE
from app.schemas.statistics import (
    ProtocolStat,
    TopEntry,
    TopTalkers,
    TrafficSnapshot,
)
from app.statistics.manager import (
    DEFAULT_TOP_LIMIT,
    TrafficStatisticsManager,
    get_statistics_manager,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Supported ranking metrics for top-talker queries.
RankingMetric = Literal["packets", "bytes"]
# Supported rate-window labels exposed through the API.
RateWindowLabel = Literal["1s", "10s", "60s"]
# Supported port directions for the port-statistics endpoint.
PortDirection = Literal["source", "destination"]

# Bounds for the ``limit`` query parameter shared by the ranking endpoints.
_MIN_LIMIT = 1
_MAX_LIMIT = MAX_PAGE_SIZE


@router.get("/traffic", response_model=None)
def get_traffic_statistics(
    window: RateWindowLabel = Query(
        default="1s", description="Rate window used for packets/bytes per second"
    ),
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the current full traffic statistics snapshot (M13.9).

    ``window`` selects which rate window the per-second figures describe. The
    default ``1s`` is the snapshot's own live rate, so nothing is recomputed; a
    wider window asks the manager for that window's rate and the snapshot is
    re-emitted with those figures in place, which keeps one response shape for
    every window.
    """
    snapshot: TrafficSnapshot = manager.get_statistics()
    if window != "1s":
        packets_per_second, bytes_per_second = manager.get_rates(window)
        snapshot = snapshot.model_copy(
            update={
                "packets_per_second": packets_per_second,
                "bytes_per_second": bytes_per_second,
                "bits_per_second": bytes_per_second * 8.0,
            }
        )
    return success_payload(
        "Traffic statistics retrieved", snapshot.model_dump(mode="json")
    )


@router.get("/protocols", response_model=None)
def get_protocol_statistics(
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the protocol distribution with packet, byte and percentage data.

    The distribution is complete rather than a page of it: every protocol the
    manager has seen is listed, because a truncated distribution would misreport
    the shares it exists to convey (M13.9).
    """
    protocols: list[ProtocolStat] = manager.get_protocol_statistics()
    return success_payload(
        "Protocol statistics retrieved",
        [protocol.model_dump(mode="json") for protocol in protocols],
    )


@router.get("/top-talkers", response_model=None)
def get_top_talkers(
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=_MIN_LIMIT,
        le=_MAX_LIMIT,
        description="Number of ranked entries to return per category",
    ),
    by: RankingMetric = Query(
        default="packets", description="Ranking metric: packets or bytes"
    ),
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the busiest sources, destinations and conversations (M13.9).

    ``limit`` applies to each category, so a limit of 10 can return up to 30
    entries across the three lists.
    """
    talkers = manager.get_top_talkers(limit=limit, by=by)
    payload = TopTalkers(
        sources=talkers["sources"],
        destinations=talkers["destinations"],
        conversations=talkers["conversations"],
    )
    return success_payload(
        "Top talkers retrieved", payload.model_dump(mode="json")
    )


@router.get("/ports", response_model=None)
def get_top_ports(
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT,
        ge=_MIN_LIMIT,
        le=_MAX_LIMIT,
        description="Number of ranked ports to return",
    ),
    by: RankingMetric = Query(
        default="packets", description="Ranking metric: packets or bytes"
    ),
    direction: PortDirection = Query(
        default="destination", description="Port direction: source or destination"
    ),
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the most active ports for the requested direction (M6.6/M13.9)."""
    ports: list[TopEntry] = manager.get_top_ports(
        limit=limit, by=by, direction=direction
    )
    return success_payload(
        "Port statistics retrieved",
        [entry.model_dump(mode="json") for entry in ports],
    )


@router.post("/reset", response_model=None)
def reset_statistics(
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Reset all aggregated statistics (development/testing only).

    Clears counters and time-window data. It never stops packet capture and leaves
    the service fully available.
    """
    manager.reset()
    logger.info("Traffic statistics reset via API")
    return success_payload("Statistics reset", {"reset": True})
