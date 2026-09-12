"""Read-only traffic statistics API endpoints for NetWatch AI (M6.16/M6.17).

These endpoints expose the aggregated output of the M6
:class:`~app.statistics.manager.TrafficStatisticsManager`. They are strictly
read-only except for the explicit development/testing reset endpoint, and they
never start, stop, or otherwise affect packet capture.
"""

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query

from app.schemas.statistics import ProtocolStat, TopEntry, TopTalkers, TrafficSnapshot
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

# Bounds for the ``limit`` query parameter shared by ranking endpoints.
_MIN_LIMIT = 1
_MAX_LIMIT = 1000


@router.get("/traffic", response_model=None)
def get_traffic_statistics(
    window: RateWindowLabel = Query(
        default="1s", description="Rate window used for packets/bytes per second"
    ),
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the current full traffic statistics snapshot."""
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
    return {
        "success": True,
        "message": "Traffic statistics retrieved",
        "data": snapshot.model_dump(mode="json"),
    }


@router.get("/protocols", response_model=None)
def get_protocol_statistics(
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the protocol distribution with packet, byte and percentage data."""
    protocols: list[ProtocolStat] = manager.get_protocol_statistics()
    return {
        "success": True,
        "message": "Protocol statistics retrieved",
        "data": [protocol.model_dump(mode="json") for protocol in protocols],
    }


@router.get("/top-talkers", response_model=None)
def get_top_talkers(
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT, ge=_MIN_LIMIT, le=_MAX_LIMIT,
        description="Number of ranked entries to return per category",
    ),
    by: RankingMetric = Query(
        default="packets", description="Ranking metric: packets or bytes"
    ),
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Return the busiest sources, destinations and conversations."""
    talkers = manager.get_top_talkers(limit=limit, by=by)
    payload = TopTalkers(
        sources=talkers["sources"],
        destinations=talkers["destinations"],
        conversations=talkers["conversations"],
    )
    return {
        "success": True,
        "message": "Top talkers retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/ports", response_model=None)
def get_top_ports(
    limit: int = Query(
        default=DEFAULT_TOP_LIMIT, ge=_MIN_LIMIT, le=_MAX_LIMIT,
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
    """Return the most active ports for the requested direction (M6.6)."""
    ports: list[TopEntry] = manager.get_top_ports(
        limit=limit, by=by, direction=direction
    )
    return {
        "success": True,
        "message": "Port statistics retrieved",
        "data": [entry.model_dump(mode="json") for entry in ports],
    }


@router.post("/reset", response_model=None)
def reset_statistics(
    manager: TrafficStatisticsManager = Depends(get_statistics_manager),
) -> dict:
    """Reset all aggregated statistics (development/testing only).

    Clears counters and time-window data. It never stops packet capture and
    leaves the service fully available.
    """
    manager.reset()
    logger.info("Traffic statistics reset via API")
    return {
        "success": True,
        "message": "Statistics reset",
        "data": {"reset": True},
    }
