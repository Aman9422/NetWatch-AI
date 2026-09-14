"""Internal packet read endpoints for NetWatch AI (M7.16).

**Status: internal / development endpoints.** The master roadmap places the
complete, frontend-facing packet REST API in M13. M7 therefore exposes only the
minimum needed to *verify* that packet persistence works end to end: a read-only
query over the stored packets, and an explicitly-labelled manual trigger for the
retention cleanup so M7.23 can be checked without a shell.

Nothing here writes packet data, starts or stops capture, or touches detection.
Both endpoints read through
:class:`~app.services.packet_query.PacketQueryService`, which is where the query
rules live.

Responses follow the same envelope as the rest of the API::

    {"success": true,  "message": "...", "data": {...}}
    {"success": false, "message": "...", "errors": [{"field": ..., "code": ...}]}
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.persistence.retention import get_packet_retention_service
from app.schemas.packet_query import PacketListData
from app.services.packet_query import (
    DEFAULT_PACKET_LIMIT,
    MAX_PACKET_LIMIT,
    PacketQueryService,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Error code returned when a packet id is unknown.
_CODE_PACKET_NOT_FOUND = "PACKET_NOT_FOUND"


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


def _to_naive_utc(value: datetime | None) -> datetime | None:
    """Convert a boundary timestamp into the naive UTC form the table stores.

    Packets are written as timezone-aware UTC datetimes, but SQLite keeps only
    the wall-clock part, so stored values read back as *naive* UTC. A filter
    datetime must therefore be converted to UTC and stripped of its offset
    before it is compared, otherwise an offset such as ``+05:30`` would shift
    the comparison by hours.

    A datetime supplied without an offset is taken to mean UTC, which matches
    how the values are stored and is the least surprising reading for a client.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


@router.get("", response_model=None)
def list_packets(
    source_ip: str | None = Query(
        default=None, description="Keep only packets from this source address"
    ),
    destination_ip: str | None = Query(
        default=None, description="Keep only packets to this destination address"
    ),
    protocol: str | None = Query(
        default=None, description="Keep only this protocol label (TCP, UDP, ...)"
    ),
    source_port: int | None = Query(
        default=None, ge=0, le=65535, description="Keep only this source port"
    ),
    destination_port: int | None = Query(
        default=None, ge=0, le=65535, description="Keep only this destination port"
    ),
    since: datetime | None = Query(
        default=None, description="Keep packets captured at or after this instant"
    ),
    until: datetime | None = Query(
        default=None, description="Keep packets captured at or before this instant"
    ),
    limit: int = Query(
        default=DEFAULT_PACKET_LIMIT,
        ge=1,
        le=MAX_PACKET_LIMIT,
        description="Maximum number of packets to return",
    ),
    offset: int = Query(
        default=0, ge=0, description="Number of matching packets to skip"
    ),
    db: Session = Depends(get_db),
) -> dict:
    """Return stored packets matching the given filters, newest first."""
    service = PacketQueryService(db)
    filters: dict = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "since": _to_naive_utc(since),
        "until": _to_naive_utc(until),
    }
    packets = service.list(**filters, limit=limit, offset=offset)
    total = service.count(**filters)
    payload = PacketListData(count=len(packets), total=total, packets=packets)
    logger.info(
        "Returning %d stored packet(s) via API (total matching: %d)",
        payload.count,
        payload.total,
    )
    return {
        "success": True,
        "message": "Packets retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.post("/retention/cleanup", response_model=None)
def run_retention_cleanup() -> dict:
    """Delete packet rows older than the configured retention window.

    **Development/testing helper (M7.14).** This exposes the retention service
    so M7.23 can be verified without a shell. It deletes only packets strictly
    older than ``PACKET_RETENTION_DAYS`` and never touches recent ones, so it is
    safe to call against a development database.
    """
    deleted = get_packet_retention_service().cleanup()
    logger.info("Packet retention cleanup triggered via API (%d row(s))", deleted)
    return {
        "success": True,
        "message": "Packet retention cleanup complete",
        "data": {"deleted": deleted},
    }


@router.get("/{packet_id}", response_model=None)
def get_packet(
    packet_id: int,
    db: Session = Depends(get_db),
) -> dict | JSONResponse:
    """Return one stored packet, or 404 when the id is unknown."""
    view = PacketQueryService(db).get(packet_id)
    if view is None:
        logger.info("Packet lookup failed for id %d", packet_id)
        return _error_response(
            404, "Packet not found", "packet_id", _CODE_PACKET_NOT_FOUND
        )
    return {
        "success": True,
        "message": "Packet retrieved",
        "data": view.model_dump(mode="json"),
    }
