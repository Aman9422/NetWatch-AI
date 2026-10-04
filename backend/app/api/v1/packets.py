"""Packet read endpoints for NetWatch AI (M13.8).

The public, frontend-facing packet API. M7 owns the storage and the query rules;
this module validates the request, delegates to
:class:`~app.services.packet_query.PacketQueryService`, and renders the shared
envelope. It holds no query logic of its own, which is what keeps a filter
defined in exactly one place.

**Two listed filters are deliberately not offered**, and
``docs/17_M13_REST_API_Design.md`` §7.2 records why:

* ``interface`` — the ``packets`` table has no capture-interface column, because
  M7 dropped it rather than misuse a column;
* ``device_id`` — ``packets.device_id`` is always ``NULL``, because M7 does not
  resolve devices.

A filter that always matches nothing is worse than an absent one, so neither is
accepted rather than being silently ignored.

**No payload and no ``payload_length`` is ever returned**: the M7 mapping never
stores one (M7.5/M13.8).

Responses use the shared envelope (M13.4) and errors the shared hierarchy
(M13.5), so a route no longer builds either by hand.
"""

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import (
    ErrorCode,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    parse_datetime_filter,
    success_payload,
    validate_time_range,
)
from app.database.session import get_db
from app.persistence.retention import get_packet_retention_service
from app.schemas.packet_query import PacketListData
from app.services.packet_query import PacketQueryService

logger = logging.getLogger(__name__)

router = APIRouter()


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
    since: str | None = Query(
        default=None,
        description="Keep packets captured at or after this ISO-8601 UTC instant",
    ),
    until: str | None = Query(
        default=None,
        description="Keep packets captured strictly before this ISO-8601 UTC instant",
    ),
    window: PageWindow = Depends(pagination_params),
    db: Session = Depends(get_db),
) -> dict:
    """Return stored packets matching the given filters, newest first.

    Filters combine with AND. ``since`` is inclusive and ``until`` exclusive, so
    two adjacent windows never both claim the same instant (M13.26). Ordering is
    ``timestamp DESC, id DESC`` — total, so the same query returns the same page
    (M13.24). An unusable timestamp is a ``400`` naming the field rather than a
    silently widened window.
    """
    try:
        since_value = parse_datetime_filter(since, "since")
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="since") from exc
    try:
        until_value = parse_datetime_filter(until, "until")
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="until") from exc
    try:
        validate_time_range(since_value, until_value)
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="since") from exc

    service = PacketQueryService(db)
    filters: dict = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "since": since_value,
        "until": until_value,
    }
    packets = service.list(
        **filters, limit=window.limit, offset=window.offset
    )
    total = service.count(**filters)
    payload = PacketListData(
        **page_meta(len(packets), window, total=total), packets=packets
    )
    logger.info(
        "Returning %d stored packet(s) via API (total matching: %d)",
        payload.count,
        payload.total,
    )
    return success_payload("Packets retrieved", payload.model_dump(mode="json"))


@router.post("/retention/cleanup", response_model=None)
def run_retention_cleanup() -> dict:
    """Delete packet rows older than the configured retention window.

    **Development/testing helper (M7.14).** This exposes the retention service so
    M7.23 can be verified without a shell. It deletes only packets strictly older
    than ``PACKET_RETENTION_DAYS`` and never touches recent ones, so it is safe to
    call against a development database.
    """
    deleted = get_packet_retention_service().cleanup()
    logger.info("Packet retention cleanup triggered via API (%d row(s))", deleted)
    return success_payload(
        "Packet retention cleanup complete", {"deleted": deleted}
    )


@router.get("/{packet_id}", response_model=None)
def get_packet(
    packet_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """Return one stored packet, or ``404`` when the id is unknown."""
    view = PacketQueryService(db).get(packet_id)
    if view is None:
        logger.info("Packet lookup failed for id %d", packet_id)
        raise NotFoundError(
            "Packet not found",
            code=ErrorCode.PACKET_NOT_FOUND,
            field="packet_id",
        )
    return success_payload("Packet retrieved", view.model_dump(mode="json"))
