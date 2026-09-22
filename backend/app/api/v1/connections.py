"""Read-only connection tracking API endpoints for NetWatch AI (M9.22).

These endpoints expose the live conversation registry maintained by the M9
:class:`~app.connections.manager.ConnectionTracker`. M9 tracks conversations;
it never edits, blocks or judges one, so no connection is ever mutated. The one
non-read verb is the explicit ``POST /expire`` verification helper, which runs
the idle sweep and mutates no record itself.

This is deliberately *not* the master REST API — that milestone is M13. These
internal endpoints exist so the connection layer can be verified end to end
against the running application.

Responses follow the same envelope as the rest of the API::

    {"success": true,  "message": "...", "data": {...}}
    {"success": false, "message": "...", "errors": [{"field": ..., "code": ...}]}
"""

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BeforeValidator

from app.connections.identity import PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.schemas.connection import ConnectionListData, ConnectionView

logger = logging.getLogger(__name__)

router = APIRouter()


def _canonical_protocol(value: str) -> str:
    """Fold a protocol query value to its canonical label before validation.

    The tracker's own protocol filter is case- and whitespace-insensitive, so
    the API layer must not be stricter than the service behind it: ``tcp`` is
    accepted and validated as ``TCP``. An unknown value still fails with a 422.
    """
    return value.strip().upper()


def _canonical_state(value: str) -> str:
    """Fold a state query value to its canonical label before validation."""
    return value.strip().lower()


# Tracked transport protocols, mirrored from the M9 identity rules. The Literal
# keeps the OpenAPI schema honest and lets FastAPI reject an unknown protocol
# with a 422 before the handler runs, so a typo can never look like "no
# conversations". The validator folds case, so the API agrees with the tracker.
ProtocolParam = Annotated[
    Literal["TCP", "UDP", "ICMP"],
    BeforeValidator(_canonical_protocol),
]

# Connection states, mirrored from ``ConnectionState`` (M9.10/M9.11).
StateParam = Annotated[
    Literal[
        "observed",
        "established",
        "closing",
        "closed",
        "active",
        "inactive",
        "unknown",
    ],
    BeforeValidator(_canonical_state),
]

# Bounds for the ``limit`` query parameter, so a response stays bounded even
# when thousands of conversations are being tracked.
_MIN_LIMIT = 1
_MAX_LIMIT = 1000
DEFAULT_CONNECTION_LIMIT = 100

# Error code returned when a connection id is unknown.
_CODE_CONNECTION_NOT_FOUND = "CONNECTION_NOT_FOUND"
# Error code returned when a filter value is unusable.
_CODE_INVALID_FILTER = "INVALID_FILTER"

# Protocols whose conversations have no ports at all.
_PORTLESS_PROTOCOLS = frozenset({PROTOCOL_ICMP})

_TRACKED_PROTOCOLS = (PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP)


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


def _invalid_filter(exc: ValueError, field: str) -> JSONResponse:
    """Turn a tracker filter rejection into a 400 response.

    A filter that cannot be honoured must fail loudly rather than be silently
    ignored, so a typo never turns into a request that returns every
    conversation.
    """
    return _error_response(400, str(exc), field, _CODE_INVALID_FILTER)


@router.get("", response_model=None)
def list_connections(
    protocol: ProtocolParam | None = Query(
        default=None, description="Keep only this transport protocol"
    ),
    source_ip: str | None = Query(
        default=None, description="Keep only conversations with this source address"
    ),
    destination_ip: str | None = Query(
        default=None,
        description="Keep only conversations with this destination address",
    ),
    source_port: int | None = Query(
        default=None,
        ge=0,
        le=65535,
        description="Keep only conversations with this source port",
    ),
    destination_port: int | None = Query(
        default=None,
        ge=0,
        le=65535,
        description="Keep only conversations with this destination port",
    ),
    device_id: str | None = Query(
        default=None,
        description="Keep only conversations where either end is this M8 device",
    ),
    state: StateParam | None = Query(
        default=None, description="Keep only conversations in this state"
    ),
    active_only: bool = Query(
        default=True,
        description="When True, only conversations still being observed",
    ),
    limit: int = Query(
        default=DEFAULT_CONNECTION_LIMIT,
        ge=_MIN_LIMIT,
        le=_MAX_LIMIT,
        description="Maximum number of connections to return",
    ),
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict | JSONResponse:
    """Return tracked conversations, most recently seen first (M9.21).

    Active conversations are returned by default; pass ``active_only=false`` to
    include retired ones. An unusable filter is rejected with 400.
    """
    if protocol is not None and protocol in _PORTLESS_PROTOCOLS and (
        source_port is not None or destination_port is not None
    ):
        return _error_response(
            400,
            f"{protocol} conversations have no ports",
            "source_port",
            _CODE_INVALID_FILTER,
        )

    try:
        views: list[ConnectionView] = tracker.list_connection_views(
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            device_id=device_id,
            state=state,
            active_only=active_only,
            limit=limit,
        )
    except ValueError as exc:
        return _invalid_filter(exc, "filter")

    payload = ConnectionListData(count=len(views), connections=views)
    logger.info("Returning %d connection(s) via API", payload.count)
    return {
        "success": True,
        "message": "Connections retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.get("/active", response_model=None)
def list_active_connections(
    limit: int = Query(
        default=DEFAULT_CONNECTION_LIMIT,
        ge=_MIN_LIMIT,
        le=_MAX_LIMIT,
        description="Maximum number of connections to return",
    ),
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict:
    """Return only the conversations still being observed (M9.21).

    Registered before the catch-all id route so ``active`` can never be
    mistaken for a connection id.
    """
    views: list[ConnectionView] = tracker.get_active_connection_views(limit=limit)
    payload = ConnectionListData(count=len(views), connections=views)
    logger.info("Returning %d active connection(s) via API", payload.count)
    return {
        "success": True,
        "message": "Active connections retrieved",
        "data": payload.model_dump(mode="json"),
    }


@router.post("/expire", response_model=None)
def expire_connections(
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict:
    """Run the idle sweep now and report what it retired (M9.22 dev helper).

    This is the only non-read verb M9 exposes, and it exists solely so that
    expiration and persistence can be verified against a running application.
    The sweep retires idle conversations; it never edits or blocks one.
    """
    expired = tracker.expire_connections()
    logger.info("Connection sweep retired %d conversation(s)", expired)
    return {
        "success": True,
        "message": "Idle connections expired",
        "data": {
            "expired": expired,
            "active": tracker.get_active_count(),
            "historical": tracker.get_historical_count(),
        },
    }


@router.get("/{connection_id:path}", response_model=None)
def get_connection(
    connection_id: str,
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict | JSONResponse:
    """Return one tracked conversation, or 404 when the id is unknown.

    The id may contain ``|`` and ``:`` (it renders a 5-tuple), so the path is
    captured as a path segment rather than parsed as routing syntax.
    """
    view = tracker.get_connection_view(connection_id)
    if view is None:
        logger.info("Connection lookup failed for id %r", connection_id)
        return _error_response(
            404,
            "Connection not found",
            "connection_id",
            _CODE_CONNECTION_NOT_FOUND,
        )
    return {
        "success": True,
        "message": "Connection retrieved",
        "data": view.model_dump(mode="json"),
    }
