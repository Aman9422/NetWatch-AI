"""Connection API endpoints for NetWatch AI (M13.11).

Exposes the live conversation registry maintained by the M9
:class:`~app.connections.manager.ConnectionTracker`. M9 tracks conversations; it
never edits, blocks or judges one, so no connection is ever mutated. The one
non-read verb is the explicit ``POST /expire`` verification helper, which runs
the idle sweep and mutates no record of its own.

Every filter is validated by the tracker, which raises ``ValueError`` for a value
it cannot honour; the route turns that into a ``400 INVALID_FILTER`` rather than a
silently wider result set (M13.25). ICMP carries no ports, so a port filter
combined with ``protocol=ICMP`` is a ``400`` rather than an empty page.

Paging uses the shared ``limit``/``offset`` contract (M13.24) and ordering is
``last_seen DESC, connection_id`` — total, so the same query returns the same
page. The registry is in memory, so the route resolves the whole filtered set
once and then slices it, which makes ``total`` the real match count.
"""

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BeforeValidator

from app.api.common import (
    ErrorCode,
    InvalidFilterError,
    NotFoundError,
    PageWindow,
    page_meta,
    pagination_params,
    success_payload,
)
from app.connections.identity import PROTOCOL_ICMP
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.schemas.connection import ConnectionListData, ConnectionView

logger = logging.getLogger(__name__)

router = APIRouter()


def _canonical_protocol(value: str) -> str:
    """Fold a protocol query value to its canonical label before validation.

    The tracker's own protocol filter is case- and whitespace-insensitive, so the
    API layer must not be stricter than the service behind it: ``tcp`` is accepted
    and validated as ``TCP``. An unknown value still fails with a 422.
    """
    return value.strip().upper()


def _canonical_state(value: str) -> str:
    """Fold a state query value to its canonical label before validation."""
    return value.strip().lower()


# Tracked transport protocols, mirrored from the M9 identity rules. The Literal
# keeps the OpenAPI schema honest and lets FastAPI reject an unknown protocol with
# a 422 before the handler runs, so a typo can never look like "no conversations".
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

# Protocols whose conversations have no ports at all.
_PORTLESS_PROTOCOLS = frozenset({PROTOCOL_ICMP})


def _matching_views(
    tracker: ConnectionTracker,
    *,
    protocol: str | None,
    source_ip: str | None,
    destination_ip: str | None,
    source_port: int | None,
    destination_port: int | None,
    device_id: str | None,
    state: str | None,
    active_only: bool,
) -> list[ConnectionView]:
    """Return every conversation matching the filters, unresized.

    The tracker is the authority on which filters are usable, so this helper only
    performs the translation of a rejected filter into a ``400``. An unusable
    filter must fail loudly rather than be silently dropped, so a typo never turns
    into a request that returns every conversation.

    The set is resolved without a limit because the route pages it in memory: that
    is what makes the reported ``total`` the true match count rather than the size
    of whichever page happened to be requested.
    """
    if protocol is not None and protocol in _PORTLESS_PROTOCOLS and (
        source_port is not None or destination_port is not None
    ):
        raise InvalidFilterError(
            f"{protocol} conversations have no ports", field="source_port"
        )
    try:
        return tracker.list_connection_views(
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            device_id=device_id,
            state=state,
            active_only=active_only,
        )
    except ValueError as exc:
        raise InvalidFilterError(str(exc), field="filter") from exc


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
    window: PageWindow = Depends(pagination_params),
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict:
    """Return tracked conversations, most recently seen first (M9.21).

    Active conversations are returned by default; pass ``active_only=false`` to
    include retired ones. An unusable filter is rejected with 400.
    """
    matched = _matching_views(
        tracker,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        device_id=device_id,
        state=state,
        active_only=active_only,
    )
    page = window.slice(matched)
    payload = ConnectionListData(
        **page_meta(len(page), window, total=len(matched)),
        connections=page,
    )
    logger.info(
        "Returning %d of %d connection(s) via API", payload.count, len(matched)
    )
    return success_payload("Connections retrieved", payload.model_dump(mode="json"))


@router.get("/active", response_model=None)
def list_active_connections(
    window: PageWindow = Depends(pagination_params),
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict:
    """Return only the conversations still being observed (M9.21).

    Registered before the catch-all id route so ``active`` can never be mistaken
    for a connection id.
    """
    active: list[ConnectionView] = tracker.get_active_connection_views()
    page = window.slice(active)
    payload = ConnectionListData(
        **page_meta(len(page), window, total=len(active)),
        connections=page,
    )
    logger.info(
        "Returning %d of %d active connection(s) via API", payload.count, len(active)
    )
    return success_payload(
        "Active connections retrieved", payload.model_dump(mode="json")
    )


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
    return success_payload(
        "Idle connections expired",
        {
            "expired": expired,
            "active": tracker.get_active_count(),
            "historical": tracker.get_historical_count(),
        },
    )


@router.get("/{connection_id:path}", response_model=None)
def get_connection(
    connection_id: str,
    tracker: ConnectionTracker = Depends(get_connection_tracker),
) -> dict:
    """Return one tracked conversation, or ``404`` when the id is unknown.

    The id may contain ``|`` and ``:`` (it renders a 5-tuple), so the path is
    captured as a path segment rather than parsed as routing syntax.
    """
    view = tracker.get_connection_view(connection_id)
    if view is None:
        logger.info("Connection lookup failed for id %r", connection_id)
        raise NotFoundError(
            "Connection not found",
            code=ErrorCode.CONNECTION_NOT_FOUND,
            field="connection_id",
        )
    return success_payload("Connection retrieved", view.model_dump(mode="json"))
