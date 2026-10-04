"""Event constructors: one function per event the application publishes (M14.7).

A builder exists so that no publish site has to remember three things at once —
which channel an event belongs on, which source produced it, and which payload
projection it takes. The mapping from signal to channel is fixed here and nowhere
else:

    packet  → packets     alert, incident → alerts
    dashboard → dashboard capture, service, database → system

Each builder stamps the sequence number and the ISO-8601 timestamp, so an event
cannot be created without them. ``timestamp`` is overridable so a test can pin an
event's time rather than race it.

This module may not import a service, a manager or a database module: publishing
has to stay cheap enough to sit on the capture path (M14.14).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from app.websockets.channels import Channel
from app.websockets.event import (
    ALERT_STATUS_EVENT_TYPES,
    EventSource,
    EventType,
    JsonDocument,
    WebSocketEvent,
    iso_utc,
    next_sequence,
)
from app.websockets import payloads

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module import-light
    from app.alerts.alert import Alert
    from app.correlation.incident import CorrelatedIncident
    from app.schemas.capture import CaptureStatusData
    from app.schemas.packet import NormalizedPacket


def _event(
    event_type: str,
    channel: Channel,
    source: str,
    data: JsonDocument,
    *,
    timestamp: float | None = None,
) -> WebSocketEvent:
    """Assemble one enveloped event, stamping time and sequence.

    The single construction point for the module: a builder cannot forget the
    sequence or hand in a timestamp in the wrong format, and an event type outside
    the closed set is refused by the model rather than by a caller's discipline.
    """
    if timestamp is None:
        timestamp = time.time()
    return WebSocketEvent(
        type=event_type,
        channel=channel,
        source=source,
        timestamp=iso_utc(timestamp) or iso_utc(time.time()) or "",
        sequence=next_sequence(),
        data=data,
    )


# -- packets (M14.8) ---------------------------------------------------------


def packet_event(
    packet: "NormalizedPacket", *, timestamp: float | None = None
) -> WebSocketEvent:
    """Build the event for one processed packet (M14.8)."""
    return _event(
        EventType.PACKET_OBSERVED,
        Channel.PACKETS,
        EventSource.PACKETS,
        payloads.packet_payload(packet),
        timestamp=timestamp,
    )


# -- dashboard (M14.9) -------------------------------------------------------


def dashboard_event(
    *,
    capture_running: bool,
    interface: str | None,
    packet_count: int,
    packets_per_second: float,
    bytes_per_second: float,
    device_count: int,
    active_connections: int,
    open_alerts: int,
    active_incidents: int,
    timestamp: float | None = None,
) -> WebSocketEvent:
    """Build one dashboard tick (M14.9)."""
    return _event(
        EventType.DASHBOARD_UPDATED,
        Channel.DASHBOARD,
        EventSource.DASHBOARD,
        payloads.dashboard_payload(
            capture_running=capture_running,
            interface=interface,
            packet_count=packet_count,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            device_count=device_count,
            active_connections=active_connections,
            open_alerts=open_alerts,
            active_incidents=active_incidents,
        ),
        timestamp=timestamp,
    )


# -- alerts and incidents (M14.10/M14.12) -----------------------------------


def alert_event(
    alert: "Alert",
    *,
    event_type: str = EventType.ALERT_CREATED,
    timestamp: float | None = None,
) -> WebSocketEvent:
    """Build an alert event of ``event_type`` (M14.10)."""
    return _event(
        event_type,
        Channel.ALERTS,
        EventSource.ALERTS,
        payloads.alert_payload(alert),
        timestamp=timestamp,
    )


def alert_lifecycle_event(
    alert: "Alert", *, timestamp: float | None = None
) -> WebSocketEvent | None:
    """Build the event for an alert's current lifecycle state (M14.10).

    Returns ``None`` for a state that has no lifecycle event — ``open`` is where an
    alert starts, and it is announced by ``alert.created`` rather than by a second
    event. Returning ``None`` rather than inventing ``alert.opened`` keeps the
    vocabulary equal to the set the milestone names.
    """
    event_type = ALERT_STATUS_EVENT_TYPES.get(str(alert.status.value))
    if event_type is None:
        return None
    return alert_event(alert, event_type=event_type, timestamp=timestamp)


def incident_event(
    incident: "CorrelatedIncident",
    *,
    event_type: str = EventType.INCIDENT_CREATED,
    timestamp: float | None = None,
) -> WebSocketEvent:
    """Build an incident event on the alerts channel (M14.12)."""
    return _event(
        event_type,
        Channel.ALERTS,
        EventSource.CORRELATION,
        payloads.incident_payload(incident),
        timestamp=timestamp,
    )


# -- system (M14.11) ---------------------------------------------------------


def capture_event(
    event_type: str,
    status: "CaptureStatusData",
    *,
    reason: str | None = None,
    timestamp: float | None = None,
) -> WebSocketEvent:
    """Build a capture state change (M14.11).

    ``event_type`` must be one of the three capture names; the model refuses
    anything else, so a caller cannot publish a capture event under an alert name.
    """
    return _event(
        event_type,
        Channel.SYSTEM,
        EventSource.CAPTURE,
        payloads.capture_payload(status, reason=reason),
        timestamp=timestamp,
    )


def service_event(
    service: str, state: str, *, detail: str | None = None
) -> WebSocketEvent:
    """Build a service state event (M14.11)."""
    return _event(
        EventType.SERVICE_STATUS,
        Channel.SYSTEM,
        EventSource.SYSTEM,
        payloads.service_payload(service, state, detail=detail),
    )


def database_event(*, dialect: str, reachable: bool) -> WebSocketEvent:
    """Build a database status event (M14.11)."""
    return _event(
        EventType.DATABASE_STATUS,
        Channel.SYSTEM,
        EventSource.SYSTEM,
        payloads.database_payload(dialect=dialect, reachable=reachable),
    )


# -- keepalive and refusals (M14.23/M14.24) ---------------------------------


def ping_event(channel: Channel, *, nonce: str | None = None) -> WebSocketEvent:
    """Build the server's keepalive (M14.24)."""
    return _event(
        EventType.PING, channel, EventSource.SYSTEM, payloads.keepalive_payload(nonce=nonce)
    )


def pong_event(channel: Channel, *, nonce: str | None = None) -> WebSocketEvent:
    """Build the answer to a client ping (M14.23)."""
    return _event(
        EventType.PONG, channel, EventSource.SYSTEM, payloads.keepalive_payload(nonce=nonce)
    )


def error_event(
    channel: Channel, reason: str, *, field: str = "message"
) -> WebSocketEvent:
    """Build the refusal of a client message (M14.23)."""
    return _event(
        EventType.ERROR,
        channel,
        EventSource.SYSTEM,
        payloads.refusal_payload(reason, field=field),
    )


__all__ = [
    "alert_event",
    "alert_lifecycle_event",
    "capture_event",
    "dashboard_event",
    "database_event",
    "error_event",
    "incident_event",
    "packet_event",
    "ping_event",
    "pong_event",
    "service_event",
]
