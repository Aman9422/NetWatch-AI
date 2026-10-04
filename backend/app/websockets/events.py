"""Publish helpers: build one event and hand it over, contained (M14.13/M14.14).

Every service that publishes does the same three things: build the event for a
signal, hand it to the publisher, and ensure that a failure in either step cannot
reach the caller. These functions are that sequence written once per signal, so a
service imports one function and cannot get the containment wrong.

The contract every helper keeps:

* the **publisher comes first**, so a call site cannot forget it;
* each returns whether the event was accepted — ``False`` when there is no
  publisher, the channel is disabled, the event was too large, or the projection
  failed;
* none of them ever raises, for any input, including an object of the wrong
  shape. A ``TypeError`` from a projection must not travel back up the capture
  thread (M14.14), and a projection is the one place a stale attribute could
  raise it.

The helpers are deliberately thin: they build, they hand over, they contain.
Anything that decided *what* an event means would belong in
:mod:`app.websockets.builders`, and anything that decided *whether* to send it
belongs in the manager.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.websockets import builders
from app.websockets.event import EventType, WebSocketEvent
from app.websockets.publisher import EventPublisher

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module import-light
    from app.alerts.alert import Alert
    from app.correlation.incident import CorrelatedIncident
    from app.correlation.registry import CorrelationOutcome
    from app.schemas.capture import CaptureStatusData
    from app.schemas.packet import NormalizedPacket

logger = logging.getLogger(__name__)


def _hand_over(publisher: EventPublisher, event: WebSocketEvent) -> bool:
    """Hand one built event to the publisher, containing a failure (M14.14)."""
    try:
        return bool(publisher.publish(event))
    except Exception:  # noqa: BLE001 - publishing must never raise (M14.14)
        logger.debug(
            "A %s event could not be published; the caller continues",
            event.type,
            exc_info=True,
        )
        return False


def _build_and_publish(
    publisher: EventPublisher, name: str, build: "object"
) -> bool:
    """Build one event, then publish it, containing either failure (M14.14).

    ``build`` is a zero-argument callable. It is passed as an argument rather than
    written inline at each call site so the two ``try`` blocks — one for the
    projection, one for the publish — exist exactly once.
    """
    try:
        event = build()  # type: ignore[operator]
    except Exception:  # noqa: BLE001 - a projection must never raise (M14.14)
        logger.debug(
            "A %s event could not be built; the caller continues",
            name,
            exc_info=True,
        )
        return False
    return _hand_over(publisher, event)


# -- packets (M14.8) ---------------------------------------------------------


def publish_packet(publisher: EventPublisher, packet: "NormalizedPacket") -> bool:
    """Publish one normalized packet (M14.8)."""
    return _build_and_publish(
        publisher, EventType.PACKET_OBSERVED, lambda: builders.packet_event(packet)
    )


# -- alerts (M14.10) ---------------------------------------------------------


def publish_alert(publisher: EventPublisher, alert: "Alert", *, created: bool) -> bool:
    """Publish an alert's creation, or the fold that updated it (M14.10).

    ``created`` distinguishes the two cases the alert service reports in its
    outcome: a new alert is ``alert.created``, a repeated observation folded into
    an existing one is ``alert.updated``. They are different facts for a client —
    one is a new row, the other is a row whose evidence count moved — so they are
    different event types rather than one type with a flag.
    """
    return _build_and_publish(
        publisher,
        EventType.ALERT_CREATED if created else EventType.ALERT_UPDATED,
        lambda: builders.alert_event(
            alert,
            event_type=EventType.ALERT_CREATED if created else EventType.ALERT_UPDATED,
        ),
    )


def publish_alert_lifecycle(publisher: EventPublisher, alert: "Alert") -> bool:
    """Publish an alert's lifecycle move (M14.10).

    Returns False — without publishing anything — for the ``open`` state, which is
    where an alert starts and which has no lifecycle event of its own. Inventing
    ``alert.opened`` here would put a name on the wire that the milestone does not
    define.
    """
    try:
        event = builders.alert_lifecycle_event(alert)
    except Exception:  # noqa: BLE001 - a projection must never raise (M14.14)
        logger.debug("A lifecycle event could not be built", exc_info=True)
        return False
    if event is None:
        return False
    return _hand_over(publisher, event)


# -- incidents (M14.12) ------------------------------------------------------


def publish_correlation_outcome(
    publisher: EventPublisher, outcome: "CorrelationOutcome"
) -> bool:
    """Publish an incident's creation or the event that joined it (M14.12).

    Reads the flags M12 already reports rather than comparing incidents: an
    outcome that opened an incident is ``incident.created``, one that folded into
    an existing incident is ``incident.updated``, and a duplicate — an event M12
    had already ingested and deduplicated (M12.11) — publishes nothing at all,
    because nothing changed.
    """
    event_type = (
        EventType.INCIDENT_CREATED
        if outcome.created
        else EventType.INCIDENT_UPDATED
        if outcome.joined
        else None
    )
    incident = outcome.incident
    if event_type is None or incident is None:
        return False
    return _build_and_publish(
        publisher,
        event_type,
        lambda: builders.incident_event(incident, event_type=event_type),
    )


def publish_incident_status(
    publisher: EventPublisher, incident: "CorrelatedIncident"
) -> bool:
    """Publish an incident lifecycle move (M14.12)."""
    return _build_and_publish(
        publisher,
        EventType.INCIDENT_STATUS_CHANGED,
        lambda: builders.incident_event(
            incident, event_type=EventType.INCIDENT_STATUS_CHANGED
        ),
    )


# -- system (M14.11) ---------------------------------------------------------


def publish_capture(
    publisher: EventPublisher,
    event_type: str,
    status: "CaptureStatusData",
    *,
    reason: str | None = None,
) -> bool:
    """Publish a capture state change (M14.11).

    ``reason`` is only used by ``capture.error`` and is supplied by the capture
    layer as a fixed sentence: the exception's own text can name a device or a
    path and never reaches the wire (M14.22).
    """
    return _build_and_publish(
        publisher,
        event_type,
        lambda: builders.capture_event(event_type, status, reason=reason),
    )


def publish_service(publisher: EventPublisher, service: str, state: str) -> bool:
    """Publish a service state change (M14.11)."""
    return _build_and_publish(
        publisher,
        EventType.SERVICE_STATUS,
        lambda: builders.service_event(service, state),
    )


def publish_database(
    publisher: EventPublisher, *, dialect: str, reachable: bool
) -> bool:
    """Publish a database probe result (M14.11)."""
    return _build_and_publish(
        publisher,
        EventType.DATABASE_STATUS,
        lambda: builders.database_event(dialect=dialect, reachable=reachable),
    )


__all__ = [
    "publish_alert",
    "publish_alert_lifecycle",
    "publish_capture",
    "publish_correlation_outcome",
    "publish_database",
    "publish_incident_status",
    "publish_packet",
    "publish_service",
]
