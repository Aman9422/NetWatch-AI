"""The one WebSocket event envelope (M14.7).

Every message M14 sends, on every channel, is a :class:`WebSocketEvent`. One
envelope rather than one shape per channel is what makes a client's decoder a
single function, and it is what M14.7 asks for: "Define a common WebSocket event
envelope... Event schemas must be deterministic and versionable."

Three properties the model enforces by construction:

* **The type is from a closed set.** :class:`EventType` holds every name, and
  :data:`EVENT_TYPES` is the set membership is checked against, so a publish site
  cannot invent a type by concatenating strings.
* **The timestamp is ISO-8601 UTC with an offset** (M14.17). Internally M10–M12
  time things in epoch seconds and the M2 alert rows hold naive UTC datetimes;
  :func:`iso_utc` is the single conversion at the boundary, so no two events can
  disagree about what a timestamp looks like.
* **The payload is JSON-shaped.** :data:`JsonDocument` is a dictionary at the type
  level, so the model *validates* the payload against :func:`json.dumps` and
  refuses an event whose payload has no JSON representation. A bad value is
  therefore rejected where it was produced rather than at the socket, which is
  what stops an ORM row, a session or an arbitrary object from reaching the wire
  by accident.

Size is a *transport* concern, not a model one: :func:`encoded` returns the exact
bytes a client would receive, and the manager measures it against the configured
cap before queueing (M14.22).
"""

from __future__ import annotations

import itertools
import json
import threading
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.websockets.channels import Channel

#: Envelope version. Bumped only by a breaking change to the envelope itself, so
#: a client can refuse a shape it does not understand rather than misread it.
SCHEMA_VERSION = 1

#: Prefix on every generated event id, so an id is recognisable in a log line.
EVENT_ID_PREFIX = "evt-"

#: The JSON value a payload field may hold. ``object`` is all a Python annotation
#: can say here — it admits anything — so the JSON contract is enforced at runtime
#: by :meth:`WebSocketEvent._serializable_data` rather than claimed by the type.
JsonValue = object
JsonDocument = dict[str, JsonValue]


class EventType:
    """Every event name M14 can emit (M14.7/M14.10/M14.11/M14.12).

    A plain class of string constants rather than an ``Enum``: the value is what
    travels on the wire, and an enum would invite a caller to send
    ``EventType.PACKET_OBSERVED.value`` inconsistently with sending the constant
    itself. The set is closed — :func:`is_known_type` is the membership test the
    model applies.
    """

    # packets (M14.8)
    PACKET_OBSERVED = "packet.observed"

    # dashboard (M14.9)
    DASHBOARD_UPDATED = "dashboard.updated"

    # alerts (M14.10)
    ALERT_CREATED = "alert.created"
    ALERT_UPDATED = "alert.updated"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_DISMISSED = "alert.dismissed"
    ALERT_FALSE_POSITIVE = "alert.false_positive"

    # incidents (M14.12), carried on the alerts channel
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_STATUS_CHANGED = "incident.status_changed"

    # system (M14.11)
    CAPTURE_STARTED = "capture.started"
    CAPTURE_STOPPED = "capture.stopped"
    CAPTURE_ERROR = "capture.error"
    DATABASE_STATUS = "database.status"
    SERVICE_STATUS = "service.status"

    # keepalive and refusals (M14.23/M14.24)
    PING = "ping"
    PONG = "pong"
    ERROR = "error"


#: Lifecycle event type per M11 alert status value (M14.10). A status the client
#: can be moved to names its own event, so no translation table is invented here.
ALERT_STATUS_EVENT_TYPES: dict[str, str] = {
    "acknowledged": EventType.ALERT_ACKNOWLEDGED,
    "resolved": EventType.ALERT_RESOLVED,
    "dismissed": EventType.ALERT_DISMISSED,
    "false_positive": EventType.ALERT_FALSE_POSITIVE,
}

#: The closed set of event names. Every constant above is collected here so a new
#: one cannot be added without also being declared known to the model.
EVENT_TYPES: frozenset[str] = frozenset(
    value
    for name, value in vars(EventType).items()
    if not name.startswith("_") and isinstance(value, str)
)


class EventSource:
    """Which service produced an event, for client-side diagnostics (M14.7)."""

    PACKETS = "pipeline.packets"
    ALERTS = "alerts.engine"
    CORRELATION = "correlation.engine"
    CAPTURE = "capture.manager"
    DASHBOARD = "dashboard"
    SYSTEM = "system"


def is_known_type(event_type: str) -> bool:
    """Return True when ``event_type`` is one of the documented names."""
    return str(event_type) in EVENT_TYPES


def new_event_id() -> str:
    """Return a unique, opaque event identifier."""
    return f"{EVENT_ID_PREFIX}{uuid.uuid4().hex}"


def iso_utc(value: float | datetime | None) -> str | None:
    """Render epoch seconds or a datetime as ISO-8601 UTC, or ``None``.

    Epoch seconds are read as UTC, and a naive datetime is likewise read as UTC,
    because naive-UTC is what the database round-trips and what M11/M12 already
    write (see :mod:`app.alerts.timestamps`). The result always carries an offset,
    which is the part a client needs and the part a naive ``isoformat()`` would
    omit.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(
            tzinfo=timezone.utc
        )
        return moment.astimezone(timezone.utc).isoformat()
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


# -- sequence ----------------------------------------------------------------

_sequence_lock = threading.Lock()
_sequence_counter = itertools.count(1)


def next_sequence() -> int:
    """Return the next process-wide event sequence number.

    One counter for the process, shared by all channels: a client watching two
    channels can then interleave them by sequence and see a gap as a gap. The
    counter is guarded because events are built on the capture thread and on the
    API's thread pool.
    """
    with _sequence_lock:
        return next(_sequence_counter)


def reset_sequence() -> None:
    """Restart the sequence at 1. For tests that assert exact numbering."""
    global _sequence_counter
    with _sequence_lock:
        _sequence_counter = itertools.count(1)


class WebSocketEvent(BaseModel):
    """One message on one channel (M14.7).

    Frozen, because an event is a fact about something that already happened: a
    consumer that could edit it could publish a second, different fact under the
    same id.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int = Field(
        default=SCHEMA_VERSION, description="Envelope version, currently 1"
    )
    event_id: str = Field(
        default_factory=new_event_id, description="Unique event identifier"
    )
    type: str = Field(description="One of the documented event names")
    channel: Channel = Field(description="Channel this event belongs to")
    timestamp: str = Field(description="ISO-8601 UTC, always with an offset")
    source: str = Field(default=EventSource.SYSTEM, description="Producing service")
    sequence: int = Field(
        default=0, description="Process-wide monotonic sequence number"
    )
    data: JsonDocument = Field(
        default_factory=dict, description="Channel-specific payload"
    )

    @field_validator("type")
    @classmethod
    def _known_type(cls, value: str) -> str:
        """Refuse an event type outside the documented vocabulary."""
        if not is_known_type(value):
            raise ValueError(f"unknown event type: {value!r}")
        return value

    @field_validator("data")
    @classmethod
    def _serializable_data(cls, value: JsonDocument) -> JsonDocument:
        """Refuse a payload that could not survive the wire (M14.14/M14.17).

        The annotation is a dictionary, not a JSON type: ``object`` admits
        anything, so without this check an ORM row, a session or an arbitrary
        object could be attached to an event and would only fail later, inside
        ``model_dump_json`` — on the dispatch path, where M14.14 requires that
        nothing raises. Refusing at construction moves the failure back to the
        caller that produced the bad value, which is the only place it can be
        fixed, and makes "a malformed event cannot be constructed" true rather
        than aspirational.

        ``json.dumps`` is the same check the wire performs, so the model and the
        socket cannot disagree about what is sendable.
        """
        if not is_valid_payload(value):
            raise ValueError("event data must be JSON-serializable")
        return value

    def model_dump_json_safe(self) -> str:
        """Return this event as compact JSON text.

        ``model_dump_json`` is enough for the envelope, and this wrapper exists to
        give the manager one call site for encoding. The payload was validated as
        JSON-shaped when the event was constructed, so no custom encoder is needed.
        """
        return self.model_dump_json()


def encoded(event: WebSocketEvent) -> str:
    """Return the exact text a client receives for ``event``."""
    return event.model_dump_json_safe()


def encoded_size(event: WebSocketEvent) -> int:
    """Return the byte length of the encoded event.

    Measured as UTF-8 bytes, which is what a socket write costs and therefore what
    the configured event-size cap has to be compared against.
    """
    return len(encoded(event).encode("utf-8"))


def is_valid_payload(payload: JsonDocument) -> bool:
    """Return True when ``payload`` survives a JSON round trip.

    Used by the tests and available to any caller that builds a payload from
    outside a builder: a value that cannot be serialized must be caught before it
    reaches a socket, not by the socket at send time.
    """
    try:
        json.dumps(payload)
    except (TypeError, ValueError):
        return False
    return True


__all__ = [
    "ALERT_STATUS_EVENT_TYPES",
    "EVENT_ID_PREFIX",
    "EVENT_TYPES",
    "SCHEMA_VERSION",
    "EventSource",
    "EventType",
    "JsonDocument",
    "JsonValue",
    "WebSocketEvent",
    "encoded",
    "encoded_size",
    "is_known_type",
    "is_valid_payload",
    "iso_utc",
    "new_event_id",
    "next_sequence",
    "reset_sequence",
]
