"""Unit tests for the M14 event envelope and its serialization (M14.26).

M14.7 asks for "a common WebSocket event envelope" whose "event schemas must be
deterministic and versionable", and M14.17 asks that serialization be stable. Both
are properties of :mod:`app.websockets.event`, so they are tested there rather
than through a socket: a shape that a client can rely on is a shape that must be
asserted directly.

The file covers, in order:

* the envelope's field set, its order and its defaults;
* the closed event vocabulary, and the refusal of a name outside it;
* timestamps, which are ISO-8601 UTC with an offset on every event and at every
  conversion point;
* serialization — the JSON a client receives, its field order, a round trip, and
  the two facts that make a payload safe to send (it is JSON-shaped, and the model
  is frozen so an event cannot be edited after it is built);
* the packet projection, which is the one payload M14.8 defines field by field and
  the one place an accidental leak would matter;
* the sequence counter, which is what lets a client see a dropped event as a gap;
* the size cap, which is enforced by the manager rather than by the model and is
  therefore tested against a manager.

Nothing here needs a channel: an event's channel is part of its envelope, and the
tests that an event reaches only its own channel's subscribers live in
``test_ws_broadcast.py``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.websockets.channels import Channel
from app.websockets.event import (
    EVENT_ID_PREFIX,
    EVENT_TYPES,
    SCHEMA_VERSION,
    EventSource,
    EventType,
    WebSocketEvent,
    encoded,
    encoded_size,
    is_known_type,
    is_valid_payload,
    iso_utc,
    next_sequence,
    reset_sequence,
)
from tests.fakes import PACKET_BASE_TIME, make_normalized_packet
from tests.ws_fakes import (
    FakeSocket,
    asyncio_test,
    clean_websockets,  # noqa: F401 - fixture, imported for this module
    make_event,
    make_manager,
    make_policies,
    packet_event,
    queued_count,
    queued_types,
)

#: The envelope's fields, in the order a client receives them. Asserted as a
#: literal rather than read from the model, because the point of the test is that
#: the model has not changed: reading the expectation from the code under test
#: would make the assertion unfalsifiable.
DOCUMENTED_FIELDS = (
    "schema_version",
    "event_id",
    "type",
    "channel",
    "timestamp",
    "source",
    "sequence",
    "data",
)

#: The packet fields M14.8 names, plus the capture interface. Listed here for the
#: same reason: this is the contract, not a description of the implementation.
DOCUMENTED_PACKET_FIELDS = (
    "packet_id",
    "timestamp",
    "interface",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "length",
    "packet_type",
)
# ---------------------------------------------------------------------------
# The envelope's shape (M14.7)
# ---------------------------------------------------------------------------


def test_envelope_exposes_exactly_the_documented_fields() -> None:
    """The envelope is the documented set of fields and nothing else."""
    assert tuple(WebSocketEvent.model_fields) == DOCUMENTED_FIELDS


def test_serialization_emits_the_fields_in_the_documented_order() -> None:
    """A client can read the JSON positionally, so the order is part of the shape.

    ``model_dump_json`` follows declaration order, and declaring the order is what
    makes that reliable rather than incidental.
    """
    decoded = json.loads(encoded(make_event()))

    assert tuple(decoded) == DOCUMENTED_FIELDS


def test_schema_version_defaults_to_the_documented_version() -> None:
    """Every event carries the envelope version, so a client can refuse a shape."""
    assert SCHEMA_VERSION == 1
    assert make_event().schema_version == SCHEMA_VERSION


def test_event_id_is_prefixed_and_unique_per_event() -> None:
    """An id is opaque, recognisable in a log, and never reused."""
    ids = {make_event().event_id for _ in range(50)}

    assert len(ids) == 50
    assert all(event_id.startswith(EVENT_ID_PREFIX) for event_id in ids)


def test_sequence_defaults_to_zero_when_the_builder_did_not_stamp_it() -> None:
    """A hand-built event has a neutral sequence rather than a random one.

    The builders stamp the real sequence; the default exists so an event can be
    constructed from a literal in a test without reaching for the counter.
    """
    event = WebSocketEvent(
        type=EventType.PING, channel=Channel.SYSTEM, timestamp=iso_utc(0.0) or ""
    )

    assert event.sequence == 0


def test_data_defaults_to_an_empty_object() -> None:
    """A payload-less event sends ``{}`` rather than ``null``."""
    event = WebSocketEvent(
        type=EventType.PING, channel=Channel.SYSTEM, timestamp=iso_utc(0.0) or ""
    )

    assert event.data == {}
    assert json.loads(encoded(event))["data"] == {}


def test_source_defaults_to_the_system_source() -> None:
    """An event with no named producer is attributed to the system, not to ``None``."""
    event = WebSocketEvent(
        type=EventType.PING, channel=Channel.SYSTEM, timestamp=iso_utc(0.0) or ""
    )

    assert event.source == EventSource.SYSTEM


def test_the_envelope_is_frozen() -> None:
    """An event is a fact about something that already happened, so it cannot change.

    A consumer able to edit an event could publish a second, different fact under
    the same id — which is why the model is frozen rather than merely discouraged
    from being modified.
    """
    event = make_event()

    with pytest.raises(ValidationError):
        event.type = EventType.ALERT_CREATED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# The closed vocabulary (M14.7/M14.10/M14.11/M14.12)
# ---------------------------------------------------------------------------


def test_the_vocabulary_is_the_documented_closed_set() -> None:
    """Nineteen names, and a new one cannot be added without being declared known.

    ``EVENT_TYPES`` is derived from the constants, so this assertion is really
    "the published vocabulary has not silently grown": a twentieth event would
    have to be added here too.
    """
    assert len(EVENT_TYPES) == 19
    assert all(isinstance(name, str) and name for name in EVENT_TYPES)


@pytest.mark.parametrize("event_type", sorted(EVENT_TYPES))
def test_every_documented_type_is_accepted(event_type: str) -> None:
    """Each name in the vocabulary can be put on an event."""
    event = WebSocketEvent(
        type=event_type, channel=Channel.SYSTEM, timestamp=iso_utc(0.0) or ""
    )

    assert event.type == event_type
    assert is_known_type(event_type) is True


@pytest.mark.parametrize(
    "event_type",
    ["", "packet", "packet.observed.extra", "PACKET.OBSERVED", "alert.exploded"],
)
def test_a_type_outside_the_vocabulary_is_refused(event_type: str) -> None:
    """A name the milestone does not define cannot reach the wire.

    The check is a set membership rather than a prefix match, so ``packet.something``
    is refused as firmly as a name from an unrelated namespace.
    """
    with pytest.raises(ValidationError):
        WebSocketEvent(
            type=event_type, channel=Channel.SYSTEM, timestamp=iso_utc(0.0) or ""
        )


def test_alert_lifecycle_types_use_the_m11_status_vocabulary() -> None:
    """A lifecycle move names its own event, with no translation table invented.

    The four non-``open`` M11 statuses map to four event types, and ``open`` has
    none — it is where an alert starts and is announced by ``alert.created``.
    """
    from app.websockets.event import ALERT_STATUS_EVENT_TYPES

    assert set(ALERT_STATUS_EVENT_TYPES) == {
        "acknowledged",
        "resolved",
        "dismissed",
        "false_positive",
    }
    assert "open" not in ALERT_STATUS_EVENT_TYPES
    assert all(
        is_known_type(value) for value in ALERT_STATUS_EVENT_TYPES.values()
    )
# ---------------------------------------------------------------------------
# Timestamps (M14.17)
# ---------------------------------------------------------------------------


def test_an_event_timestamp_is_iso_8601_utc_with_an_offset() -> None:
    """A client parses one format, and never has to guess a timezone."""
    event = make_event()

    parsed = datetime.fromisoformat(event.timestamp)

    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)
    assert event.timestamp.endswith("+00:00")


def test_iso_utc_reads_epoch_seconds_as_utc() -> None:
    """The internal convention is epoch seconds; the boundary renders them as UTC."""
    assert iso_utc(PACKET_BASE_TIME) == "2023-11-14T22:13:20+00:00"


def test_iso_utc_accepts_an_integer_timestamp() -> None:
    """An integer epoch is as valid as a float, and renders identically."""
    assert iso_utc(1_700_000_000) == iso_utc(1_700_000_000.0)


def test_iso_utc_reads_a_naive_datetime_as_utc() -> None:
    """A naive value is UTC, because naive-UTC is what the alert rows round-trip."""
    naive = datetime(2026, 4, 10, 11, 17, 3)

    assert iso_utc(naive) == "2026-04-10T11:17:03+00:00"


def test_iso_utc_converts_an_aware_datetime_to_utc() -> None:
    """An aware value is converted rather than relabelled."""
    offset = timezone(timedelta(hours=5, minutes=30))
    aware = datetime(2026, 4, 10, 16, 47, 3, tzinfo=offset)

    assert iso_utc(aware) == "2026-04-10T11:17:03+00:00"


def test_iso_utc_keeps_microsecond_precision() -> None:
    """Two events inside the same second are still ordered by their timestamp."""
    assert iso_utc(1_700_000_000.412345) == "2023-11-14T22:13:20.412345+00:00"


def test_iso_utc_returns_none_for_none() -> None:
    """A missing time stays missing instead of becoming the epoch."""
    assert iso_utc(None) is None


def test_a_packet_event_timestamp_comes_from_the_packet() -> None:
    """The packet's own capture time is used, not the moment it was published."""
    event = packet_event()

    assert event.data["timestamp"] == iso_utc(PACKET_BASE_TIME)
    assert event.timestamp == iso_utc(PACKET_BASE_TIME)


# ---------------------------------------------------------------------------
# Serialization (M14.17)
# ---------------------------------------------------------------------------


def test_serialization_produces_compact_json() -> None:
    """The frame is one JSON object with no trailing whitespace or newline."""
    text = encoded(make_event())

    assert text.startswith("{") and text.endswith("}")
    assert "\n" not in text
    assert json.loads(text)["type"] == EventType.SERVICE_STATUS


def test_a_serialized_event_round_trips_through_the_model() -> None:
    """What a client receives can be rebuilt as the same event."""
    original = make_event(data={"service": "websockets", "state": "running"})

    rebuilt = WebSocketEvent.model_validate_json(encoded(original))

    assert rebuilt == original


def test_encoded_size_measures_utf8_bytes() -> None:
    """The cap is compared against bytes, which is what a socket write costs.

    A payload of multi-byte characters must therefore measure larger than its
    character count, or a client could be sent a frame over the configured limit.
    """
    event = make_event(data={"note": "é" * 50})

    assert encoded_size(event) == len(encoded(event).encode("utf-8"))
    assert encoded_size(event) > len(encoded(event))


def test_is_valid_payload_accepts_a_json_document() -> None:
    """A nested document of JSON scalars is a legal payload."""
    assert is_valid_payload(
        {"counts": {"packets": 12}, "names": ["a", "b"], "ratio": 0.5, "flag": True}
    )


def test_is_valid_payload_refuses_a_value_json_cannot_express() -> None:
    """A non-serializable value is detectable before it is published."""
    assert is_valid_payload({"session": object()}) is False


def test_a_payload_that_cannot_be_serialized_cannot_be_constructed() -> None:
    """The model validates the payload, so an unserializable event never exists.

    ``JsonDocument`` is a dictionary of ``object`` at the type level, and this is
    where the runtime check that matters happens: building the event, not sending
    it, is what refuses a value the wire could not carry.
    """
    with pytest.raises(ValidationError):
        WebSocketEvent(
            type=EventType.SERVICE_STATUS,
            channel=Channel.SYSTEM,
            timestamp=iso_utc(0.0) or "",
            data={"bad": object()},
        )
# ---------------------------------------------------------------------------
# The packet projection (M14.8)
# ---------------------------------------------------------------------------


def test_a_packet_event_carries_exactly_the_documented_fields() -> None:
    """The packet payload is the documented list, and its order is fixed."""
    assert tuple(packet_event().data) == DOCUMENTED_PACKET_FIELDS


@pytest.mark.parametrize(
    "forbidden", ["payload", "raw", "raw_bytes", "bytes", "packet_bytes", "metadata"]
)
def test_a_packet_event_carries_no_packet_payload(forbidden: str) -> None:
    """Nothing that could reconstruct a packet's contents reaches a client (M7.5).

    M14.8 and M7.5 both keep payload bytes out of the process's stored and
    published representations, so the assertion is on the absence of the field by
    every name it is likely to be reintroduced under.
    """
    assert forbidden not in packet_event().data


def test_a_packet_event_projects_the_normalized_packet() -> None:
    """Every field is projected from the packet the pipeline already produced."""
    from app.websockets.builders import packet_event as build_packet_event

    packet = make_normalized_packet(
        packet_id=42,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.9",
        source_port=51515,
        destination_port=8080,
        protocol="TCP",
        length=120,
    )

    event = build_packet_event(packet, timestamp=PACKET_BASE_TIME)

    assert event.data == {
        "packet_id": 42,
        "timestamp": iso_utc(PACKET_BASE_TIME),
        "interface": None,
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.9",
        "protocol": "TCP",
        "source_port": 51515,
        "destination_port": 8080,
        "length": 120,
        "packet_type": "TCP",
    }
    assert event.channel is Channel.PACKETS
    assert event.source == EventSource.PACKETS
    assert event.type == EventType.PACKET_OBSERVED


def test_a_packet_event_carries_the_capture_interface() -> None:
    """The interface a packet arrived on is the one M14.8 adds to the list."""
    from app.websockets.builders import packet_event as build_packet_event

    event = build_packet_event(make_normalized_packet(interface="Ethernet"))

    assert event.data["interface"] == "Ethernet"


def test_a_packet_event_keeps_a_missing_port_missing() -> None:
    """A protocol with no ports reports ``None`` rather than inventing a zero."""
    from app.schemas.packet import PacketType
    from app.websockets.builders import packet_event as build_packet_event

    packet = make_normalized_packet(
        source_port=None,
        destination_port=None,
        protocol="ICMP",
        packet_type=PacketType.ICMP,
    )

    data = build_packet_event(packet).data

    assert data["source_port"] is None
    assert data["destination_port"] is None
    assert data["packet_type"] == "ICMP"


# ---------------------------------------------------------------------------
# The sequence counter (M14.7)
# ---------------------------------------------------------------------------


def test_sequence_numbers_increase_across_events() -> None:
    """A client can see a dropped event as a gap rather than as silence."""
    sequences = [make_event().sequence for _ in range(5)]

    assert sequences == sorted(sequences)
    assert len(set(sequences)) == 5


def test_each_built_event_takes_the_next_sequence_number() -> None:
    """The counter is shared by the builders, so numbering is process-wide."""
    reset_sequence()

    assert make_event().sequence == 1
    assert make_event().sequence == 2


def test_reset_sequence_restarts_numbering() -> None:
    """The counter is resettable, which is what lets a test assert exact numbers."""
    make_event()
    make_event()

    reset_sequence()

    assert make_event().sequence == 1


def test_a_packet_event_reports_a_sequence_from_the_shared_counter() -> None:
    """A packet event is numbered like every other event, not separately."""
    reset_sequence()

    assert packet_event().sequence == 1


def test_next_sequence_is_monotonic_under_concurrent_callers() -> None:
    """The counter is guarded, because events are built on more than one thread.

    The capture worker and the API's thread pool both build events, so a counter
    without a lock could hand the same number to two of them.
    """
    from concurrent.futures import ThreadPoolExecutor

    reset_sequence()
    with ThreadPoolExecutor(max_workers=8) as pool:
        numbers = list(pool.map(lambda _: next_sequence(), range(200)))

    assert sorted(numbers) == list(range(1, 201))
# ---------------------------------------------------------------------------
# The event-size cap (M14.22/M14.26)
# ---------------------------------------------------------------------------


@asyncio_test
async def test_an_event_over_the_size_cap_is_refused_and_never_queued() -> None:
    """An oversized frame is a denial of service, so it is dropped before it is sent.

    The cap is measured on the encoded UTF-8 bytes, which is what a socket write
    costs — not on the payload's character count.
    """
    manager = make_manager(
        max_event_bytes=64, policies=make_policies(packet_rate=None)
    )
    connection = await manager.connect(FakeSocket(), Channel.PACKETS)
    try:
        oversized = packet_event()
        assert encoded_size(oversized) > manager.max_event_bytes

        assert manager.broadcast(oversized) == 0
        assert queued_count(connection) == 0
        assert manager.get_counters()["rejected_oversized"] == 1
    finally:
        await manager.disconnect(connection.client_id)


@asyncio_test
async def test_an_event_within_the_size_cap_is_queued() -> None:
    """The cap refuses only what exceeds it: a normal event passes untouched."""
    manager = make_manager(
        max_event_bytes=4096, policies=make_policies(packet_rate=None)
    )
    connection = await manager.connect(FakeSocket(), Channel.PACKETS)
    try:
        assert manager.broadcast(packet_event()) == 1

        assert queued_types(connection) == [EventType.PACKET_OBSERVED]
        assert manager.get_counters()["rejected_oversized"] == 0
    finally:
        await manager.disconnect(connection.client_id)


@asyncio_test
async def test_a_directed_send_over_the_size_cap_is_refused() -> None:
    """A keepalive or a refusal is measured by the same cap as a broadcast.

    ``send`` is the directed path, and a cap that applied to only one of the two
    would leave the other as a way to put an oversized frame on a socket.
    """
    manager = make_manager(
        max_event_bytes=64, policies=make_policies(packet_rate=None)
    )
    connection = await manager.connect(FakeSocket(), Channel.PACKETS)
    try:
        assert manager.send(connection.client_id, packet_event()) is False
        assert queued_count(connection) == 0
        assert manager.get_counters()["rejected_oversized"] == 1
    finally:
        await manager.disconnect(connection.client_id)


@asyncio_test
async def test_the_size_cap_is_configurable_and_reported() -> None:
    """The effective cap is readable, so a measurement can be interpreted."""
    manager = make_manager(max_event_bytes=2048)

    assert manager.max_event_bytes == 2048
    assert manager.get_stats()["max_event_bytes"] == 2048
