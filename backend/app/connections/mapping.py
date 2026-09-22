"""``Connection`` → ``connections`` row mapping (M9.17).

This module is the single place that decides how a runtime
:class:`~app.connections.connection.Connection` becomes a row of the M2
``connections`` table. It performs **no I/O** — it only projects the aggregate
onto the column values a repository will write.

A connection is an *aggregation* of many packets, so one row per conversation is
written, never one row per packet: M7 already owns per-packet storage.

Field mapping (verified against ``docs/03_Database_Design.md`` §10):

    Connection.source_ip                 → connections.source_ip        (required)
    Connection.destination_ip            → connections.destination_ip   (required)
    Connection.source_port               → connections.source_port      (nullable)
    Connection.destination_port          → connections.destination_port (nullable)
    Connection.protocol                  → connections.protocol         (required)
    Connection.source_packet_count       → connections.packets_sent
    Connection.destination_packet_count  → connections.packets_received
    Connection.source_byte_count         → connections.bytes_sent
    Connection.destination_byte_count    → connections.bytes_received
    Connection.first_seen                → connections.start_time       (required)
    Connection.last_seen                 → connections.end_time         (when ended)
    Connection.persisted_status()        → connections.status

Deliberate decisions
--------------------

**Skipped connections.** ``start_time`` and both address columns are
``NOT NULL``, and a record that was never observed has no ``first_seen``. Such a
record is **not persisted** — we never invent a timestamp.

**Direction.** The M2 column names are ``packets_sent`` / ``packets_received``,
which match the conversation's recorded orientation exactly: *sent* is the
direction of the peer that spoke first, *received* is the reverse. The totals are
therefore preserved without adding a column.

**Device linkage.** ``source_device_id`` / ``destination_device_id`` are integer
foreign keys to ``devices.id``, while M8 device identities are strings and M8
devices are **not** persisted (M7 likewise stores ``packets.device_id`` as
``NULL``). Unless a caller injects a resolver that maps a runtime device id to a
persisted row id, both stay ``NULL`` rather than being guessed at.

**Not persisted.** Per-packet flags, the canonical key text (reconstructible from
the columns) and the runtime state name (folded into ``status``). No column is
added to the M2 schema.

**Timestamps.** Stored as timezone-aware UTC ``datetime`` values, matching the
convention used by the M2 models and M7's packet mapping.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.connections.connection import Connection

# ``connections.protocol`` is declared ``String(20)``; keep values inside it.
_MAX_PROTOCOL_LENGTH = 20

# Value used when a connection carries no usable protocol label.
_DEFAULT_PROTOCOL = "OTHER"


def to_utc_datetime(timestamp: float) -> datetime:
    """Convert epoch seconds into a timezone-aware UTC ``datetime``.

    Identical in effect to M7's ``to_epoch_datetime``; defined here so the
    connection layer does not have to import the packet layer to store a time.
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def is_persistable(connection: Connection) -> bool:
    """Return True when ``connection`` can be stored without inventing values.

    Only a record with at least one observation has a defensible ``start_time``.
    """
    return connection.first_seen > 0.0


def protocol_label(connection: Connection) -> str:
    """Return the value to store in ``connections.protocol``."""
    label = (connection.protocol or _DEFAULT_PROTOCOL).strip() or _DEFAULT_PROTOCOL
    return label[:_MAX_PROTOCOL_LENGTH]


def is_ended(connection: Connection) -> bool:
    """Return True when the conversation is over, cleanly or by timeout.

    A conversation that ended has a real ``end_time``; one still in progress does
    not, so the row honestly shows an open session rather than a fabricated
    finish line.
    """
    return connection.is_terminal or connection.is_expired


def to_connection_values(
    connection: Connection,
    *,
    source_device_row_id: int | None = None,
    destination_device_row_id: int | None = None,
) -> dict[str, object] | None:
    """Map one runtime connection onto ``connections`` column values.

    Args:
        connection: A tracked conversation from the M9 registry.
        source_device_row_id: ``devices.id`` of the source, when a caller can
            resolve it. ``None`` leaves the foreign key empty.
        destination_device_row_id: ``devices.id`` of the destination.

    Returns:
        A mapping of column name to value ready for
        :class:`~app.models.connection.NetworkConnection`, or ``None`` when the
        record cannot be stored without inventing data. A ``None`` result must be
        counted as *skipped*, never retried in a loop.
    """
    if not is_persistable(connection):
        return None

    return {
        "source_device_id": source_device_row_id,
        "destination_device_id": destination_device_row_id,
        "source_ip": connection.source_ip,
        "destination_ip": connection.destination_ip,
        "source_port": connection.source_port,
        "destination_port": connection.destination_port,
        "protocol": protocol_label(connection),
        "packets_sent": connection.source_packet_count,
        "packets_received": connection.destination_packet_count,
        "bytes_sent": connection.source_byte_count,
        "bytes_received": connection.destination_byte_count,
        "start_time": to_utc_datetime(connection.first_seen),
        "end_time": (
            to_utc_datetime(connection.last_seen) if is_ended(connection) else None
        ),
        "status": connection.persisted_status(),
    }
