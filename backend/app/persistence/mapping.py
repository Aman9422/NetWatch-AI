"""NormalizedPacket → ``packets`` row mapping (M7.2).

This module is the single place that decides how an M5
:class:`~app.schemas.packet.NormalizedPacket` becomes a row of the M2
``packets`` table. It performs **no I/O** — it only projects a packet onto the
column values the repository will insert.

Field mapping (verified against ``docs/03_Database_Design.md`` §9):

    NormalizedPacket.timestamp        → packets.timestamp        (required)
    NormalizedPacket.source_ip        → packets.source_ip        (required)
    NormalizedPacket.destination_ip   → packets.destination_ip   (required)
    NormalizedPacket.source_port      → packets.source_port      (nullable)
    NormalizedPacket.destination_port → packets.destination_port (nullable)
    NormalizedPacket.packet_type      → packets.protocol         (required)
    NormalizedPacket.length           → packets.packet_length    (required)
    NormalizedPacket.tcp_flags        → packets.tcp_flags        (nullable)
    —                                 → packets.ttl              (always NULL)
    —                                 → packets.payload_length   (always NULL)
    —                                 → packets.device_id        (always NULL)
    —                                 → packets.processed        (always 0)

Deliberate decisions
--------------------

**Protocol label.** ``packets.protocol`` is filled from the M5 *classification*
(``packet_type``: ``TCP``/``UDP``/``ICMP``/``DNS``/``ARP``/``IPV4``/``IPV6``/
``OTHER``). Its transport twin (``packet.protocol``) is strictly less
informative — it cannot represent DNS — and the classification is also what the
M6 statistics engine reports, so persisting it keeps the two modules saying the
same thing about a packet.

**Skipped packets.** ``packets.source_ip`` and ``packets.destination_ip`` are
``NOT NULL``, but a normalized packet may carry no IP (ARP, and any non-IP
frame). Such a packet is **not persisted** and is counted as *skipped*; we never
invent an address (M7.2, M7.4). This is the only reason a normalized packet is
rejected.

**Not persisted.** The M2 schema has no column for the capture interface, the
MAC addresses, the IP version, the raw ``packet_type`` alongside ``protocol``,
or the session ``packet_id``. Those values are dropped rather than stored in an
unsuitable column. Adding columns would change the shipped schema (M7.1: stay
consistent with the existing database architecture), so it is left to a later
milestone together with the frontend-facing packet API (M13).

**Payload policy (M7.5).** Full payloads are never stored. ``payload_length``
belongs to a future version and stays ``NULL`` in V1.

**Timestamp.** Capture time is stored as a timezone-aware UTC ``datetime``,
matching the ``utcnow()`` convention already used by the M2 models.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.schemas.packet import NormalizedPacket, PacketType

# Value used when a packet carries no usable classification.
_DEFAULT_PROTOCOL = "OTHER"

# ``packets.protocol`` is declared ``String(20)``; keep values inside it.
_MAX_PROTOCOL_LENGTH = 20


def is_persistable(packet: NormalizedPacket) -> bool:
    """Return True when ``packet`` can be stored without inventing values.

    Only packets that carry both endpoints can satisfy the ``NOT NULL`` address
    columns of the ``packets`` table.
    """
    return packet.source_ip is not None and packet.destination_ip is not None


def to_epoch_datetime(timestamp: float) -> datetime:
    """Convert epoch seconds into a timezone-aware UTC ``datetime``."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def protocol_label(packet: NormalizedPacket) -> str:
    """Return the value to store in ``packets.protocol``.

    A *specific* M5 classification (``TCP``/``UDP``/``ICMP``/``DNS``/``ARP``/
    ``IPV4``/``IPV6``) is the most informative label and is preferred, because
    it can express DNS where the raw transport string cannot. When the
    classification is ``OTHER`` — the normalizer could not name the packet — the
    transport ``protocol`` string is used instead, since it may still carry a
    usable label (for example ``"QUIC"``). Only when both are empty or ``OTHER``
    does the value fall back to ``"OTHER"``. The result is always truncated to
    the column width.
    """
    packet_type = packet.packet_type
    if isinstance(packet_type, PacketType) and packet_type is not PacketType.OTHER:
        label = packet_type.value
    else:  # consider the transport label before giving up
        label = packet.protocol or _DEFAULT_PROTOCOL
    label = (label or _DEFAULT_PROTOCOL).strip() or _DEFAULT_PROTOCOL
    return label[:_MAX_PROTOCOL_LENGTH]


def to_packet_values(packet: NormalizedPacket) -> dict[str, object] | None:
    """Map one normalized packet onto ``packets`` column values.

    Args:
        packet: A normalized packet produced by the M5 ``PacketProcessor``.

    Returns:
        A mapping of column name to value ready for
        :class:`~app.models.packet.Packet`, or ``None`` when the packet cannot
        be stored without inventing data (see the module docstring). A ``None``
        result must be counted as a *skipped* packet, never re-queued.
    """
    if not is_persistable(packet):
        return None

    return {
        "timestamp": to_epoch_datetime(packet.timestamp),
        "source_ip": packet.source_ip,
        "destination_ip": packet.destination_ip,
        "source_port": packet.source_port,
        "destination_port": packet.destination_port,
        "protocol": protocol_label(packet),
        "packet_length": max(int(packet.length), 0),
        "tcp_flags": packet.tcp_flags,
        # Default NULLs: payload is never stored (M7.5) and TTL is not yet
        # extracted by M5, so both stay empty rather than being invented.
        "ttl": None,
        "payload_length": None,
        # Device linkage (M8 devices are not persisted) and downstream
        # processing belong to later milestones.
        "device_id": None,
        "processed": 0,
    }
