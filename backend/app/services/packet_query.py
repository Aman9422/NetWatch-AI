"""Read-only packet query service (M7.15).

This is the service layer over *stored* packets. It turns the query rules into
repository calls and projects each ORM row onto the wire shape the API returns,
so the endpoints stay thin and every filter is defined in exactly one place.

Two deliberate properties:

* It is strictly a **query** service — it reads, never writes, and contains no
  detection, scoring or correlation logic. Packet metadata exists here so that
  later milestones can investigate it; understanding it is their job.
* It is **stateless** and holds no session of its own: the caller supplies a
  session (a request-scoped one from ``get_db``, or an isolated one in tests),
  which is what makes the service trivially testable against a temporary
  database.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.models.packet import Packet
from app.repositories.packet import PacketRepository
from app.schemas.packet_query import PacketView

# Page size used when the caller does not ask for one.
DEFAULT_PACKET_LIMIT = 100

# Largest page the service will serve. It exists so a single request cannot ask
# SQLite to materialise the whole table, which would be a denial-of-service on a
# busy capture (M7.15).
MAX_PACKET_LIMIT = 1000

# Directions understood by :meth:`PacketQueryService.by_port`.
_PORT_DIRECTIONS = ("source", "destination")


def to_packet_view(packet: Packet) -> PacketView:
    """Project a stored packet row onto its read-only wire shape.

    The timestamp is rendered as ISO-8601. SQLite returns the naive datetime
    that was stored, which is UTC by construction (see
    :func:`app.persistence.mapping.to_epoch_datetime`), so the value is exposed
    exactly as captured rather than reinterpreted as local time.
    """
    return PacketView(
        id=packet.id,
        timestamp=packet.timestamp.isoformat(),
        source_ip=packet.source_ip,
        destination_ip=packet.destination_ip,
        source_port=packet.source_port,
        destination_port=packet.destination_port,
        protocol=packet.protocol,
        packet_length=packet.packet_length,
        tcp_flags=packet.tcp_flags,
    )


class PacketQueryService:
    """Read-only queries over persisted packet metadata (M7.15)."""

    def __init__(self, db: Session) -> None:
        self._repository = PacketRepository(db)

    # -- point lookup ------------------------------------------------------

    def get(self, packet_id: int) -> PacketView | None:
        """Return one stored packet, or ``None`` when the id is unknown."""
        packet = self._repository.get_by_id(packet_id)
        return to_packet_view(packet) if packet is not None else None

    # -- filtered queries --------------------------------------------------

    def list(
        self,
        *,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        protocol: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = DEFAULT_PACKET_LIMIT,
        offset: int = 0,
    ) -> list[PacketView]:
        """Return stored packets matching the filters, newest first.

        Raises:
            ValueError: If ``limit`` is outside ``1..MAX_PACKET_LIMIT`` or
                ``offset`` is negative.
        """
        self._validate_limit(limit)
        if offset < 0:
            raise ValueError("offset must not be negative")
        packets = self._repository.list(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )
        return [to_packet_view(packet) for packet in packets]

    def count(
        self,
        *,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        protocol: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        """Count stored packets matching the same filters as :meth:`list`."""
        return self._repository.count(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            since=since,
            until=until,
        )

    # -- named queries (the shapes the roadmap asks for, M7.15) ------------

    def recent(self, limit: int = DEFAULT_PACKET_LIMIT) -> list[PacketView]:
        """Return the most recently captured packets."""
        return self.list(limit=limit)

    def by_source_ip(
        self, source_ip: str, limit: int = DEFAULT_PACKET_LIMIT
    ) -> list[PacketView]:
        """Return packets sent by one address."""
        return self.list(source_ip=source_ip, limit=limit)

    def by_destination_ip(
        self, destination_ip: str, limit: int = DEFAULT_PACKET_LIMIT
    ) -> list[PacketView]:
        """Return packets sent to one address."""
        return self.list(destination_ip=destination_ip, limit=limit)

    def by_protocol(
        self, protocol: str, limit: int = DEFAULT_PACKET_LIMIT
    ) -> list[PacketView]:
        """Return packets carrying one protocol label."""
        return self.list(protocol=protocol, limit=limit)

    def by_port(
        self,
        port: int,
        *,
        direction: str = "destination",
        limit: int = DEFAULT_PACKET_LIMIT,
    ) -> list[PacketView]:
        """Return packets involving one port, in the requested direction.

        Raises:
            ValueError: If ``direction`` is neither source nor destination.
        """
        self._validate_limit(limit)
        if direction not in _PORT_DIRECTIONS:
            raise ValueError(f"Unknown port direction: {direction}")
        packets = self._repository.get_by_port(
            port, direction=direction, limit=limit
        )
        return [to_packet_view(packet) for packet in packets]

    def between(
        self, start: datetime, end: datetime, limit: int = DEFAULT_PACKET_LIMIT
    ) -> list[PacketView]:
        """Return packets captured inside a time range."""
        return self.list(since=start, until=end, limit=limit)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _validate_limit(limit: int) -> None:
        """Reject page sizes outside the supported range.

        Raises:
            ValueError: If ``limit`` is below 1 or above ``MAX_PACKET_LIMIT``.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if limit > MAX_PACKET_LIMIT:
            raise ValueError(f"limit must not exceed {MAX_PACKET_LIMIT}")
