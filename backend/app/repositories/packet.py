"""Packet repository for NetWatch AI.

This repository owns every SQL statement that touches the ``packets`` table.
It deliberately separates *staging* from *committing* so the M7 persistence
layer can write a whole batch inside one transaction (M7.10):

* :meth:`add` / :meth:`add_many` stage rows **without** committing;
* :meth:`write_batch` stages and commits a batch, rolling back on failure;
* :meth:`delete_before` powers packet retention (M7.13);
* the read helpers return ORM ``Packet`` objects for the query service (M7.15).

Nothing here detects, scores or alters packets — it only stores and retrieves
them, which is the whole of M7's responsibility.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.packet import Packet
from app.repositories.base import BaseRepository


class PacketRepository(BaseRepository[Packet]):
    """Repository for persisting and querying packet metadata."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Packet)

    # -- writes (M7.3 / M7.10) -------------------------------------------

    def add(self, packet: Packet) -> Packet:
        """Stage a packet for insertion without committing it."""
        self.db.add(packet)
        return packet

    def add_many(self, packets: Iterable[Packet]) -> int:
        """Stage many packets without committing; return how many were staged."""
        rows = list(packets)
        if rows:
            self.db.add_all(rows)
        return len(rows)

    def write_batch(self, rows: Sequence[Mapping[str, object]]) -> int:
        """Insert a batch of already-mapped packet rows in one transaction.

        Args:
            rows: ``packets`` column values, as produced by
                :func:`app.persistence.mapping.to_packet_values`.

        Returns:
            The number of rows written.

        Raises:
            Exception: Whatever the database raised. The transaction has already
                been rolled back, so a failed batch never leaves the database
                partially written. The caller isolates and counts the failure
                (M7.11).
        """
        if not rows:
            return 0
        packets = [Packet(**dict(row)) for row in rows]
        try:
            self.db.add_all(packets)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return len(packets)

    def commit(self) -> None:
        """Commit the staged changes."""
        self.db.commit()

    def rollback(self) -> None:
        """Discard the staged changes."""
        self.db.rollback()

    def delete_before(self, cutoff: datetime) -> int:
        """Delete every packet captured strictly before ``cutoff`` (M7.13).

        Packets whose timestamp equals ``cutoff`` are kept, so a retention run
        can never delete a record that is exactly at the boundary.

        Returns:
            The number of deleted rows.
        """
        statement = delete(Packet).where(Packet.timestamp < cutoff)
        result = self.db.execute(statement)
        self.db.commit()
        return _affected_rows(result)

    # -- reads ------------------------------------------------------------

    def get_by_id(self, packet_id: int) -> Packet | None:
        """Return one packet by primary key, or ``None``."""
        return self.db.get(Packet, packet_id)

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
        limit: int = 100,
        offset: int = 0,
    ) -> list[Packet]:
        """Return packets matching the filters, newest first (M7.15).

        Raises:
            ValueError: If ``limit`` is below 1 or ``offset`` is negative.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if offset < 0:
            raise ValueError("offset must not be negative")
        statement = self._filtered(
            select(Packet),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            since=since,
            until=until,
        )
        statement = (
            statement.order_by(Packet.timestamp.desc(), Packet.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(statement).all())

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
        """Count packets matching the same filters as :meth:`list`."""
        statement = self._filtered(
            select(func.count()).select_from(Packet),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            since=since,
            until=until,
        )
        return int(self.db.scalar(statement) or 0)

    def get_by_device(self, device_id: int, *, limit: int = 100) -> list[Packet]:
        """Return packets observed from a given device."""
        stmt = (
            select(Packet)
            .where(Packet.device_id == device_id)
            .order_by(Packet.timestamp.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_source_ip(self, source_ip: str, *, limit: int = 100) -> list[Packet]:
        """Return packets with a given source IP."""
        return self.list(source_ip=source_ip, limit=limit)

    def get_by_destination_ip(
        self, destination_ip: str, *, limit: int = 100
    ) -> list[Packet]:
        """Return packets with a given destination IP."""
        return self.list(destination_ip=destination_ip, limit=limit)

    def get_by_protocol(self, protocol: str, *, limit: int = 100) -> list[Packet]:
        """Return packets of a given protocol."""
        return self.list(protocol=protocol, limit=limit)

    def get_by_port(
        self,
        port: int,
        *,
        direction: str = "destination",
        limit: int = 100,
    ) -> list[Packet]:
        """Return packets involving a port (M7.15).

        Args:
            port: The port number to match.
            direction: ``"source"`` or ``"destination"``.
            limit: Maximum number of packets to return.

        Raises:
            ValueError: If ``direction`` is neither source nor destination.
        """
        if direction == "source":
            return self.list(source_port=port, limit=limit)
        if direction == "destination":
            return self.list(destination_port=port, limit=limit)
        raise ValueError(f"Unknown port direction: {direction}")

    def get_between(
        self, start: datetime, end: datetime, *, limit: int = 100
    ) -> list[Packet]:
        """Return packets whose timestamp falls within a range."""
        return self.list(since=start, until=end, limit=limit)

    def count_all(self) -> int:
        """Return the total number of stored packets."""
        return self.count()

    def count_by_protocol(self, protocol: str) -> int:
        """Return the number of packets for a protocol."""
        return self.count(protocol=protocol)

    # -- internals --------------------------------------------------------

    @staticmethod
    def _filtered(
        statement,
        *,
        source_ip: str | None,
        destination_ip: str | None,
        protocol: str | None,
        source_port: int | None,
        destination_port: int | None,
        since: datetime | None,
        until: datetime | None,
    ):
        """Apply the shared packet filters to a select statement."""
        if source_ip is not None:
            statement = statement.where(Packet.source_ip == source_ip)
        if destination_ip is not None:
            statement = statement.where(Packet.destination_ip == destination_ip)
        if protocol is not None:
            statement = statement.where(Packet.protocol == protocol)
        if source_port is not None:
            statement = statement.where(Packet.source_port == source_port)
        if destination_port is not None:
            statement = statement.where(Packet.destination_port == destination_port)
        if since is not None:
            statement = statement.where(Packet.timestamp >= since)
        if until is not None:
            statement = statement.where(Packet.timestamp <= until)
        return statement


def _affected_rows(result: object) -> int:
    """Return how many rows a write statement affected.

    ``Session.execute`` is typed as returning a plain ``Result``, which does not
    advertise ``rowcount`` even though the concrete ``CursorResult`` it returns
    for a DELETE does. The count is therefore read defensively rather than with
    a type suppression.
    """
    return int(getattr(result, "rowcount", 0) or 0)
