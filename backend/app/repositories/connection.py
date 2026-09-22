"""Connection repository for NetWatch AI.

This repository owns every SQL statement that touches the ``connections``
table. It stores and retrieves *aggregated* conversations — one row per
conversation, never one row per packet (M7 already owns per-packet storage) —
which is exactly what M9.17 asks for.

Nothing here detects, scores, correlates or blocks: it only stores and
retrieves connection records.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.connection import NetworkConnection
from app.repositories.base import BaseRepository


class ConnectionRepository(BaseRepository[NetworkConnection]):
    """Repository for persisting and querying aggregated connections."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, NetworkConnection)

    # -- reads by status (M9.16) ------------------------------------------

    def get_active(self, *, limit: int = 100) -> list[NetworkConnection]:
        """Return connections currently marked ``active``."""
        return self.list(status="active", limit=limit)

    def get_completed(self, *, limit: int = 100) -> list[NetworkConnection]:
        """Return connections marked ``completed``."""
        return self.list(status="completed", limit=limit)

    # -- reads by endpoint ------------------------------------------------

    def get_by_source_device(
        self, device_id: int, *, limit: int = 100
    ) -> list[NetworkConnection]:
        """Return connections originating from a device."""
        stmt = (
            select(NetworkConnection)
            .where(NetworkConnection.source_device_id == device_id)
            .order_by(NetworkConnection.start_time.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_destination_device(
        self, device_id: int, *, limit: int = 100
    ) -> list[NetworkConnection]:
        """Return connections terminating at a device."""
        stmt = (
            select(NetworkConnection)
            .where(NetworkConnection.destination_device_id == device_id)
            .order_by(NetworkConnection.start_time.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_device(
        self, device_id: int, *, limit: int = 100
    ) -> list[NetworkConnection]:
        """Return connections where a device is *either* endpoint (M9.25).

        A conversation is bidirectional, so asking "what did this device talk
        to?" must not silently exclude its inbound traffic.
        """
        return self.list(device_id=device_id, limit=limit)

    def get_by_protocol(
        self, protocol: str, *, limit: int = 100
    ) -> list[NetworkConnection]:
        """Return connections using a given protocol."""
        return self.list(protocol=protocol, limit=limit)

    def get_by_ip(
        self, ip_address: str, *, limit: int = 100
    ) -> list[NetworkConnection]:
        """Return connections where an address is either endpoint."""
        stmt = (
            select(NetworkConnection)
            .where(
                (NetworkConnection.source_ip == ip_address)
                | (NetworkConnection.destination_ip == ip_address)
            )
            .order_by(NetworkConnection.start_time.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    # -- reads by time (M9.25) --------------------------------------------

    def list(
        self,
        *,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        protocol: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        device_id: int | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NetworkConnection]:
        """Return connections matching the filters, newest first (M9.25).

        ``device_id`` matches either endpoint, and ``since``/``until`` compare
        against ``start_time`` so a window selects the conversations that
        *began* inside it.

        Raises:
            ValueError: If ``limit`` is below 1 or ``offset`` is negative.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if offset < 0:
            raise ValueError("offset must not be negative")
        statement = self._filtered(
            select(NetworkConnection),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            device_id=device_id,
            status=status,
            since=since,
            until=until,
        )
        statement = (
            statement.order_by(
                NetworkConnection.start_time.desc(), NetworkConnection.id.desc()
            )
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
        device_id: int | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        """Count connections matching the same filters as :meth:`list`."""
        statement = self._filtered(
            select(func.count()).select_from(NetworkConnection),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            device_id=device_id,
            status=status,
            since=since,
            until=until,
        )
        return int(self.db.scalar(statement) or 0)

    def get_between(
        self, start: datetime, end: datetime, *, limit: int = 100
    ) -> list[NetworkConnection]:
        """Return connections that started within a time range (M9.25)."""
        return self.list(since=start, until=end, limit=limit)

    def count_all(self) -> int:
        """Return the total number of stored connections."""
        return self.count()

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
        device_id: int | None,
        status: str | None,
        since: datetime | None,
        until: datetime | None,
    ):
        """Apply the shared connection filters to a select statement."""
        if source_ip is not None:
            statement = statement.where(NetworkConnection.source_ip == source_ip)
        if destination_ip is not None:
            statement = statement.where(
                NetworkConnection.destination_ip == destination_ip
            )
        if protocol is not None:
            statement = statement.where(NetworkConnection.protocol == protocol)
        if source_port is not None:
            statement = statement.where(NetworkConnection.source_port == source_port)
        if destination_port is not None:
            statement = statement.where(
                NetworkConnection.destination_port == destination_port
            )
        if device_id is not None:
            statement = statement.where(
                (NetworkConnection.source_device_id == device_id)
                | (NetworkConnection.destination_device_id == device_id)
            )
        if status is not None:
            statement = statement.where(NetworkConnection.status == status)
        if since is not None:
            statement = statement.where(NetworkConnection.start_time >= since)
        if until is not None:
            statement = statement.where(NetworkConnection.start_time <= until)
        return statement
