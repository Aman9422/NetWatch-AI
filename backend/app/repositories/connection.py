"""Connection repository for NetWatch AI."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.connection import NetworkConnection
from app.repositories.base import BaseRepository


class ConnectionRepository(BaseRepository[NetworkConnection]):
    """Repository for network connection queries."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, NetworkConnection)

    def get_active(self, *, limit: int = 100) -> list[NetworkConnection]:
        """Return connections currently marked ``active``."""
        stmt = (
            select(NetworkConnection)
            .where(NetworkConnection.status == "active")
            .order_by(NetworkConnection.start_time.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_completed(self, *, limit: int = 100) -> list[NetworkConnection]:
        """Return connections marked ``completed``."""
        stmt = (
            select(NetworkConnection)
            .where(NetworkConnection.status == "completed")
            .order_by(NetworkConnection.start_time.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_source_device(self, device_id: int, *, limit: int = 100) -> list[NetworkConnection]:
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

    def get_by_protocol(self, protocol: str, *, limit: int = 100) -> list[NetworkConnection]:
        """Return connections using a given protocol."""
        stmt = (
            select(NetworkConnection)
            .where(NetworkConnection.protocol == protocol)
            .order_by(NetworkConnection.start_time.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())
