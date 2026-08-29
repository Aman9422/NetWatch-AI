"""Packet repository for NetWatch AI."""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.packet import Packet
from app.repositories.base import BaseRepository


class PacketRepository(BaseRepository[Packet]):
    """Repository for packet queries."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Packet)

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
        stmt = (
            select(Packet)
            .where(Packet.source_ip == source_ip)
            .order_by(Packet.timestamp.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_destination_ip(self, destination_ip: str, *, limit: int = 100) -> list[Packet]:
        """Return packets with a given destination IP."""
        stmt = (
            select(Packet)
            .where(Packet.destination_ip == destination_ip)
            .order_by(Packet.timestamp.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_protocol(self, protocol: str, *, limit: int = 100) -> list[Packet]:
        """Return packets of a given protocol."""
        stmt = (
            select(Packet)
            .where(Packet.protocol == protocol)
            .order_by(Packet.timestamp.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_between(self, start: datetime, end: datetime, *, limit: int = 100) -> list[Packet]:
        """Return packets whose timestamp falls within a range."""
        stmt = (
            select(Packet)
            .where(Packet.timestamp >= start)
            .where(Packet.timestamp <= end)
            .order_by(Packet.timestamp.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def count_all(self) -> int:
        """Return the total number of stored packets."""
        return self.count()

    def count_by_protocol(self, protocol: str) -> int:
        """Return the number of packets for a protocol."""
        stmt = select(func.count()).select_from(Packet).where(Packet.protocol == protocol)
        return int(self.db.scalar(stmt) or 0)
