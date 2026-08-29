"""Statistics repository for NetWatch AI."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.statistics import ProtocolStatistic, TrafficStatistic
from app.repositories.base import BaseRepository


class StatisticsRepository(BaseRepository[TrafficStatistic]):
    """Repository for traffic and protocol statistics queries."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, TrafficStatistic)

    def get_latest(self) -> TrafficStatistic | None:
        """Return the most recent traffic statistic."""
        stmt = select(TrafficStatistic).order_by(TrafficStatistic.timestamp.desc()).limit(1)
        return self.db.scalar(stmt)

    def get_between(self, start: datetime, end: datetime) -> list[TrafficStatistic]:
        """Return traffic statistics within a time range."""
        stmt = (
            select(TrafficStatistic)
            .where(TrafficStatistic.timestamp >= start)
            .where(TrafficStatistic.timestamp <= end)
            .order_by(TrafficStatistic.timestamp)
        )
        return list(self.db.scalars(stmt).all())

    def get_protocol_statistics(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> list[ProtocolStatistic]:
        """Return protocol statistics, optionally filtered by time range."""
        stmt = select(ProtocolStatistic)
        if start is not None:
            stmt = stmt.where(ProtocolStatistic.timestamp >= start)
        if end is not None:
            stmt = stmt.where(ProtocolStatistic.timestamp <= end)
        stmt = stmt.order_by(ProtocolStatistic.timestamp)
        return list(self.db.scalars(stmt).all())

    def get_protocol_counts(self, protocol: str, start: datetime, end: datetime) -> int:
        """Return the total packets for a protocol within a time range."""
        from sqlalchemy import func

        stmt = (
            select(func.sum(ProtocolStatistic.packet_count))
            .where(ProtocolStatistic.protocol == protocol)
            .where(ProtocolStatistic.timestamp >= start)
            .where(ProtocolStatistic.timestamp <= end)
        )
        return int(self.db.scalar(stmt) or 0)
