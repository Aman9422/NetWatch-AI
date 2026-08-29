"""Traffic and protocol statistics models for NetWatch AI."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class TrafficStatistic(Base):
    """Aggregated network traffic metrics for dashboards and analytics.

    Attributes:
        timestamp: Measurement time.
        packets_per_second / bytes_per_second: Live rates.
        active_devices / active_connections / active_alerts: Current counts.
        total_packets / total_bytes: Cumulative totals.
    """

    __tablename__ = "traffic_statistics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    packets_per_second: Mapped[float] = mapped_column(Float, nullable=False)
    bytes_per_second: Mapped[float] = mapped_column(Float, nullable=False)
    active_devices: Mapped[int] = mapped_column(Integer, nullable=False)
    active_connections: Mapped[int] = mapped_column(Integer, nullable=False)
    active_alerts: Mapped[int] = mapped_column(Integer, nullable=False)
    total_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    total_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        Index("idx_traffic_statistics_timestamp", "timestamp"),
    )


class ProtocolStatistic(Base):
    """Traffic statistics broken down by protocol.

    Attributes:
        timestamp: Measurement time.
        protocol: Protocol name (``TCP``, ``UDP``, ``ICMP``, etc.).
        packet_count: Number of packets.
        byte_count: Traffic volume in bytes.
    """

    __tablename__ = "protocol_statistics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        Index("idx_protocol_statistics_timestamp", "timestamp"),
    )
