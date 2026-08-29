"""Device model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.baseline import BehavioralBaseline
    from app.models.connection import NetworkConnection
    from app.models.packet import Packet


class Device(Base):
    """A network device observed by the monitoring system.

    Attributes:
        id: Primary key.
        ip_address: IPv4 or IPv6 address.
        mac_address: Hardware MAC address (optional).
        hostname: Resolved hostname (optional).
        vendor: Hardware vendor (optional).
        operating_system: Detected OS (optional).
        device_type: Laptop, router, server, etc. (optional).
        status: ``online``, ``offline``, or ``unknown``.
        risk_score: 0-100 risk value.
        trust_score: 0-100 trust value.
        total_packets / total_bytes: Cumulative traffic counters.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    total_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # A device can be the source or destination of many connections.
    outgoing_connections: Mapped[list["NetworkConnection"]] = relationship(
        back_populates="source_device",
        foreign_keys="NetworkConnection.source_device_id",
    )
    incoming_connections: Mapped[list["NetworkConnection"]] = relationship(
        back_populates="destination_device",
        foreign_keys="NetworkConnection.destination_device_id",
    )
    packets: Mapped[list["Packet"]] = relationship(back_populates="device")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="device")
    baseline: Mapped["BehavioralBaseline | None"] = relationship(
        back_populates="device",
        uselist=False,
        cascade="all, delete-orphan",
    )
