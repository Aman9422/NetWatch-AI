"""Network connection/session model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.device import Device


class NetworkConnection(Base):
    """An aggregated network connection/session.

    Rather than reconstructing sessions from raw packets on every query, the
    system stores summarized connection records here.

    This class is named ``NetworkConnection`` (not ``Connection``) to avoid
    clashing with SQLAlchemy's own ``Connection`` object.

    Attributes:
        source_device_id / destination_device_id: Optional device references.
        source_ip / destination_ip: Connection endpoints.
        source_port / destination_port: Ports.
        protocol: ``TCP``, ``UDP``, etc.
        packets_sent / packets_received: Packet counters.
        bytes_sent / bytes_received: Byte counters.
        start_time / end_time: Connection lifecycle timestamps.
        status: ``active``, ``completed``, ``failed``, or ``timeout``.
    """

    __tablename__ = "connections"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    destination_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    packets_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    packets_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    start_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

    source_device: Mapped["Device"] = relationship(
        back_populates="outgoing_connections",
        foreign_keys=[source_device_id],
    )
    destination_device: Mapped["Device"] = relationship(
        back_populates="incoming_connections",
        foreign_keys=[destination_device_id],
    )

    __table_args__ = (
        Index("idx_connections_start_time", "start_time"),
        Index("idx_connections_source_ip", "source_ip"),
        Index("idx_connections_destination_ip", "destination_ip"),
    )
