"""Packet model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import utcnow

if TYPE_CHECKING:
    from app.models.alert_evidence import AlertEvidence
    from app.models.device import Device


class Packet(Base):
    """Normalized packet metadata captured from the network.

    Only metadata is stored — raw payloads are intentionally excluded to keep
    storage light and avoid exposing sensitive content.

    Attributes:
        timestamp: When the packet was captured.
        source_ip / destination_ip: Packet endpoints.
        source_port / destination_port: Ports (TCP/UDP).
        protocol: ``TCP``, ``UDP``, ``ICMP``, etc.
        packet_length: Total packet size in bytes.
        ttl: IP time-to-live.
        tcp_flags: TCP flag string (optional).
        payload_length: Payload size (optional).
        device_id: Foreign key to the owning device.
        processed: Whether downstream processing is complete.
    """

    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    packet_length: Mapped[int] = mapped_column(Integer, nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_flags: Mapped[str | None] = mapped_column(String(20), nullable=True)
    payload_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    device: Mapped["Device"] = relationship(back_populates="packets")
    evidence_records: Mapped[list["AlertEvidence"]] = relationship(back_populates="packet")

    __table_args__ = (
        Index("idx_packets_timestamp", "timestamp"),
        Index("idx_packets_source_ip", "source_ip"),
        Index("idx_packets_destination_ip", "destination_ip"),
        Index("idx_packets_protocol", "protocol"),
        Index("idx_packets_device_id", "device_id"),
    )
