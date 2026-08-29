"""Behavioral baseline model for NetWatch AI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.device import Device


class BehavioralBaseline(TimestampMixin, Base):
    """A behavioral profile for a device.

    The baseline lets the system detect deviations from normal activity.
    ``device_id`` is unique, meaning each device has at most one baseline —
    this is the "one-to-one" relationship described in the database design.

    Attributes:
        device_id: Unique foreign key to the associated device.
        status: ``learning``, ``active``, or ``disabled``.
        observation_count: How many observations shaped this baseline.
        avg_packets_per_second / avg_bytes_per_second: Average rates.
        avg_unique_destinations / avg_unique_ports: Average variety.
        avg_packet_size: Typical packet size.
        normal_tcp_ratio / normal_udp_ratio / normal_icmp_ratio: Protocol mix.
    """

    __tablename__ = "behavioral_baselines"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="learning")
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_packets_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_bytes_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_unique_destinations: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_unique_ports: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_packet_size: Mapped[float | None] = mapped_column(Float, nullable=True)
    normal_tcp_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    normal_udp_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    normal_icmp_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="baseline")
