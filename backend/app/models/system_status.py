"""System status model for NetWatch AI."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.mixins import utcnow


class SystemStatus(Base):
    """Current operational state of a system component.

    Attributes:
        component_name: Unique component name (``capture_engine``,
            ``database``, ``api``, ``websocket``, ``detection_engine``,
            ``ml_engine``, ``ai_engine``).
        status: Health state (``healthy``, ``degraded``, ``unhealthy``,
            ``stopped``).
        metric_value: Optional numeric metric (e.g. packets/sec).
        message: Optional human-readable status message.
        updated_at: Last update time.
    """

    __tablename__ = "system_status"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    component_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    metric_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('healthy', 'degraded', 'unhealthy', 'stopped')",
            name="ck_system_status_status",
        ),
    )
