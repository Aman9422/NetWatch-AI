"""Application setting model for NetWatch AI."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.mixins import utcnow


class Setting(Base):
    """A key-value application configuration entry.

    A flexible key-value design keeps the settings system simple and lets new
    settings be added without schema changes.

    Attributes:
        setting_key: Unique configuration key (e.g. ``capture_interface``).
        setting_value: The stored value as text.
        data_type: How to interpret ``setting_value`` (``string``, ``int``,
            ``float``, ``bool``, ``json``).
        updated_at: Last modification time.
    """

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    setting_key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    setting_value: Mapped[str] = mapped_column(Text, nullable=False)
    data_type: Mapped[str] = mapped_column(String(20), nullable=False, default="string")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    __table_args__ = (
        CheckConstraint(
            "data_type IN ('string', 'int', 'float', 'bool', 'json')",
            name="ck_settings_data_type",
        ),
    )
