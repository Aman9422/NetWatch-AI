"""Settings repository: the ``settings`` key/value table (M13.21).

The table is a generic key/value store, so this repository is deliberately thin:
it reads rows, writes rows and knows nothing about which keys mean what. The
*policy* — which keys are readable, which are mutable, which are secret — belongs
to the settings API module, because that is a decision about what may cross the
HTTP boundary rather than about how a row is stored.

Nothing here decides what a setting means or whether changing one takes effect;
it only moves rows.
"""

from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.setting import Setting
from app.repositories.base import BaseRepository


class SettingRepository(BaseRepository[Setting]):
    """Reads and writes application settings rows (M13.21)."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Setting)

    def get_by_key(self, setting_key: str) -> Setting | None:
        """Return the row for ``setting_key``, or ``None`` when absent."""
        statement = select(Setting).where(Setting.setting_key == str(setting_key))
        return self.db.scalars(statement).first()

    def list_all(self) -> list[Setting]:
        """Return every stored setting, ordered by key for a stable response."""
        statement = select(Setting).order_by(Setting.setting_key)
        return list(self.db.scalars(statement).all())

    def upsert(self, values: Mapping[str, tuple[str, str]]) -> list[Setting]:
        """Insert or update several settings in one transaction.

        Args:
            values: ``setting_key`` mapped to ``(setting_value, data_type)``.
                The caller has already validated and serialized the value, so a
                row is written exactly as supplied.

        Returns:
            The rows as stored, so the caller can echo what was persisted rather
            than what it intended to persist.

        Raises:
            Exception: Whatever the database raised, after the transaction has
                been rolled back — a failed batch never leaves settings
                half-updated.
        """
        try:
            for key, (value, data_type) in values.items():
                existing = self.get_by_key(key)
                if existing is None:
                    self.db.add(
                        Setting(
                            setting_key=str(key),
                            setting_value=str(value),
                            data_type=str(data_type),
                        )
                    )
                else:
                    existing.setting_value = str(value)
                    existing.data_type = str(data_type)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        stored: list[Setting] = []
        for key in values:
            row = self.get_by_key(key)
            if row is not None:
                stored.append(row)
        return stored


__all__ = ["SettingRepository"]
