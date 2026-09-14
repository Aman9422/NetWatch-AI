"""Packet retention cleanup (M7.13 / M7.14).

Raw packet metadata is high-volume, so it is kept only for a configurable
window (``PACKET_RETENTION_DAYS``, default 30 — see ``docs/03_Database_Design.md``
§24). :class:`PacketRetentionService` turns that window into a cutoff instant and
deletes only rows strictly older than it, so a cleanup run can never touch a
recent packet.

The service is deliberately small and side-effect free apart from the delete
itself, which makes it independently testable (M7.14). A database failure is
contained and logged rather than propagated, because retention runs
opportunistically in the background and must never disturb capture.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.persistence.session_factory import SessionFactory, app_session_factory
from app.repositories.packet import PacketRepository

logger = logging.getLogger(__name__)

# Fallback window used when the caller does not supply one.
DEFAULT_RETENTION_DAYS = 30

# Sentinel meaning "keep packets forever".
DISABLED_RETENTION_DAYS = 0


class PacketRetentionService:
    """Deletes packet rows older than the configured retention period (M7.13)."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        """Create the retention service.

        Args:
            session_factory: Builds database sessions.
            retention_days: How many days a packet row is kept. ``0`` disables
                retention (nothing is ever deleted).

        Raises:
            ValueError: If ``retention_days`` is negative.
        """
        if retention_days < 0:
            raise ValueError("retention_days must not be negative")
        self._session_factory = session_factory
        self._retention_days = retention_days

    @property
    def retention_days(self) -> int:
        """Return the configured retention window in days."""
        return self._retention_days

    def is_enabled(self) -> bool:
        """Return True when retention actually deletes rows."""
        return self._retention_days > DISABLED_RETENTION_DAYS

    def cutoff(self, now: datetime | None = None) -> datetime:
        """Return the instant before which packets are eligible for deletion.

        Args:
            now: Override the current time (used by tests).

        Returns:
            A timezone-aware UTC datetime ``now - retention_days``.
        """
        moment = now if now is not None else datetime.now(timezone.utc)
        return moment - timedelta(days=self._retention_days)

    def cleanup(self, now: datetime | None = None) -> int:
        """Delete packets captured before the retention cutoff (M7.13).

        Args:
            now: Override the current time (used by tests).

        Returns:
            How many rows were deleted. ``0`` means either nothing was eligible
            or the database failed — in both cases the caller should simply
            continue.
        """
        if not self.is_enabled():
            logger.debug("Packet retention disabled; nothing deleted")
            return 0

        cutoff = self.cutoff(now)
        session = self._session_factory()
        try:
            deleted = PacketRepository(session).delete_before(cutoff)
        except Exception:  # noqa: BLE001 - retention must never crash the app
            logger.exception("Packet retention cleanup failed; continuing")
            return 0
        finally:
            session.close()

        if deleted:
            logger.info(
                "Packet retention removed %d row(s) older than %s",
                deleted,
                cutoff.isoformat(),
            )
        else:
            logger.debug("Packet retention found no expired packets")
        return deleted


def get_packet_retention_service() -> PacketRetentionService:
    """Return a retention service configured from application settings."""
    from app.config.settings import settings

    return PacketRetentionService(
        session_factory=app_session_factory,
        retention_days=settings.packet_retention_days,
    )
