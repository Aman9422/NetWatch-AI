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

**A failure is reported, not folded into a zero (M19.3/M19.5).** M7 contained a
failure by returning ``0``, which is also the answer for "nothing was old enough
to delete". A cleanup that could not read the database at all was therefore
indistinguishable from one that had nothing to do, and the only evidence was a
log line nobody reads on a machine where everything else is green.
:meth:`PacketRetentionService.cleanup_outcome` separates the two explicitly, and
:meth:`PacketRetentionService.cleanup` — kept at its M7 signature, because
callers and tests depend on the count — is now defined in terms of it. The
containment is unchanged: neither method raises, because retention must never
disturb capture.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.persistence.session_factory import SessionFactory, app_session_factory
from app.repositories.packet import PacketRepository

logger = logging.getLogger(__name__)

# Fallback window used when the caller does not supply one.
DEFAULT_RETENTION_DAYS = 30

# Sentinel meaning "keep packets forever".
DISABLED_RETENTION_DAYS = 0

#: The sentence a failed cleanup carries. Constant, and free of any internal
#: detail: an operator reads it, the log carries the real cause (M13.30).
RETENTION_FAILURE_MESSAGE = (
    "Packet retention could not read the packet store; nothing was deleted"
)


@dataclass(frozen=True)
class RetentionOutcome:
    """What one cleanup attempt actually did (M19.5).

    Three fields because there are three distinct answers, and M7's single ``int``
    collapsed two of them:

    * ``deleted > 0`` — rows were removed. The only state in which anything
      changed.
    * ``deleted == 0`` and ``failed is False`` — a *measured* zero. Either
      retention is switched off or nothing was old enough; in both cases the
      store was read and had nothing to give up.
    * ``failed is True`` — the attempt did not complete. ``deleted`` is ``0``
      because nothing is known to have been removed, and ``error`` carries a
      safe sentence. This is the state M7 could not express, and the one an
      operator needs to see: a retention policy that has silently stopped
      running is a database that grows without bound (M19.5).

    Attributes:
        deleted: Rows removed. ``0`` for both a measured zero and a failure.
        failed: True when the attempt raised rather than answering.
        error: A safe sentence when ``failed``, otherwise ``None``.
        enabled: Whether the configured policy would delete anything at all.
    """

    deleted: int = 0
    failed: bool = False
    error: str | None = None
    enabled: bool = True

    @property
    def succeeded(self) -> bool:
        """True when the attempt completed, whether or not it deleted anything."""
        return not self.failed

    @property
    def removed_anything(self) -> bool:
        """True when this attempt actually deleted a row."""
        return self.deleted > 0

    def summary(self) -> str:
        """Return a short human description of the attempt.

        Present on both retention outcomes so the M19 sweep can log a pass from a
        single code path without knowing which store it just cleaned (M19.5):
        :class:`~app.reports.retention.ReportRetentionOutcome` carries the same
        method for the same reason.
        """
        if not self.enabled:
            return "packet retention disabled"
        if self.failed:
            return "packet retention failed; nothing was deleted"
        return f"{self.deleted} packet row(s) deleted"


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
        # Guarded because cleanup may be reached from a background thread and
        # from a request at the same time; the counter is the operator's only
        # signal that a policy has stopped working (M19.3).
        self._failure_lock = threading.Lock()
        self._failures = 0

    @property
    def retention_days(self) -> int:
        """Return the configured retention window in days."""
        return self._retention_days

    @property
    def failure_count(self) -> int:
        """Return how many cleanup attempts this instance has seen fail (M19.3).

        A non-zero value means retention is *not* protecting the store: rows that
        should have been deleted are still there, and the database is growing by
        whatever the capture rate writes. Reading it is how a caller can tell a
        measured zero from a failed attempt without parsing a log.
        """
        with self._failure_lock:
            return self._failures

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

    def cleanup_outcome(self, now: datetime | None = None) -> RetentionOutcome:
        """Delete expired packets and report honestly what happened (M19.5).

        The answer M7's single ``int`` could not give. The delete, the cutoff and
        the containment are unchanged; what is new is that a failure returns a
        described outcome instead of the same ``0`` a no-op returns.

        Args:
            now: Override the current time (used by tests).

        Returns:
            A :class:`RetentionOutcome`. This method **never raises**, because
            retention runs opportunistically and must never disturb capture
            (M7.14) — the failure is contained, counted and described rather than
            propagated.
        """
        if not self.is_enabled():
            logger.debug("Packet retention disabled; nothing deleted")
            # A *measured* zero: the store was never asked, so nothing is unknown.
            return RetentionOutcome(deleted=0, failed=False, enabled=False)

        cutoff = self.cutoff(now)
        session = None
        try:
            session = self._session_factory()
            deleted = int(PacketRepository(session).delete_before(cutoff))
        except Exception:  # noqa: BLE001 - retention must never crash the app
            self._note_failure()
            logger.exception("Packet retention cleanup failed; continuing")
            return RetentionOutcome(
                deleted=0, failed=True, error=RETENTION_FAILURE_MESSAGE
            )
        finally:
            if session is not None:
                session.close()

        if deleted:
            logger.info(
                "Packet retention removed %d row(s) older than %s",
                deleted,
                cutoff.isoformat(),
            )
        else:
            logger.debug("Packet retention found no expired packets")
        return RetentionOutcome(deleted=deleted)

    def cleanup(self, now: datetime | None = None) -> int:
        """Delete packets captured before the retention cutoff (M7.13).

        Kept at its M7 signature because callers and tests depend on the count.
        Prefer :meth:`cleanup_outcome`, which can also say that the attempt
        failed: this method's ``0`` is ambiguous between "nothing was old enough"
        and "the store could not be read" (M19.3).

        Args:
            now: Override the current time (used by tests).

        Returns:
            How many rows were deleted. ``0`` means either nothing was eligible
            or the attempt failed; :meth:`failure_count` tells the two apart.
        """
        return self.cleanup_outcome(now).deleted

    def _note_failure(self) -> None:
        """Count one failed attempt, so a broken policy is observable (M19.3)."""
        with self._failure_lock:
            self._failures += 1


def get_packet_retention_service() -> PacketRetentionService:
    """Return a retention service configured from application settings."""
    from app.config.settings import settings

    return PacketRetentionService(
        session_factory=app_session_factory,
        retention_days=settings.packet_retention_days,
    )
