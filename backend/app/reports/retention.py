"""Report artifact retention (M19.5).

M17 writes a metadata row and a file for every generated report, and nothing ever
removed either. M18 recorded that as an open operational concern: a long-lived
installation accumulates report files without limit, and the directory's growth is
proportional to how many reports were asked for rather than to anything bounded.

This module is the smallest policy that fixes it, and it is deliberately built to
the shape M7's packet retention already established, so there is one retention
concept in the project rather than two:

* it is **switched off by default** — ``REPORT_RETENTION_DAYS=0`` means "keep every
  report". A report is something an operator asked for, and M19 does not delete
  one nobody asked it to delete (M19.5);
* a window is a number of whole days, and only rows generated *strictly before*
  the cutoff are eligible, so a cleanup can never touch a recent report;
* it **never raises** — retention runs in the background, beside capture and
  analysis, and a cleanup that could not reach the store must not be able to
  disturb either (M19.4);
* a failure is **reported as a failure** rather than as a zero, because M7 taught
  this project what a misleading zero costs (M19.3).

**The file and the row go together.** Removing a metadata row without its file
would leave an orphan file that no later pass knows about, so it would never be
cleaned up; removing a file without its row would leave metadata claiming an
artifact that is gone. The file is removed *first*, then the row: if the row
delete fails, the row survives and the next pass tries again, and until then the
listing reports honestly that the artifact is not available. The other order has
no such recovery — a leak that nothing will ever revisit. One commit for the whole
bounded pass, so a failure is retried wholesale rather than half-applied.

**A pass is bounded.** At most ``max_per_run`` reports are removed per pass and
the outcome says whether a backlog remains, so a cleanup holds a write transaction
open for a bounded time and a large backlog is drained over several passes. This
is what keeps retention from competing with capture for the database.

**A generation in flight is never touched.** A row whose status is ``generating``
is a report being written *right now*; its timestamp is irrelevant, because an
artifact is produced after its row exists. Such a row is excluded from every
candidate set regardless of age, which is what stops retention from deleting the
record of the very generation it is running beside.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.report import Report
from app.persistence.session_factory import SessionFactory, app_session_factory
from app.repositories.report import ReportRepository
from app.reports.status import ReportStatus
from app.reports.storage import ReportStorage

logger = logging.getLogger(__name__)

#: Fallback window used when a caller does not supply one. Zero, matching the
#: configured default, because report retention is opt-in.
DEFAULT_RETENTION_DAYS = 0

#: Sentinel meaning "keep every report".
DISABLED_RETENTION_DAYS = 0

#: Most reports one pass removes unless a caller says otherwise. Bounded for the
#: same reason the packet queue is (M7.9): a cleanup task must not be able to hold
#: a write transaction open for an unbounded time, however large the backlog.
DEFAULT_MAX_PER_RUN = 500

#: The sentence a failed cleanup carries. Constant, and free of any internal
#: detail: an operator reads it, the log carries the real cause (M13.30).
REPORT_RETENTION_FAILURE_MESSAGE = (
    "Report retention could not read the report store; nothing was removed"
)


@dataclass(frozen=True)
class ReportRetentionOutcome:
    """What one report-retention pass actually did (M19.5).

    Five counters because four different things can happen to one candidate and
    collapsing any two of them would hide a failure behind a plausible number:

    * ``removed`` — metadata rows deleted.
    * ``files_removed`` — artifacts deleted from the storage directory.
    * ``files_missing`` — rows whose artifact was already absent, so there was no
      file to delete. Not a failure: the artifact was gone before the pass ran,
      which is exactly what a listing already reports as "not available".
    * ``drained`` — the pass reached the end of the expired set. ``False`` means a
      bounded pass stopped early and a later pass will continue.
    * ``failed`` — the attempt did not complete. ``error`` carries a safe sentence.

    Attributes:
        removed: Metadata rows deleted by this pass.
        files_removed: Artifacts deleted from disk by this pass.
        files_missing: Eligible rows whose artifact was already absent.
        failed: True when the pass raised rather than completing.
        error: A safe sentence when ``failed``, otherwise ``None``.
        enabled: Whether the configured policy would remove anything at all.
        drained: Whether the expired set was fully processed.
    """

    removed: int = 0
    files_removed: int = 0
    files_missing: int = 0
    failed: bool = False
    error: str | None = None
    enabled: bool = True
    drained: bool = True

    @property
    def succeeded(self) -> bool:
        """True when the pass completed, whether or not it removed anything."""
        return not self.failed

    @property
    def removed_anything(self) -> bool:
        """True when this pass deleted at least one row or file."""
        return self.removed > 0 or self.files_removed > 0

    def summary(self) -> str:
        """Return a short human description of the pass, for a log or a report."""
        if not self.enabled:
            return "report retention disabled"
        if self.failed:
            return f"report retention failed after {self.removed} row(s)"
        text = f"{self.removed} report(s) and {self.files_removed} file(s) removed"
        if self.files_missing:
            text += f", {self.files_missing} artifact(s) already absent"
        if not self.drained:
            text += "; backlog remains"
        return text


class ReportRetentionService:
    """Removes report rows and artifacts older than a window (M19.5)."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        storage: ReportStorage | None = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_per_run: int = DEFAULT_MAX_PER_RUN,
    ) -> None:
        """Create the report-retention service.

        Args:
            session_factory: Builds database sessions.
            storage: Where artifacts live. Defaults to the configured directory;
                a test supplies its own so nothing is removed outside a temporary
                path.
            retention_days: How many days a report is kept. ``0`` disables
                retention, so no report is ever removed automatically.
            max_per_run: Hard cap on rows removed by one pass.

        Raises:
            ValueError: If ``retention_days`` is negative or ``max_per_run`` is
                not positive — both are configuration mistakes that would make the
                policy mean something other than it says.
        """
        if retention_days < 0:
            raise ValueError("retention_days must not be negative")
        if max_per_run < 1:
            raise ValueError("max_per_run must be positive")
        self._session_factory = session_factory
        self._storage = storage if storage is not None else ReportStorage()
        self._retention_days = retention_days
        self._max_per_run = max_per_run
        # Guarded because the sweep thread and a caller may reach a cleanup at the
        # same time; the counter is the operator's only signal that the policy has
        # stopped working (M19.3).
        self._failure_lock = threading.Lock()
        self._failures = 0

    @property
    def retention_days(self) -> int:
        """Return the configured retention window in days."""
        return self._retention_days

    @property
    def max_per_run(self) -> int:
        """Return the most reports one pass will remove."""
        return self._max_per_run

    @property
    def failure_count(self) -> int:
        """Return how many cleanup attempts this instance has seen fail (M19.3)."""
        with self._failure_lock:
            return self._failures

    def is_enabled(self) -> bool:
        """Return True when retention actually removes reports."""
        return self._retention_days > DISABLED_RETENTION_DAYS

    def cutoff(self, now: datetime | None = None) -> datetime:
        """Return the instant before which reports are eligible for removal.

        The result is timezone-aware UTC, while ``reports.generated_at`` is stored
        naive UTC — SQLite does not preserve a tzinfo. The comparison is therefore
        made against the naive value (see :meth:`_naive`), so the cutoff and the
        column are expressed in the same instant rather than two hours apart.
        """
        moment = now if now is not None else datetime.now(timezone.utc)
        return moment - timedelta(days=self._retention_days)

    def cleanup_outcome(self, now: datetime | None = None) -> ReportRetentionOutcome:
        """Remove expired reports and report honestly what happened (M19.5).

        Returns:
            A :class:`ReportRetentionOutcome`. This method **never raises**:
            retention runs beside capture and analysis, and a cleanup that could
            not reach the store must not be able to disturb either (M19.4). The
            failure is contained, counted and described instead of propagated.
        """
        if not self.is_enabled():
            logger.debug("Report retention disabled; nothing removed")
            return ReportRetentionOutcome(enabled=False)

        cutoff = self.cutoff(now)
        session: Session | None = None
        try:
            session = self._session_factory()
            repository = ReportRepository(session)
            # One more than the cap, so a full pass can tell "that was all of
            # them" from "there is more to do" without a second query.
            candidates = repository.list_expired(
                cutoff=self._naive(cutoff),
                limit=self._max_per_run + 1,
                excluded_status=ReportStatus.GENERATING,
            )
            drained = len(candidates) <= self._max_per_run
            batch = candidates[: self._max_per_run]
            files_removed, files_missing = self._remove_artifacts(batch)
            removed = repository.delete_many(batch)
        except Exception:  # noqa: BLE001 - retention must never crash the app
            self._note_failure()
            logger.exception("Report retention cleanup failed; continuing")
            if session is not None:
                self._rollback(session)
            return ReportRetentionOutcome(
                failed=True, error=REPORT_RETENTION_FAILURE_MESSAGE
            )
        finally:
            if session is not None:
                session.close()

        if removed:
            logger.info(
                "Report retention removed %d report(s) and %d file(s)%s",
                removed,
                files_removed,
                "" if drained else " (bounded pass; backlog remains)",
            )
        else:
            logger.debug("Report retention found no expired reports")
        return ReportRetentionOutcome(
            removed=removed,
            files_removed=files_removed,
            files_missing=files_missing,
            drained=drained,
        )

    def cleanup(self, now: datetime | None = None) -> int:
        """Remove expired reports and return how many rows went (M19.5).

        Provided for symmetry with the packet service's ``cleanup``, which callers
        and verification scripts use for its count. Prefer
        :meth:`cleanup_outcome`, which can also say that the attempt failed.
        """
        return self.cleanup_outcome(now).removed

    # -- internals -------------------------------------------------------

    def _remove_artifacts(self, batch: Sequence[Report]) -> tuple[int, int]:
        """Delete each candidate's artifact, returning how many went and how many
        were already absent.

        Never raises: the storage layer already answers a missing or unreadable
        artifact as a boolean, and a file that cannot be removed is reported by
        its own log line rather than by failing the whole pass. A row whose file
        survived is still deleted, because the alternative -- keeping a row to
        retry its file forever -- would leave retention permanently stuck on one
        unwritable file.
        """
        removed = 0
        missing = 0
        for row in batch:
            stored = str(row.file_path or "")
            if not stored:
                # A row interrupted before its file name was assigned has no
                # artifact to remove; the empty value is not a location (M17.9).
                missing += 1
                continue
            if self._storage.delete(stored):
                removed += 1
            else:
                missing += 1
        return removed, missing

    @staticmethod
    def _naive(moment: datetime) -> datetime:
        """Return ``moment`` as naive UTC, the form ``reports.generated_at`` holds.

        The column is a plain ``DateTime``, so SQLite stores and returns it without
        a timezone. Passing an aware datetime into the comparison would have the
        driver store a literal with an offset that never matches the stored values,
        which is how a retention window silently stops matching anything (M19.5).
        """
        if moment.tzinfo is None:
            return moment
        return moment.astimezone(timezone.utc).replace(tzinfo=None)

    def _rollback(self, session: Session) -> None:
        """Discard a failed pass's transaction, logging rather than raising."""
        try:
            session.rollback()
        except Exception:  # noqa: BLE001 - cleanup must not mask the real failure
            logger.exception("Report retention could not roll back its transaction")

    def _note_failure(self) -> None:
        """Count one failed attempt, so a broken policy is observable (M19.3)."""
        with self._failure_lock:
            self._failures += 1


def get_report_retention_service() -> ReportRetentionService:
    """Return a report-retention service configured from application settings."""
    from app.config.settings import settings

    return ReportRetentionService(
        session_factory=app_session_factory,
        storage=ReportStorage(),
        retention_days=settings.report_retention_days,
        max_per_run=settings.report_retention_max_per_run,
    )


__all__ = [
    "DEFAULT_MAX_PER_RUN",
    "DEFAULT_RETENTION_DAYS",
    "DISABLED_RETENTION_DAYS",
    "REPORT_RETENTION_FAILURE_MESSAGE",
    "ReportRetentionOutcome",
    "ReportRetentionService",
    "get_report_retention_service",
]
