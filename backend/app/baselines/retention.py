"""Baseline retention (M21.8).

One policy: observation windows older than the configured window are deleted, in
bounded passes. A **profile is not deleted**, and that asymmetry is deliberate
rather than an oversight.

A window is evidence. Evidence ages out: after seven days it no longer describes
how a device behaves *now*, and keeping it would make the profile a summary of
increasingly ancient behaviour. A profile is the *conclusion* drawn from that
evidence, and deleting it would lose the fact that the device was ever seen at
all. So when a profile's windows expire, the profile is **recomputed** rather than
removed: it falls back to ``learning`` with its sample count at zero, which is the
honest statement that its evidence has aged out.

Nothing here deletes from another table. The only write retention issues is a
DELETE against ``baseline_windows``.

The sweep is driven by the existing M19
:class:`~app.services.retention_scheduler.RetentionSweeper` rather than by a
thread of its own, so baseline retention inherits the same interval, the same
failure isolation and the same bounded shutdown the other two policies have.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.baselines.store import BaselineStore, retention_cutoff
from app.config.settings import settings

logger = logging.getLogger(__name__)

#: Default retention window in days, mirroring ``settings``.
DEFAULT_RETENTION_DAYS = 7

#: Default cap on rows one pass may delete.
DEFAULT_MAX_ROWS_PER_RUN = 5000


@dataclass(frozen=True)
class BaselineRetentionOutcome:
    """What one retention pass did (M21.8).

    Satisfies :class:`app.services.retention_scheduler.RetentionOutcomeLike`
    structurally — ``enabled``, ``succeeded`` and ``summary()`` — so the sweeper
    drives this policy without importing it.

    Attributes:
        enabled: Whether a retention window is configured.
        succeeded: Whether the pass completed, whether or not it deleted anything.
        deleted: How many window rows were removed.
        recomputed: How many profiles were recalculated afterwards.
        cutoff: The instant the pass treated as expired, ISO-8601, or ``None``.
        error: A safe sentence when the pass failed, otherwise ``None``.
    """

    enabled: bool
    succeeded: bool
    deleted: int = 0
    recomputed: int = 0
    cutoff: str | None = None
    error: str | None = None

    def summary(self) -> str:
        """Return one line describing the pass, safe to log."""
        if not self.enabled:
            return "retention disabled; nothing was deleted"
        if not self.succeeded:
            return f"retention failed: {self.error or 'unknown failure'}"
        return (
            f"deleted {self.deleted} window(s) older than {self.cutoff}, "
            f"recomputed {self.recomputed} profile(s)"
        )


class BaselineRetentionService:
    """Applies the baseline retention window (M21.8).

    Args:
        store: The store to delete through. Defaults to a new one over the
            application database.
        retention_days: Days a window is kept. ``0`` is allowed and means "delete
            everything already closed", which is an operator's explicit choice
            rather than a default.
        max_rows_per_run: Most rows one pass may delete.

    Raises:
        ValueError: If ``retention_days`` is negative or ``max_rows_per_run`` is
            not positive.
    """

    def __init__(
        self,
        *,
        store: BaselineStore | None = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_rows_per_run: int = DEFAULT_MAX_ROWS_PER_RUN,
    ) -> None:
        if retention_days < 0:
            raise ValueError("retention_days must not be negative")
        if max_rows_per_run < 1:
            raise ValueError("max_rows_per_run must be at least 1")
        self._store = store or BaselineStore()
        self._retention_days = retention_days
        self._max_rows_per_run = max_rows_per_run

    @property
    def retention_days(self) -> int:
        """Return the configured retention window in days."""
        return self._retention_days

    def cleanup_outcome(self) -> BaselineRetentionOutcome:
        """Run one retention pass and describe what happened (M21.8).

        Never raises: a retention failure is a policy that did not run, and
        letting it escape would make the sweeper report a failed pass. The
        failure is logged and reported in the outcome instead.
        """
        try:
            return self._cleanup()
        except Exception:  # noqa: BLE001 - a sweep must survive a failing policy
            logger.exception("Baseline retention pass failed")
            return BaselineRetentionOutcome(
                enabled=True,
                succeeded=False,
                error="the retention pass raised an unexpected failure",
            )

    def _cleanup(self) -> BaselineRetentionOutcome:
        """Perform the pass, letting a database failure reach the guard above."""
        cutoff = retention_cutoff(self._retention_days)
        deleted, affected = self._store.delete_windows_before(
            cutoff, max_rows=self._max_rows_per_run
        )
        recomputed = self._recompute(affected) if deleted else 0
        if deleted:
            logger.info(
                "Baseline retention deleted %d window(s) and recomputed %d profile(s)",
                deleted,
                recomputed,
            )
        return BaselineRetentionOutcome(
            enabled=True,
            succeeded=True,
            deleted=deleted,
            recomputed=recomputed,
            cutoff=f"{cutoff.isoformat()}Z",
        )

    def _recompute(self, device_keys: list[str]) -> int:
        """Recalculate the profiles whose windows the pass just deleted.

        A recompute failure is not a deletion failure — the rows are already gone
        — so a profile that cannot be recalculated is logged and skipped rather
        than turning a successful delete into a failed pass.
        """
        recomputed = 0
        for device_key in device_keys:
            try:
                if self._store.recompute_profile(device_key) is not None:
                    recomputed += 1
            except Exception:  # noqa: BLE001 - one profile must not stop the rest
                logger.exception("Could not recompute baseline %s", device_key)
        return recomputed


_retention_service: BaselineRetentionService | None = None


def get_baseline_retention_service() -> BaselineRetentionService:
    """Return the process-wide baseline retention service (M21.8)."""
    global _retention_service
    if _retention_service is None:
        _retention_service = BaselineRetentionService(
            retention_days=settings.baseline_retention_days,
            max_rows_per_run=settings.baseline_retention_max_per_run,
        )
    return _retention_service


def reset_baseline_retention_service() -> None:
    """Drop the cached service. For tests and reloads."""
    global _retention_service
    _retention_service = None


__all__ = [
    "DEFAULT_MAX_ROWS_PER_RUN",
    "DEFAULT_RETENTION_DAYS",
    "BaselineRetentionOutcome",
    "BaselineRetentionService",
    "get_baseline_retention_service",
    "reset_baseline_retention_service",
]
