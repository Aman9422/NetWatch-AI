"""Anomaly-record retention (M22.10).

One policy: evaluation rows older than the configured window are deleted, in
bounded passes. **Model metadata is not deleted**, and that asymmetry is
deliberate — the same reasoning M21 applies to profiles versus windows.

An evaluation is *evidence*: after thirty days a verdict about one minute of
traffic no longer describes how a device behaves now. A model is the *conclusion*
about a device's learned behaviour, and deleting it because its verdicts expired
would lose that and force a pointless retrain.

Nothing here deletes from another table.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.anomaly_detection.evaluation_store import EvaluationStore, retention_cutoff
from app.config.settings import settings

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_ROWS_PER_RUN = 5000


@dataclass(frozen=True)
class AnomalyRetentionOutcome:
    """What one retention pass did (M22.10)."""

    enabled: bool
    succeeded: bool
    deleted: int = 0
    cutoff: str | None = None
    error: str | None = None

    def summary(self) -> str:
        """Return one line describing the pass, safe to log."""
        if not self.enabled:
            return "retention disabled; nothing was deleted"
        if not self.succeeded:
            return f"retention failed: {self.error or 'unknown failure'}"
        return f"deleted {self.deleted} anomaly record(s) older than {self.cutoff}"


class AnomalyRetentionService:
    """Applies the anomaly retention window (M22.10)."""

    def __init__(
        self,
        *,
        store: EvaluationStore | None = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_rows_per_run: int = DEFAULT_MAX_ROWS_PER_RUN,
    ) -> None:
        if retention_days < 0:
            raise ValueError("retention_days must not be negative")
        if max_rows_per_run < 1:
            raise ValueError("max_rows_per_run must be at least 1")
        self._store = store or EvaluationStore()
        self._retention_days = retention_days
        self._max_rows_per_run = max_rows_per_run

    @property
    def retention_days(self) -> int:
        """Return the configured retention window in days."""
        return self._retention_days

    def cleanup_outcome(self) -> AnomalyRetentionOutcome:
        """Run one retention pass and describe what happened (M22.10).

        Never raises: a retention failure is a policy that did not run, and
        letting it escape would make the sweeper report a failed pass.
        """
        try:
            return self._cleanup()
        except Exception:  # noqa: BLE001 - a sweep must survive a failing policy
            logger.exception("Anomaly retention pass failed")
            return AnomalyRetentionOutcome(
                enabled=True,
                succeeded=False,
                error="the retention pass raised an unexpected failure",
            )

    def _cleanup(self) -> AnomalyRetentionOutcome:
        """Perform the pass, letting a database failure reach the guard above."""
        cutoff = retention_cutoff(self._retention_days)
        deleted = self._store.delete_before(cutoff, max_rows=self._max_rows_per_run)
        if deleted:
            logger.info("Anomaly retention deleted %d record(s)", deleted)
        return AnomalyRetentionOutcome(
            enabled=True,
            succeeded=True,
            deleted=deleted,
            cutoff=f"{cutoff.isoformat()}Z",
        )


_retention_service: AnomalyRetentionService | None = None


def get_anomaly_retention_service() -> AnomalyRetentionService:
    """Return the process-wide anomaly retention service (M22.10)."""
    global _retention_service
    if _retention_service is None:
        _retention_service = AnomalyRetentionService(
            retention_days=settings.anomaly_retention_days,
            max_rows_per_run=settings.anomaly_retention_max_per_run,
        )
    return _retention_service


def reset_anomaly_retention_service() -> None:
    """Drop the cached service. For tests and reloads."""
    global _retention_service
    _retention_service = None


__all__ = [
    "DEFAULT_MAX_ROWS_PER_RUN",
    "DEFAULT_RETENTION_DAYS",
    "AnomalyRetentionOutcome",
    "AnomalyRetentionService",
    "get_anomaly_retention_service",
    "reset_anomaly_retention_service",
]
