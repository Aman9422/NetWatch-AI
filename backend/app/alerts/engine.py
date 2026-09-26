"""The alert engine: the M11 consumer of the detection pipeline (M11.21).

Its shape mirrors :class:`~app.detection.engine.DetectionEngine` deliberately,
because it sits in the same place in the pipeline and must honour the same
contract. It:

* holds the master enable switch (M11.24);
* consumes findings, in order, handing each to the service (M11.21);
* **never raises into its caller** — the capture pipeline calls it for every
  packet, and M11.21 requires that no alerting failure may stop capture;
* aggregates diagnostics across the service's counters (M11.31).

It owns no logic of its own: every decision about *what* an alert is lives in the
service, the mapping and the evidence builder. The engine exists so the pipeline
has one object to call and the application has one place to look for diagnostics.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from app.alerts.service import AlertCounters, AlertOutcome, AlertService
from app.detection.finding import DetectionFinding

logger = logging.getLogger(__name__)


class AlertEngine:
    """Consumes detection findings and raises alerts (M11.21)."""

    def __init__(self, service: AlertService, *, enabled: bool = True) -> None:
        """Create the engine.

        Args:
            service: The alert service every finding is handed to.
            enabled: When False, findings are accepted and dropped without being
                turned into alerts — the master switch (M11.24). The service's
                own ``enabled`` flag is the same switch at a lower level; both
                exist so either layer can be disabled independently in tests.
        """
        self._service = service
        self._enabled = bool(enabled)

    # -- configuration ----------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return True while findings are turned into alerts (M11.24)."""
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Turn alert creation on or off without discarding stored alerts."""
        self._enabled = bool(enabled)

    @property
    def service(self) -> AlertService:
        """Return the underlying alert service."""
        return self._service

    # -- ingestion (M11.21) ----------------------------------------------

    def process_finding(self, finding: DetectionFinding) -> AlertOutcome:
        """Handle one finding, never raising.

        When the engine is disabled the finding is reported as skipped rather
        than silently ignored, so a caller can see *that* alerting is off rather
        than wondering why no alert appeared.
        """
        if not self._enabled:
            return AlertOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                message="The alert engine is disabled",
            )
        try:
            return self._service.process_finding(finding)
        except Exception:  # noqa: BLE001 - alerting must never stop capture
            # The service already contains its own failures, so reaching here
            # means something outside it went wrong. Still contained, because
            # M11.21 gives no exception a path back to the capture thread.
            logger.exception(
                "Alert engine failed for finding %s; capture continues",
                finding.finding_id,
            )
            return AlertOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                error=True,
                message="The alert engine failed",
            )

    def process_findings(
        self, findings: Iterable[DetectionFinding]
    ) -> list[AlertOutcome]:
        """Handle several findings, in order, and return one outcome each.

        Findings are processed in the order they arrive so an alert's evidence
        and its deduplication window are applied to the observations in the order
        they were actually made.
        """
        return [self.process_finding(finding) for finding in findings]

    # -- observability (M11.31) -------------------------------------------

    def get_counters(self) -> AlertCounters:
        """Return the service counters (M11.31)."""
        return self._service.get_counters()

    def reset(self) -> None:
        """Zero the counters and re-enable the service's ingestion.

        Stored alerts are deliberately untouched: resetting diagnostics must
        never delete a security record. Mirrors
        :meth:`~app.detection.engine.DetectionEngine.reset`, which also clears
        only in-memory state.
        """
        self._service.reset_counters()
        logger.info("Alert diagnostics reset")


__all__ = ["AlertEngine"]
