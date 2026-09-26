"""The alert service: findings in, alerts out (M11.21/M11.22).

This is the write path of M11 and the only component that decides *whether* a
finding becomes an alert. Concretely it:

* looks the finding's rule up in the mapping and refuses unknown ones (M11.8);
* builds the deduplication key and checks the bounded window (M11.9/M11.10);
* builds the bounded evidence set (M11.11-M11.15);
* writes the alert and its evidence in **one transaction** (M11.16);
* applies validated lifecycle transitions (M11.19/M11.20).

Three properties are deliberate:

* **It never raises into its caller (M11.26).** The capture pipeline calls it for
  every finding, and M11.21 requires that no alerting failure may stop capture.
  Every unexpected failure is counted and logged, and reported as an outcome.
* **The check-and-insert is atomic.** Deduplication is a read followed by a
  write, so two threads evaluating findings for the same incident could both
  find "no duplicate" and both insert. A lock spans the whole operation, which
  the database alone cannot guarantee at SQLite's isolation level.
* **Every operation opens its own session.** The service is called from the
  capture thread and from the API's thread pool, and a SQLAlchemy session is not
  thread-safe, so a session is never shared or cached.

Reads live in :mod:`app.alerts.queries`; this module only changes state (plus the
lifecycle queries it has to answer to apply a transition).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.alerts.alert import Alert
from app.alerts.dedup import (
    DEFAULT_DEDUP_WINDOW_SECONDS,
    DeduplicationKey,
    DeduplicationWindow,
)
from app.alerts.evidence_builder import build_evidence
from app.alerts.mapping import mapping_for_rule
from app.alerts.persistence import to_alert_row_values
from app.alerts.resolvers import FindingResolvers
from app.alerts.status import AlertStatus, from_value, validate_transition
from app.alerts.timestamps import to_utc_datetime
from app.detection.finding import DetectionFinding
from app.models.alert import Alert as AlertRow
from app.persistence.session_factory import SessionFactory
from app.repositories.alert import AlertRepository
from app.repositories.alert_evidence import AlertEvidenceRepository

logger = logging.getLogger(__name__)

#: Default evidence cap, in step with ``settings.alert_max_evidence_per_alert``.
DEFAULT_MAX_EVIDENCE = 64


@dataclass(frozen=True)
class AlertOutcome:
    """What happened to one finding (M11.21).

    An outcome is always returned, never raised, so the pipeline has nothing to
    catch. Exactly one of the flags describes the result:

    Attributes:
        finding_id: The finding this outcome concerns.
        rule_id: The detector that produced it.
        alert: The alert it created, folded into, or ``None`` when none exists.
        created: True when a new alert was stored.
        duplicate: True when the finding was folded into an existing alert.
        unsupported: True when the rule has no alert mapping (M11.8).
        error: True when the attempt failed and was contained (M11.26).
        message: Short human-readable explanation, for logs and diagnostics.
    """

    finding_id: str
    rule_id: str
    alert: Alert | None = None
    created: bool = False
    duplicate: bool = False
    unsupported: bool = False
    error: bool = False
    message: str = ""


@dataclass
class AlertCounters:
    """Execution counters for the alert service (M11.31)."""

    findings_seen: int = 0
    alerts_created: int = 0
    duplicates_folded: int = 0
    unsupported_findings: int = 0
    errors: int = 0
    transitions: int = 0


class AlertService:
    """Turns detection findings into persisted alerts (M11.21)."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        resolvers: FindingResolvers | None = None,
        dedup_window_seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS,
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
        packet_evidence_enabled: bool = True,
        enabled: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Create the alert service.

        Args:
            session_factory: Opens a session. Injected so tests can run against
                an isolated database, exactly as M7 and M9 do.
            resolvers: Where related packets, conversations and rule rows come
                from. ``None`` disables resolution, which still produces fully
                explainable alerts from the finding itself.
            dedup_window_seconds: Length of the deduplication window (M11.10).
                Validated by :class:`~app.alerts.dedup.DeduplicationWindow`.
            max_evidence: Hard cap on an alert's evidence records (M11.12).
            packet_evidence_enabled: Whether packet references are resolved.
            enabled: When False, findings are accepted and counted but no alert
                is produced, which is what the master switch (M11.24) means.
            clock: Time source in epoch seconds, used for lifecycle timestamps.
                Injectable so a test can pin ``updated_at`` exactly.

        Raises:
            ValueError: If ``max_evidence`` is not positive.
        """
        if max_evidence < 1:
            raise ValueError("max_evidence must be at least 1")
        self._session_factory = session_factory
        self._resolvers = resolvers
        # Constructed once so an invalid window fails here, at startup, rather
        # than on the first finding to arrive.
        self._window = DeduplicationWindow(dedup_window_seconds)
        self._max_evidence = int(max_evidence)
        self._packet_evidence_enabled = bool(packet_evidence_enabled)
        self._enabled = bool(enabled)
        self._clock = clock

        self._write_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._counters = AlertCounters()

    # -- configuration ----------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return True while findings are turned into alerts (M11.24)."""
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """Turn alert creation on or off without discarding stored alerts."""
        self._enabled = bool(enabled)

    def set_resolvers(self, resolvers: FindingResolvers | None) -> None:
        """Set (or clear) the evidence resolver set."""
        self._resolvers = resolvers

    # -- ingestion (M11.21) ----------------------------------------------

    def process_finding(self, finding: DetectionFinding) -> AlertOutcome:
        """Turn one finding into an alert, or fold it into an existing one.

        Never raises: M11.21 requires that no alerting failure may stop capture,
        so every failure is counted and returned as an error outcome.
        """
        self._increment("findings_seen")
        if not self._enabled:
            return AlertOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                message="Alerting is disabled",
            )

        mapping = mapping_for_rule(finding.rule_id)
        if mapping is None:
            self._increment("unsupported_findings")
            logger.debug(
                "Finding from unsupported rule %r produced no alert", finding.rule_id
            )
            return AlertOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                unsupported=True,
                message=f"Rule {finding.rule_id!r} has no alert mapping",
            )

        try:
            # The lock spans the duplicate check *and* the insert: checking and
            # inserting must be one step, or two threads can both decide "no
            # duplicate" and both create the alert (M11.9).
            with self._write_lock:
                return self._create_or_fold(finding, mapping)
        except Exception:  # noqa: BLE001 - alerting must never stop capture
            self._increment("errors")
            logger.exception(
                "Alert creation failed for finding %s; capture continues",
                finding.finding_id,
            )
            return AlertOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                error=True,
                message="Alert creation failed",
            )

    def process_findings(self, findings: list[DetectionFinding]) -> list[AlertOutcome]:
        """Process several findings, in order, and return their outcomes."""
        return [self.process_finding(finding) for finding in findings]

    # -- lifecycle (M11.19/M11.20) ---------------------------------------

    def set_status(
        self,
        alert_id: int,
        status: AlertStatus | str,
        *,
        updated_at: float | None = None,
    ) -> Alert | None:
        """Apply a validated lifecycle transition to a stored alert.

        Args:
            alert_id: The alert to change.
            status: The target state, validated against the transition table.
            updated_at: Observation time for the change, in epoch seconds.
                Defaults to the clock, so a test can pin it.

        Returns:
            The updated alert, or ``None`` when no alert has that id.

        Raises:
            ValueError: If ``status`` is not one of the five M11 states.
            InvalidStatusTransition: If the move is not allowed (M11.19), or if
                the transition is out of a terminal state.
            Exception: Whatever the database raised. A lifecycle change is a
                direct user action, so unlike alert *creation* it reports its
                failure instead of swallowing it.
        """
        target = from_value(status)
        stamp = to_utc_datetime(updated_at if updated_at is not None else self._clock())
        session = self._session_factory()
        try:
            alerts = AlertRepository(session)
            row = alerts.get(alert_id)
            if row is None:
                return None
            evidence = AlertEvidenceRepository(session)
            current = Alert.from_record(
                row, evidence_count=evidence.count_for_alert(alert_id)
            )
            # Validation happens here, before any write: an invalid move must
            # leave the stored alert exactly as it was.
            validate_transition(current.status, target)
            updated = current.with_status(target, updated_at=stamp)
            alerts.update_status(
                row,
                status=updated.status.value,
                updated_at=stamp,
                resolved_at=updated.resolved_at,
            )
            self._increment("transitions")
            logger.info(
                "Alert %d moved from %s to %s",
                alert_id,
                current.status.value,
                updated.status.value,
            )
            return Alert.from_record(
                row, evidence_count=evidence.count_for_alert(alert_id)
            )
        finally:
            session.close()

    # -- diagnostics (M11.31) --------------------------------------------

    def get_counters(self) -> AlertCounters:
        """Return a copy of the service counters."""
        with self._counter_lock:
            return AlertCounters(**vars(self._counters))

    def reset_counters(self) -> None:
        """Zero every counter, without touching stored alerts."""
        with self._counter_lock:
            self._counters = AlertCounters()

    # -- internals --------------------------------------------------------

    def _create_or_fold(self, finding: DetectionFinding, mapping) -> AlertOutcome:
        """Check the window, then create the alert or report the duplicate.

        The deduplication window is measured against the *observation* time, not
        the wall clock: ``created_at`` is the finding's timestamp (M11.3), so the
        window has to be anchored to the same instant or an alert would age out
        at a rate that depends on when it happened to be processed.
        """
        session = self._session_factory()
        try:
            alerts = AlertRepository(session)
            evidence_repo = AlertEvidenceRepository(session)
            key = DeduplicationKey.from_finding(finding)
            observed_at = float(finding.timestamp)
            cutoff = to_utc_datetime(self._window.cutoff(observed_at))

            candidate = alerts.find_duplicate_candidate(key.value(), cutoff=cutoff)
            if candidate is not None:
                self._increment("duplicates_folded")
                logger.debug(
                    "Finding %s folded into alert %d inside the deduplication window",
                    finding.finding_id,
                    candidate.id,
                )
                return AlertOutcome(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    alert=Alert.from_record(
                        candidate,
                        evidence_count=evidence_repo.count_for_alert(candidate.id),
                    ),
                    duplicate=True,
                    message=f"Folded into alert {candidate.id}",
                )

            evidence = build_evidence(
                finding,
                mapping,
                resolvers=self._resolvers,
                max_records=self._max_evidence,
                packet_evidence_enabled=self._packet_evidence_enabled,
            )
            runtime = self._build_alert(finding, mapping, key)
            rule_row_id = (
                self._resolvers.rule_row_id(mapping.rule_id)
                if self._resolvers is not None
                else None
            )
            row = AlertRow(**to_alert_row_values(runtime, rule_row_id=rule_row_id))
            session.add(row)
            # ``flush`` assigns the primary key without committing, so the
            # evidence can reference it inside the *same* transaction: an alert
            # is never stored without the evidence that justified it (M11.16).
            session.flush()
            records = evidence.records()
            if records:
                evidence_repo.stage(
                    [record.to_row_values(alert_id=row.id) for record in records]
                )
            session.commit()
            session.refresh(row)
            self._increment("alerts_created")
            logger.info(
                "Created alert %d for rule %s at severity %s",
                row.id,
                mapping.rule_id,
                mapping.severity.value,
            )
            return AlertOutcome(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                # The stored values are exactly the ones supplied here, so the
                # alert as built *is* the alert as stored; reporting it keeps the
                # device associations the row itself has no columns for (M11.15).
                alert=runtime.model_copy(
                    update={"alert_id": row.id, "evidence_count": len(records)}
                ),
                created=True,
                message=f"Created alert {row.id}",
            )
        finally:
            session.close()

    def _build_alert(
        self, finding: DetectionFinding, mapping, key: DeduplicationKey
    ) -> Alert:
        """Build the runtime alert for a finding (M11.3/M11.8).

        Severity comes from the rule's mapping, never from the finding and never
        from a detector (M11.4). Confidence comes from the finding, because that
        is what M10 measured (M11.5).
        """
        observed_at = to_utc_datetime(finding.timestamp)
        return Alert(
            rule_id=mapping.rule_id,
            title=mapping.title,
            description=finding.description,
            severity=mapping.severity,
            confidence=finding.confidence,
            status=AlertStatus.OPEN,
            created_at=observed_at,
            updated_at=observed_at,
            source_ip=finding.source_ip,
            destination_ip=finding.destination_ip,
            source_device_id=finding.source_device_id,
            destination_device_id=finding.destination_device_id,
            protocol=finding.protocol,
            finding_id=finding.finding_id,
            correlation_key=key.value(),
        )

    def _increment(self, field: str) -> None:
        """Increment one counter under the counter lock."""
        with self._counter_lock:
            setattr(self._counters, field, getattr(self._counters, field) + 1)


__all__ = ["AlertCounters", "AlertOutcome", "AlertService"]
