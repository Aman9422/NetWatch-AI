"""The correlation engine: findings and alerts in, incidents out (M12.2).

``CorrelationEngine`` is the layer's public face. It is what the capture
pipeline calls, what the read paths ask, and the only part of M12 that knows
about all three of its collaborators at once:

* :class:`~app.correlation.registry.IncidentRegistry` — the bounded, thread-safe
  store of incidents, which owns the read-decide-write lock (M12.22/M12.23).
* :class:`~app.risk.engine.RiskScoringEngine` — the scoring formula, which knows
  nothing about incidents at all (M12.13).
* :mod:`app.correlation.rules` — the explicit M12.12 rule set that decides
  whether two things are the same activity.

The four responsibilities, and why each sits here rather than in the registry:

**Rule evaluation.** The registry is injected with an *evaluator* — a closure
built per event — that computes the relationships between the incoming event and
one candidate incident, checks them against the rule set, and returns a verdict
or ``None``. Rules are policy; a bounded store should not hold policy. Injecting
the evaluator is also what lets the registry keep its lock across the whole
read-decide-write step without importing anything from this module (M12.23).

**The two gates before a merge.** A candidate is accepted only when it shares at
least one *anchoring* relationship — an identity overlap strong enough to
justify correlation on its own (M12.4/M12.6) — **and** the resulting
correlation confidence reaches the configured floor (M12.7). The first gate is
what stops two unrelated events being merged because they happened at the same
time; the second is what stops a weak overlap being treated as a real one. They
are separate checks on purpose, and either can reject.

**Scoring.** ``incident.to_risk_inputs()`` is the one bridge into the risk layer,
and the scorer passed to the registry reads the score back out of a
:class:`~app.risk.engine.RiskResult`. The registry stores incidents with their
score attached, so a stored incident is never inconsistent with its own
membership.

**Isolation (M12.25).** Neither a correlation failure nor a scoring failure may
stop alert processing or destroy the underlying alert. Every public entry point
here therefore returns a :class:`~app.correlation.registry.CorrelationOutcome`
rather than raising, and a failure is counted and reported in the outcome's
``error`` field. A malformed *input* — an alert with no observation time — is
handled the same way, because it arrives from the capture path exactly like a
well-formed one does.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from app.config.settings import Settings
from app.correlation.confidence import combine_relationships, meets_threshold
from app.correlation.event import CorrelationEvent, from_alert, from_finding
from app.correlation.identity import has_anchor, relationships_with_identity
from app.correlation.incident import CorrelatedIncident
from app.correlation.registry import (
    CorrelationOutcome,
    IncidentEvaluator,
    IncidentOrder,
    IncidentQuery,
    IncidentRegistry,
    IncidentVerdict,
)
from app.correlation.relationship import DEFAULT_ANCHOR_THRESHOLD, Relationship
from app.correlation.rules import evaluate_rules
from app.correlation.status import IncidentStatus
from app.correlation.window import CorrelationWindow
from app.risk.engine import RiskResult, RiskScoringEngine
from app.websockets.events import (
    publish_correlation_outcome,
    publish_incident_status,
)
from app.websockets.publisher import EventPublisher, ensure_publisher

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an eager import
    from app.alerts.alert import Alert
    from app.detection.finding import DetectionFinding

#: Lowest correlation confidence at which an event joins an existing incident
#: (M12.7). Mirrors ``settings.correlation_min_confidence``. Below it the event
#: starts its own incident instead of joining a weak one.
DEFAULT_MIN_CONFIDENCE = 0.5

#: Callable that writes an incident's risk score onto its member alerts and
#: returns how many rows it touched (M12.24). Injected rather than held, because
#: it touches the database and the engine deliberately does not (M12.23).
RiskPersistence = Callable[[CorrelatedIncident], int]


logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Groups related findings and alerts into scored incidents (M12.2).

    Args:
        window: The bounded correlation window (M12.5). Defaults to the
            documented window.
        registry: The incident store. Defaults to a registry with the documented
            bounds. Injected so a test can supply a deterministic clock.
        risk: The scoring engine. Defaults to the documented bounds.
        anchor_threshold: The strength a single relationship must reach on its
            own to justify correlation (M12.4/M12.6). Must be in ``[0, 1]``.
            Defaults to the documented threshold, at which the four identity
            relationships anchor and rule identity and time proximity do not.
        min_confidence: The correlation confidence floor (M12.7). Must be in
            ``[0, 1]``.
        risk_persistence: Optional writer that propagates an incident's score to
            its member alerts (M12.24). Called *after* the registry lock is
            released, so a slow disk cannot stall correlation (M12.23). Its
            failures are contained and counted.
        enabled: Whether correlation is switched on (M12.25). Exposed for the
            caller rather than enforced here, because the decision to call the
            engine belongs to the pipeline that owns the setting.
        clock: Time source in epoch seconds, used only for "as of now" scoring.

    Raises:
        ValueError: If a threshold is outside ``[0, 1]``. A threshold outside the
            unit interval could never be met (or always be met), which would
            silently disable the check it configures rather than fail it.
    """

    def __init__(
        self,
        *,
        window: CorrelationWindow | None = None,
        registry: IncidentRegistry | None = None,
        risk: RiskScoringEngine | None = None,
        anchor_threshold: float = DEFAULT_ANCHOR_THRESHOLD,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        risk_persistence: RiskPersistence | None = None,
        events: EventPublisher | None = None,
        enabled: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        for name, value in (
            ("anchor_threshold", anchor_threshold),
            ("min_confidence", min_confidence),
        ):
            number = float(value)
            if not 0.0 <= number <= 1.0:
                raise ValueError(f"{name} must be within 0..1")
        self._window = window if window is not None else CorrelationWindow()
        self._registry = registry if registry is not None else IncidentRegistry()
        self._risk = risk if risk is not None else RiskScoringEngine()
        self._anchor_threshold = float(anchor_threshold)
        self._min_confidence = float(min_confidence)
        self._risk_persistence = risk_persistence
        # Resolved once (M14.13), so no publish site tests it for ``None``. With no
        # publisher supplied this is a null sink, which is what keeps every
        # existing correlation test working unchanged.
        self._publisher = ensure_publisher(events)
        self._enabled = bool(enabled)
        self._clock = clock
        self._errors = 0
        self._persisted = 0
        self._persist_errors = 0

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        risk_persistence: RiskPersistence | None = None,
        events: EventPublisher | None = None,
        clock: Callable[[], float] = time.time,
    ) -> CorrelationEngine:
        """Build an engine from application settings (M12 configuration).

        This is the only place the layers' bounds meet the settings object, so
        the correlation model, the rule set and the scoring formula each stay
        free of configuration coupling. The registry and the engine share one
        clock, so an injected clock governs both retention and scoring.

        ``events`` is passed through rather than built here, for the same reason
        ``risk_persistence`` is: this classmethod configures the engine, it does
        not decide what the process's transport layer is (M14.13).
        """
        window_seconds = float(settings.correlation_window_seconds)
        return cls(
            window=CorrelationWindow(
                seconds=window_seconds,
                proximity_seconds=settings.correlation_proximity_seconds,
                max_span_seconds=window_seconds,
            ),
            registry=IncidentRegistry(
                max_incidents=settings.correlation_max_incidents,
                retention_seconds=settings.correlation_retention_seconds,
                max_members=settings.correlation_max_related_alerts,
                max_reasons=settings.correlation_max_correlation_reasons,
                clock=clock,
            ),
            risk=RiskScoringEngine.from_settings(settings),
            anchor_threshold=settings.correlation_min_anchor_strength,
            min_confidence=settings.correlation_min_confidence,
            risk_persistence=risk_persistence,
            events=events,
            enabled=settings.correlation_enabled,
            clock=clock,
        )

    # -- collaborators ------------------------------------------------------

    @property
    def window(self) -> CorrelationWindow:
        """Return the bounded correlation window in use (M12.5)."""
        return self._window

    @property
    def registry(self) -> IncidentRegistry:
        """Return the incident store (M12.22).

        Exposed so the read paths can reach the registry's full query surface
        without this class mirroring every method of it (M12.26).
        """
        return self._registry

    @property
    def risk(self) -> RiskScoringEngine:
        """Return the scoring engine in use (M12.13)."""
        return self._risk

    @property
    def enabled(self) -> bool:
        """Return whether the setting says correlation is switched on."""
        return self._enabled

    @property
    def anchor_threshold(self) -> float:
        """Return the configured anchor strength (M12.4/M12.6)."""
        return self._anchor_threshold

    @property
    def min_confidence(self) -> float:
        """Return the configured correlation confidence floor (M12.7)."""
        return self._min_confidence

    # -- ingestion (M12.2) --------------------------------------------------

    def correlate_event(self, event: CorrelationEvent) -> CorrelationOutcome:
        """Correlate one normalized event, never raising (M12.25).

        The registry already contains its own failures; this wraps the call so a
        fault in the *engine's* own collaborators — a relationship computation, a
        scorer — is contained too, and so the risk write (M12.24) happens outside
        the registry's lock (M12.23).

        Returns:
            The outcome. ``error`` is set when anything failed; the event is
            simply not correlated in that case, and the alert it came from is
            untouched.
        """
        try:
            outcome = self._registry.ingest(
                event,
                window=self._window,
                evaluator=self._evaluator_for(event),
                title_factory=self._title_for,
                scorer=self._score,
            )
        except Exception:  # noqa: BLE001 - correlation must never stop capture
            self._errors += 1
            logger.exception(
                "Correlation failed for event %s; alert processing continues",
                event.event_id,
            )
            return CorrelationOutcome(
                event_id=str(event.event_id),
                rule_id=str(event.rule_id),
                error="Correlation failed",
            )
        if outcome.ok and not outcome.duplicate:
            self._persist_incident(outcome.incident)
        # Announced after the registry's lock was released, like the risk write
        # above. The helper publishes only for a step that opened an incident or
        # joined one: a duplicate (M12.11) and a contained error changed nothing,
        # and announcing them would be a notification about no change (M14.12).
        publish_correlation_outcome(self._publisher, outcome)
        return outcome

    def correlate_finding(
        self,
        finding: DetectionFinding,
        *,
        connection_id: str | None = None,
    ) -> CorrelationOutcome:
        """Correlate an M10 detection finding (M12.3).

        Args:
            finding: The finding to normalize and correlate.
            connection_id: An optional M9 conversation reference. M10 findings
                carry none, so this is supplied only when the caller resolved one.
        """
        try:
            event = from_finding(finding, connection_id=connection_id)
        except Exception:  # noqa: BLE001 - a bad finding must not stop capture
            self._errors += 1
            logger.exception("Could not normalize a detection finding")
            return CorrelationOutcome(
                event_id=str(getattr(finding, "finding_id", "")),
                rule_id=str(getattr(finding, "rule_id", "")),
                error="Could not normalize the finding",
            )
        return self.correlate_event(event)

    def correlate_alert(
        self, alert: Alert, *, timestamp: float | None = None
    ) -> CorrelationOutcome:
        """Correlate an M11 alert (M12.3).

        Args:
            alert: The runtime alert to normalize and correlate.
            timestamp: Epoch seconds to date the event. Defaults to the alert's
                own observation time.

        Returns:
            The outcome. An alert that cannot be timed produces an error outcome
            rather than raising: correlation is about time, so an untimed event
            is not correlated, but the alert itself is left intact (M12.25).
        """
        try:
            event = from_alert(alert, timestamp=timestamp)
        except Exception:  # noqa: BLE001 - an unusable alert must not stop capture
            self._errors += 1
            logger.warning(
                "Could not time an alert for correlation; it stays uncorrelated",
                exc_info=True,
            )
            return CorrelationOutcome(
                event_id=f"alert:{getattr(alert, 'alert_id', '')}",
                rule_id=str(getattr(alert, "rule_id", "")),
                error="Could not normalize the alert",
            )
        return self.correlate_event(event)

    def correlate_findings(
        self,
        findings: Iterable[DetectionFinding],
        *,
        connection_id: str | None = None,
    ) -> list[CorrelationOutcome]:
        """Correlate several findings in order, one outcome each (M12.2)."""
        return [
            self.correlate_finding(finding, connection_id=connection_id)
            for finding in findings
        ]

    def correlate_alerts(
        self, alerts: Iterable[Alert]
    ) -> list[CorrelationOutcome]:
        """Correlate several alerts in order, one outcome each (M12.2)."""
        return [self.correlate_alert(alert) for alert in alerts]

    # -- reads (M12.2/M12.26) ----------------------------------------------

    def get_incidents(
        self, query: IncidentQuery | None = None
    ) -> list[CorrelatedIncident]:
        """Return one bounded page of incidents matching ``query`` (M12.26)."""
        return self._registry.list_incidents(query)

    def get_incident(self, incident_id: str) -> CorrelatedIncident | None:
        """Return one incident by identifier, or ``None`` when unknown."""
        return self._registry.get(incident_id)

    def count_incidents(self, query: IncidentQuery | None = None) -> int:
        """Return how many incidents match ``query`` (M12.26)."""
        return self._registry.count_incidents(query)

    def recent_incidents(
        self, *, limit: int = 100
    ) -> list[CorrelatedIncident]:
        """Return the most recently active incidents (M12.26)."""
        return self._registry.recent_incidents(limit=limit)

    def open_incidents(self, *, limit: int = 100) -> list[CorrelatedIncident]:
        """Return incidents still needing attention, riskiest first (M12.26)."""
        return self._registry.open_incidents(limit=limit)

    def incidents_for_device(
        self, device_id: str, *, limit: int = 100
    ) -> list[CorrelatedIncident]:
        """Return incidents involving one M8 device identity (M12.26)."""
        return self._registry.incidents_for_device(device_id, limit=limit)

    def incidents_for_source(
        self, source_ip: str, *, limit: int = 100
    ) -> list[CorrelatedIncident]:
        """Return incidents from one source address (M12.26)."""
        return self._registry.incidents_for_source(source_ip, limit=limit)

    def incidents_for_rule(
        self, rule_id: str, *, correlation: bool = False, limit: int = 100
    ) -> list[CorrelatedIncident]:
        """Return incidents a rule contributed to (M12.26).

        Args:
            rule_id: The rule to match.
            correlation: When True, match the M12.12 correlation rule that grouped
                the incident rather than a detector rule.
        """
        return self._registry.incidents_for_rule(
            rule_id, correlation=correlation, limit=limit
        )

    def incidents_by_risk(
        self,
        *,
        min_risk_score: int = 0,
        max_risk_score: int | None = None,
        limit: int = 100,
    ) -> list[CorrelatedIncident]:
        """Return incidents inside a risk-score range, highest first (M12.26)."""
        return self._registry.incidents_by_risk(
            min_risk_score=min_risk_score,
            max_risk_score=max_risk_score,
            limit=limit,
        )

    def incidents_in_range(
        self,
        *,
        since: float,
        until: float | None = None,
        limit: int = 100,
    ) -> list[CorrelatedIncident]:
        """Return incidents whose extent overlaps a time range (M12.26)."""
        return self._registry.incidents_in_range(
            since=since, until=until, limit=limit
        )

    def highest_risk_incidents(
        self, *, limit: int = 100
    ) -> list[CorrelatedIncident]:
        """Return every held incident ordered by risk, highest first (M12.26)."""
        return self._registry.list_incidents(
            IncidentQuery(limit=limit, order=IncidentOrder.RISK)
        )

    # -- expiration and lifecycle (M12.2/M12.9/M12.22) ----------------------

    def expire_old_context(
        self, *, now: float | None = None, retention_seconds: float | None = None
    ) -> int:
        """Drop incidents with no activity inside the retention age (M12.22).

        Args:
            now: Current time in epoch seconds. Defaults to the engine's clock.
            retention_seconds: Override the configured age for this sweep.

        Returns:
            How many incidents were dropped. The alerts they referenced are
            untouched: only the correlation context is released.
        """
        return self._registry.expire_old_context(
            now=now, retention_seconds=retention_seconds
        )

    def set_status(
        self,
        incident_id: str,
        status: IncidentStatus | str,
        *,
        updated_at: float | None = None,
    ) -> CorrelatedIncident | None:
        """Move an incident to a new lifecycle state (M12.9).

        Returns:
            The updated incident, or ``None`` when the id is unknown.

        Raises:
            InvalidIncidentTransition: If the move is not allowed. A terminal
                incident stays terminal — M12 asks for no reopen.
        """
        updated = self._registry.set_status(
            incident_id, status, updated_at=updated_at
        )
        if updated is not None:
            # Announced after the registry accepted the move, so a client is never
            # told about a transition that was refused. An unknown id returns
            # ``None`` and announces nothing (M14.12).
            publish_incident_status(self._publisher, updated)
        return updated

    def rescore(self, incident_id: str) -> CorrelatedIncident | None:
        """Recompute and store one incident's risk score (M12.13).

        Used when a score should reflect *now* rather than the incident's own last
        activity — after a lifecycle change, or on demand. Ingestion scores
        inline, so this is the explicit path.

        Returns:
            The rescored incident, or ``None`` when the id is unknown.
        """
        incident = self._registry.get(incident_id)
        if incident is None:
            return None
        result = self._score(incident)
        updated = self._registry.apply_risk(
            incident.incident_id, score=result.score, band=result.band
        )
        if updated is not None:
            self._persist_incident(updated)
        return updated

    def reset(self) -> None:
        """Clear the incident store and every counter (M12.22).

        Runtime state only: no database row is touched, so the alerts and
        findings the incidents referred to are unaffected. The scoring engine's
        counters are cleared too — they are diagnostics, and a reset that left
        some counters behind would make the next ``stats()`` read as a mixture of
        two runs.
        """
        self._registry.reset()
        self._risk.reset()
        self._errors = 0
        self._persisted = 0
        self._persist_errors = 0

    def stats(self) -> dict[str, object]:
        """Return counters, configuration and store statistics (M12.34).

        Diagnostics only, read at one instant, and incapable of affecting a
        correlation or a score. It reports the *effective* configuration — the
        window, the two thresholds, the store's bounds — so a baseline run and a
        re-run can be compared without reading the settings object as well.
        """
        return {
            "enabled": self._enabled,
            "errors": self._errors,
            "persisted_alerts": self._persisted,
            "persist_errors": self._persist_errors,
            "window_seconds": float(self._window.seconds),
            "proximity_seconds": float(self._window.proximity_seconds),
            "max_span_seconds": float(
                self._window.max_span_seconds or self._window.seconds
            ),
            "anchor_threshold": self._anchor_threshold,
            "min_confidence": self._min_confidence,
            "risk": self._risk.stats(),
            "incidents": self._registry.stats(),
        }

    # -- rule evaluation (M12.4/M12.12) ------------------------------------

    def _evaluator_for(self, event: CorrelationEvent) -> IncidentEvaluator:
        """Return the rule evaluator for one incoming event (M12.12).

        A closure rather than a method, because the registry's evaluator is handed
        a candidate incident and nothing else, while a decision needs *both* sides
        of the comparison. Building it per event keeps the incoming event out of
        shared state, so two threads correlating different events cannot observe
        each other's event (M12.23).
        """

        def evaluate(incident: CorrelatedIncident) -> IncidentVerdict | None:
            return self._evaluate_event_against(event, incident)

        return evaluate

    def _evaluate_event_against(
        self, event: CorrelationEvent, incident: CorrelatedIncident
    ) -> IncidentVerdict | None:
        """Decide whether one event belongs to one incident (M12.4/M12.12).

        Two gates, both required, and they answer different questions:

        1. **Is there an anchor?** At least one relationship must be strong enough
           on its own to justify correlation. This is M12.4's "do not merge events
           simply because they occurred close together": two events that share
           only a timestamp produce no anchor, so they are never merged.
        2. **Is the rule set satisfied, and is the confidence high enough?** The
           explicit M12.12 rules decide *which* relationship pattern counts, and
           M12.7's floor decides whether the resulting confidence is strong enough
           to act on.

        Returns:
            ``(rule_id, relationships, reasons)`` when the event belongs here, or
            ``None`` when it does not. ``None`` is the ordinary answer for
            unrelated activity, and it is what makes the engine open a new
            incident instead of forcing a merge.
        """
        relationships: list[Relationship] = relationships_with_identity(
            event,
            incident.identity,
            reference_time=incident.last_seen,
            window=self._window,
        )
        if not relationships:
            return None
        if not has_anchor(relationships, threshold=self._anchor_threshold):
            return None
        match = evaluate_rules(
            relationships,
            event_rule_id=event.rule_id,
            incident_rules=incident.rule_set(),
            incident_event_count=incident.event_count,
            anchor_threshold=self._anchor_threshold,
        )
        if match is None:
            return None
        confidence = combine_relationships(relationships)
        if not meets_threshold(confidence, self._min_confidence):
            return None
        return match.rule_id, tuple(relationships), match.reasons

    # -- scoring (M12.13/M12.15) -------------------------------------------

    def _score(self, incident: CorrelatedIncident) -> RiskResult:
        """Score one incident as of now, for the registry to store (M12.13).

        The scorer injected into the registry. It reads only the incident's
        bounded facts, through :meth:`CorrelatedIncident.to_risk_inputs`, stamps
        the current time for the recency term (M12.15), and leaves ML unavailable
        (M12.18). Never raises: the risk engine contains its own failures, and the
        registry contains anything that escapes this (M12.25).
        """
        return self._risk.score(
            incident.to_risk_inputs(now=float(self._clock()))
        )

    def _title_for(self, event: CorrelationEvent) -> str:
        """Return the title for an incident ``event`` opens (M12.8).

        An incident wears the name of the detector that opened it, so it reads as
        "Port scan" rather than as a bare identifier. When a detector supplied no
        name, the rule id is qualified by where the event came from, so the same
        rule seen as a finding and as an alert is still distinguishable.
        """
        label = str(event.title or "").strip()
        if label:
            return label
        return f"{event.rule_id} ({event.kind.value})"

    # -- risk persistence (M12.24) -----------------------------------------

    def _persist_incident(self, incident: CorrelatedIncident | None) -> None:
        """Write an incident's risk score onto its member alerts (M12.24).

        Called *after* the registry lock has been released, so a slow database
        cannot stall correlation for any other thread (M12.23), and never raises:
        a persistence problem must not destroy a correlation, and it must not stop
        the capture path (M12.25). Failures are counted and logged, and the
        incident keeps its score in memory regardless.
        """
        if incident is None or self._risk_persistence is None:
            return
        try:
            written = int(self._risk_persistence(incident))
        except Exception:  # noqa: BLE001 - persistence must never stop capture
            self._persist_errors += 1
            logger.exception(
                "Could not persist the risk score for incident %s",
                incident.incident_id,
            )
            return
        self._persisted += max(written, 0)


__all__ = [
    "CorrelationEngine",
    "DEFAULT_MIN_CONFIDENCE",
    "RiskPersistence",
]
