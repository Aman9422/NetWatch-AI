"""Correlation and risk scoring for NetWatch AI (M12).

This package turns the alerts M11 raises into **correlated incidents** with a
bounded **risk score**, while keeping three numbers that are easy to confuse
rigorously apart (M12.16):

    alert confidence        how sure a detector was of its own observation
    correlation confidence  how sure correlation is that two things are related
    risk score              how much attention the resulting incident deserves

The flow:

    M10 finding ─┐
                 ├─► CorrelationEvent ─► rules ─► CorrelatedIncident ─► RiskScore
    M11 alert  ──┘                        │              │
                                          │              └─► alerts.risk_score (M12.24)
                                          └─► relationships ─► confidence ─► reasons

The layers, bottom up:

* :mod:`app.correlation.window` — the bounded time window and the rule that an
  incident only accepts an event inside its span (M12.5).
* :mod:`app.correlation.relationship` — the six documented relationships, their
  strengths, and which of them may anchor a correlation on their own
  (M12.6/M12.7).
* :mod:`app.correlation.identity` — the identity index an incident accumulates,
  and the comparison that turns two identities into relationships (M12.4).
* :mod:`app.correlation.confidence` — combining relationships into one bounded
  correlation confidence (M12.7).
* :mod:`app.correlation.rules` — the four explicit M12.12 rules, as data.
* :mod:`app.correlation.event` — the normalized input, built from a finding or an
  alert (M12.3).
* :mod:`app.correlation.incident` — the immutable incident model (M12.8).
* :mod:`app.correlation.status` — the four-state lifecycle (M12.9).
* :mod:`app.risk` — the scoring formula, from :class:`RiskInputs` to a bounded
  score with its bands (M12.13-M12.21).
* :mod:`app.correlation.registry` — the bounded, lock-protected store, its
  queries and its lifecycle transitions (M12.22/M12.23/M12.26).
* :mod:`app.correlation.persistence` — writing an incident's score back onto its
  alerts (M12.24).
* :mod:`app.correlation.engine` — the pipeline consumer that ties them together
  (M12.2/M12.25).

What this package deliberately does **not** contain: ML or AI analysis (M12.18),
asset criticality the application has no configured source for (M12.19),
automatic blocking, WebSockets, or any incident-response automation. Correlation
groups and prioritises; it never acts.

Nothing here touches a database at import time. The shared engine is built on
first use, and the module-level names are all pure.

Design: ``docs/16_M12_Correlation_Design.md``.
"""

from app.correlation.confidence import (
    combine_relationships,
    describe_confidence,
    meets_threshold,
)
from app.correlation.engine import (
    DEFAULT_MIN_CONFIDENCE,
    CorrelationEngine,
    RiskPersistence,
)
from app.correlation.event import (
    CorrelationEvent,
    EventKind,
    alert_event_id,
    finding_event_id,
    from_alert,
    from_finding,
)
from app.correlation.identity import (
    IdentityIndex,
    anchor_relationships,
    has_anchor,
    identity_relationships,
    relationships_between,
    relationships_with_identity,
)
from app.correlation.incident import (
    DEFAULT_MAX_MEMBERS,
    DEFAULT_MAX_REASONS,
    MAX_IDENTITY_ENTITIES,
    CorrelatedIncident,
    incident_id_for,
)
from app.correlation.persistence import IncidentRiskWriter
from app.correlation.registry import (
    CorrelationCounters,
    CorrelationOutcome,
    IncidentOrder,
    IncidentQuery,
    IncidentRegistry,
)
from app.correlation.relationship import (
    ANCHOR_RELATIONSHIPS,
    DEFAULT_ANCHOR_THRESHOLD,
    RELATIONSHIP_WEIGHTS,
    Relationship,
    RelationshipKind,
    describe_relationships,
)
from app.correlation.rules import (
    DEFAULT_RULES,
    SCAN_SEQUENCE_RULES,
    CorrelationMatch,
    CorrelationRule,
    describe_rules,
    evaluate_rules,
    rule_by_id,
    rule_ids,
)
from app.correlation.status import (
    ACTIVE_STATUSES,
    TERMINAL_STATUSES,
    IncidentStatus,
    InvalidIncidentTransition,
    allowed_targets,
    is_active,
    is_terminal,
    validate_transition,
)
from app.correlation.window import CorrelationWindow

__all__ = [
    "ACTIVE_STATUSES",
    "ANCHOR_RELATIONSHIPS",
    "CorrelatedIncident",
    "CorrelationCounters",
    "CorrelationEngine",
    "CorrelationEvent",
    "CorrelationMatch",
    "CorrelationOutcome",
    "CorrelationRule",
    "CorrelationWindow",
    "DEFAULT_ANCHOR_THRESHOLD",
    "DEFAULT_MAX_MEMBERS",
    "DEFAULT_MAX_REASONS",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_RULES",
    "EventKind",
    "IdentityIndex",
    "IncidentOrder",
    "IncidentQuery",
    "IncidentRegistry",
    "IncidentRiskWriter",
    "IncidentStatus",
    "InvalidIncidentTransition",
    "MAX_IDENTITY_ENTITIES",
    "RELATIONSHIP_WEIGHTS",
    "Relationship",
    "RelationshipKind",
    "RiskPersistence",
    "SCAN_SEQUENCE_RULES",
    "TERMINAL_STATUSES",
    "alert_event_id",
    "allowed_targets",
    "anchor_relationships",
    "combine_relationships",
    "describe_confidence",
    "describe_relationships",
    "describe_rules",
    "evaluate_rules",
    "finding_event_id",
    "from_alert",
    "from_finding",
    "get_correlation_engine",
    "has_anchor",
    "identity_relationships",
    "incident_id_for",
    "is_active",
    "is_terminal",
    "meets_threshold",
    "relationships_between",
    "relationships_with_identity",
    "reset_correlation_engine",
    "rule_by_id",
    "rule_ids",
    "validate_transition",
]

#: The shared engine used by the application at runtime.
_correlation_engine: CorrelationEngine | None = None


def _build_default_engine() -> CorrelationEngine:
    """Construct the process-wide correlation engine from settings (M12.25).

    Imports are local so that importing this package never reads the environment,
    opens a database or wires a session factory as a side effect — which is what
    keeps the pure modules in it (window, relationship, identity, confidence,
    rules, status) importable in isolation and in tests.

    The risk writer is wired to the application session factory, so an incident's
    score reaches ``alerts.risk_score`` (M12.24). It is skipped entirely when the
    setting disables it, in which case correlation still runs and incidents still
    carry their scores in memory — only the column is left alone.
    """
    from app.config.settings import settings
    from app.persistence.session_factory import app_session_factory
    from app.websockets import get_event_publisher

    writer: IncidentRiskWriter | None = None
    if settings.correlation_risk_persistence_enabled:
        writer = IncidentRiskWriter(app_session_factory)
    return CorrelationEngine.from_settings(
        settings,
        risk_persistence=writer,
        # The live stream (M14.13). Injected rather than reached for, so the
        # engine stays constructible with no publisher at all in a test. Every
        # publish call is contained and does nothing while the layer is disabled
        # (M14.14), so no existing behaviour changes.
        events=get_event_publisher(),
    )


def get_correlation_engine() -> CorrelationEngine:
    """Return the shared correlation engine, building it on first use (M12.25)."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = _build_default_engine()
    return _correlation_engine


def reset_correlation_engine() -> None:
    """Drop the shared engine so the next call rebuilds it (used by tests).

    The alerts the incidents referred to are untouched: this discards the
    in-memory correlation context, not the security record.
    """
    global _correlation_engine
    _correlation_engine = None
