"""Alert engine for NetWatch AI (M11).

This package turns the observations M10 publishes into **alerts**: a conclusion
about behaviour, with a severity, a lifecycle, a deduplication identity and the
evidence that justifies it. The flow is:

    M10 finding ──► mapping ──► deduplication ──► evidence ──► alerts row
                        │             │               │
                        ▼             ▼               ▼
                   severity/title  correlation_key  alert_evidence rows

An alert is deliberately *not* a finding. A finding says what was measured; an
alert says that the measurement is worth a human's attention, how serious it is,
and what supported it. Severity and confidence are separate (M11.5), severity is
never invented by a detector (M11.4), and risk scoring is M12's concern — no risk
field exists anywhere in this package.

The layers are:

* :mod:`app.alerts.severity` / :mod:`app.alerts.status` — the vocabularies and the
  validated lifecycle;
* :mod:`app.alerts.mapping` — the documented rule → alert table (M11.8);
* :mod:`app.alerts.dedup` — the key and the bounded window (M11.9/M11.10);
* :mod:`app.alerts.evidence` / :mod:`app.alerts.evidence_builder` — what supports
  an alert, bounded and reference-based (M11.11-M11.15);
* :mod:`app.alerts.service` / :mod:`app.alerts.queries` — the write and read
  paths;
* :mod:`app.alerts.engine` — the pipeline consumer (M11.21).

Design: ``docs/15_M11_Alert_Engine_Design.md``.
"""

from app.alerts.alert import Alert
from app.alerts.dedup import (
    DeduplicationKey,
    DeduplicationWindow,
    MAX_DEDUP_WINDOW_SECONDS,
)
from app.alerts.engine import AlertEngine
from app.alerts.evidence import (
    AlertEvidenceRecord,
    EvidenceCollection,
    EvidenceRole,
    EvidenceType,
)
from app.alerts.mapping import RULE_MAPPINGS, RuleAlertMapping, mapping_for_rule
from app.alerts.queries import AlertDetail, AlertPage, AlertQueries, AlertQuery
from app.alerts.resolvers import FindingResolvers, ResolutionLimits
from app.alerts.service import AlertCounters, AlertOutcome, AlertService
from app.alerts.severity import AlertSeverity
from app.alerts.status import (
    AlertStatus,
    InvalidStatusTransition,
    allowed_targets,
    validate_transition,
)

__all__ = [
    "Alert",
    "AlertCounters",
    "AlertDetail",
    "AlertEngine",
    "AlertEvidenceRecord",
    "AlertOutcome",
    "AlertPage",
    "AlertQueries",
    "AlertQuery",
    "AlertService",
    "AlertSeverity",
    "AlertStatus",
    "DeduplicationKey",
    "DeduplicationWindow",
    "EvidenceCollection",
    "EvidenceRole",
    "EvidenceType",
    "FindingResolvers",
    "InvalidStatusTransition",
    "MAX_DEDUP_WINDOW_SECONDS",
    "RULE_MAPPINGS",
    "ResolutionLimits",
    "RuleAlertMapping",
    "allowed_targets",
    "get_alert_engine",
    "mapping_for_rule",
    "reset_alert_engine",
    "validate_transition",
]

# Shared singleton used by the application at runtime.
_alert_engine: AlertEngine | None = None


def _build_default_engine() -> AlertEngine:
    """Construct the process-wide alert engine from application settings (M11.23).

    Imports are local so importing this package never opens a database, builds a
    connection tracker or reads the environment as a side effect — which is what
    keeps the pure modules in it (severity, status, mapping, dedup) importable in
    isolation.

    The resolver set is wired to the M7 packet repository, the M9 connection
    tracker and the M2 rule catalogue, each through a session-scoped adapter, so
    evidence resolution works from the capture thread without holding a session.
    """
    from app.config.settings import settings
    from app.connections.manager import get_connection_tracker
    from app.persistence.session_factory import app_session_factory
    from app.alerts.resolvers import SessionPacketSource, SessionRuleSource

    resolvers = FindingResolvers(
        packet_source=SessionPacketSource(app_session_factory),
        connection_source=get_connection_tracker(),
        rule_source=SessionRuleSource(app_session_factory),
        limits=ResolutionLimits(
            max_packets=settings.alert_packet_evidence_max_packets,
            packet_window_seconds=settings.alert_packet_evidence_window_seconds,
            max_connections=settings.alert_connection_evidence_max,
        ),
    )
    service = AlertService(
        session_factory=app_session_factory,
        resolvers=resolvers,
        dedup_window_seconds=settings.alert_dedup_window_seconds,
        max_evidence=settings.alert_max_evidence_per_alert,
        packet_evidence_enabled=settings.alert_packet_evidence_enabled,
    )
    return AlertEngine(service, enabled=settings.alerts_enabled)


def get_alert_engine() -> AlertEngine:
    """Return the shared alert engine, building it on first use (M11.23)."""
    global _alert_engine
    if _alert_engine is None:
        _alert_engine = _build_default_engine()
    return _alert_engine


def reset_alert_engine() -> None:
    """Drop the shared engine so the next call rebuilds it (used by tests).

    Stored alerts are untouched: this discards the in-memory engine, not the
    security record.
    """
    global _alert_engine
    _alert_engine = None
