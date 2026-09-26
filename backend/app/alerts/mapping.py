"""Detection-to-alert mapping: which M10 findings become alerts (M11.8).

This is the **only** place that decides what a detector's finding means as an
alert. A finding says *what was observed*; this table says whether that
observation is alertable, what the alert is called, and how serious it is. There
is deliberately no inference anywhere else: a rule that is not listed here
produces no alert at all, and a detector can never choose its own severity.

The five entries cover exactly the five detectors M10 implements. Nothing is
listed for functionality that does not exist — a table entry for an unimplemented
detector would be a promise M11 cannot keep.

===================  ================  ===========  ==================
rule_id              alert title       severity     confidence source
===================  ================  ===========  ==================
``port_scan``        Port Scan         high         M10 finding (0..1)
``syn_flood``        SYN Flood         critical     M10 finding (0..1)
``icmp_flood``       ICMP Flood        medium       M10 finding (0..1)
``internal_scan``    Internal Scan     high         M10 finding (0..1)
``high_bandwidth``   High Bandwidth    high         M10 finding (0..1)
===================  ================  ===========  ==================

Severity is independent of confidence (M11.5): the severity column is fixed per
rule, while the confidence column is whatever M10 measured for *this* finding.
Confidence is never invented — when a finding is missing a usable confidence the
service falls back to :data:`app.detection.finding.MIN_CONFIDENCE`, the value
M10 documents for evidence that only just met its threshold.

Severity is *not* a risk score (M11.4). Risk scoring needs the historical and
correlational context that M12 owns, and no risk field exists in this package.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.alerts.severity import AlertSeverity

#: Where a value comes from, so the provenance of every alert field is explicit.
CONFIDENCE_SOURCE_FINDING = "detection finding (M10.15)"


@dataclass(frozen=True)
class RuleAlertMapping:
    """How one detection rule becomes an alert (M11.8).

    Attributes:
        rule_id: The detector's stable identifier, as it appears on a finding.
        title: The alert title. Stable per rule, so alerts are groupable.
        severity: The alert severity for this rule. Fixed, never invented.
        confidence_source: Human-readable provenance of the alert's confidence.
    """

    rule_id: str
    title: str
    severity: AlertSeverity
    confidence_source: str = CONFIDENCE_SOURCE_FINDING


def _mapping(rule_id: str, title: str, severity: AlertSeverity) -> RuleAlertMapping:
    """Build a mapping entry for one detector."""
    return RuleAlertMapping(rule_id=rule_id, title=title, severity=severity)


#: The alertable detection rules, keyed by the detector's ``rule_id`` (M11.8).
#:
#: Severity is aligned with the ``detection_rules`` catalogue the M2 seed data
#: defines (``high``/``critical``/``medium``/``high``/``high`` for these five
#: behaviours), so the alert layer and the rule catalogue cannot drift apart.
RULE_MAPPINGS: dict[str, RuleAlertMapping] = {
    entry.rule_id: entry
    for entry in (
        _mapping("port_scan", "Port Scan", AlertSeverity.HIGH),
        _mapping("syn_flood", "SYN Flood", AlertSeverity.CRITICAL),
        _mapping("icmp_flood", "ICMP Flood", AlertSeverity.MEDIUM),
        _mapping("internal_scan", "Internal Scan", AlertSeverity.HIGH),
        _mapping("high_bandwidth", "High Bandwidth", AlertSeverity.HIGH),
    )
}

#: Every rule id that can produce an alert, in a deterministic order.
SUPPORTED_RULE_IDS: tuple[str, ...] = tuple(RULE_MAPPINGS)


def mapping_for_rule(rule_id: str | None) -> RuleAlertMapping | None:
    """Return the alert mapping for a detector, or ``None`` when it has none.

    ``None`` is the answer for an unknown, empty or missing rule id: an
    unrecognised finding is not alertable, which is exactly the behaviour M11.26
    requires ("unsupported finding does not create alert"). It is not an error,
    because M10 may legitimately gain a detector before M11 gains its mapping.
    """
    if not rule_id:
        return None
    return RULE_MAPPINGS.get(str(rule_id).strip())


def is_alertable_rule(rule_id: str | None) -> bool:
    """Return True when a finding from ``rule_id`` would produce an alert."""
    return mapping_for_rule(rule_id) is not None
