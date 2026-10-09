"""The runtime half of the threat block: retained findings and incident links (M16.6).

Two things the persisted alert table cannot answer, because neither is stored:

**What the detectors observed in the period.** M10 retains findings in a bounded
in-process history and never persists them (a finding is an observation, not an
entity). So the windowed view of them is built by asking the engine for the
findings it still holds inside the period — the history's own cap bounds the
work, so this cannot grow with the capture.

**How alerts and incidents refer to each other.** An incident names the alerts it
grouped, and M12 keeps incidents in memory, so the relationship is reported from
the references that already exist rather than derived.

Both builders are read-only and keep the concepts M16.6 separates apart: a
finding is not an alert, an alert is not an incident, and the confidence here is
M10's own evidence confidence — not a severity (findings have none) and not a
risk score (M12 owns that, and reads it from the incident registry, not from
here).
"""

from __future__ import annotations

from collections.abc import Iterable

from app.analytics.distributions import (
    CONFIDENCE_RANGE_LABELS,
    confidence_range_label,
)
from app.analytics.window import AnalyticsWindow
from app.correlation.incident import CorrelatedIncident
from app.detection.engine import DetectionEngine
from app.detection.finding import DetectionFinding
from app.schemas.analytics import (
    FindingRuleCount,
    FindingsSummary,
    IncidentLinkage,
)

#: Scale between a finding's confidence and the project's documented 0-100
#: tiling. A finding carries ``confidence`` as a ``0.0..1.0`` fraction (M10.15);
#: the ranges it is binned into are the one 0-100 tiling the project documents
#: (M12.27), so the value is scaled purely to place it there. No threshold is
#: invented, and the label stays numeric rather than borrowing a risk band's name.
_CONFIDENCE_SCALE = 100.0


def build_findings_summary(
    detections: DetectionEngine, window: AnalyticsWindow
) -> FindingsSummary:
    """Return the period's retained findings, by rule and by confidence range.

    Args:
        detections: The M10 engine, read through its own bounded history.
        window: The resolved window, applied with the same inclusive/exclusive
            rule M10's own finding query uses, so the two agree exactly.
    """
    findings = detections.get_findings(since=window.since, until=window.until)
    return FindingsSummary(
        retained=detections.get_retained_finding_count(),
        in_window=len(findings),
        mean_confidence=_mean_confidence(findings),
        by_confidence_range=_by_confidence_range(findings),
        by_rule=_by_rule(findings),
    )


def build_incident_linkage(
    incidents: Iterable[CorrelatedIncident],
) -> IncidentLinkage:
    """Return the alert-to-incident references M12 already holds (M16.6).

    Distinct alert ids are counted rather than links, so an alert two incidents
    both reference is one alert. The registry is bounded (M12.22), so the walk is
    bounded too.
    """
    total = 0
    with_alerts = 0
    referenced: set[int] = set()
    for incident in incidents:
        total += 1
        if incident.alert_ids:
            with_alerts += 1
            referenced.update(int(alert_id) for alert_id in incident.alert_ids)
    return IncidentLinkage(
        incidents_total=total,
        incidents_with_alerts=with_alerts,
        alerts_in_incidents=len(referenced),
    )


def _mean_confidence(findings: list[DetectionFinding]) -> float | None:
    """Return the mean confidence of the findings, or ``None`` when there are none.

    ``None`` rather than ``0.0``: a period with no finding has no confidence to
    average, and zero would be a claim that every observation was worthless
    (M16.8).
    """
    if not findings:
        return None
    return sum(float(finding.confidence) for finding in findings) / float(
        len(findings)
    )


def _by_confidence_range(findings: list[DetectionFinding]) -> dict[str, int]:
    """Return finding counts per documented confidence range (M16.6).

    Zero-filled over every range so a client renders fixed rows, and derived from
    :data:`~app.analytics.distributions.CONFIDENCE_RANGES` rather than re-spelled,
    so the alert histogram and the finding histogram share their boundaries.
    """
    counts = {label: 0 for label in CONFIDENCE_RANGE_LABELS}
    for finding in findings:
        label = confidence_range_label(float(finding.confidence) * _CONFIDENCE_SCALE)
        counts[label] = counts.get(label, 0) + 1
    return counts


def _by_rule(findings: list[DetectionFinding]) -> list[FindingRuleCount]:
    """Return finding counts per detector, busiest first.

    A finding carries both the rule's stable id and its display name, so the
    summary can name the detector without resolving it against the rule table —
    which matters because a finding survives its rule being disabled or removed
    from the catalogue. The tie-break is the rule id, so equal counts order the
    same way on every request (M13.24).
    """
    counted: dict[str, FindingRuleCount] = {}
    for finding in findings:
        entry = counted.get(finding.rule_id)
        if entry is None:
            counted[finding.rule_id] = FindingRuleCount(
                rule_id=finding.rule_id,
                rule_name=finding.rule_name,
                findings=1,
            )
            continue
        entry.findings += 1
    return sorted(
        counted.values(), key=lambda entry: (-entry.findings, entry.rule_id)
    )


__all__ = [
    "build_findings_summary",
    "build_incident_linkage",
]
