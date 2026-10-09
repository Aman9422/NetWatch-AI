"""Stored alerts, read for the threat analytics block (M16.6).

The one security record this system persists with a timestamp is ``alerts``, so
it is the only place a *windowed* security breakdown can come from. The M13
threat block reports what M10's counters, M11's read service and M12's registry
hold right now; this block reports what the alert table holds over an explicit
period. Both are reported, side by side, because live counters reset with the
process and stored rows do not (M16.6).

The three distinctions M16.6 asks to be kept apart are kept apart in three
fields, each read from the milestone that owns it:

* ``by_severity`` — M11's evidence-based judgement of how serious the behaviour
  is (``app.alerts.severity``);
* ``by_confidence_range`` — how strongly M11 believed its own evidence, binned
  into the project's one documented 0–100 tiling (``app.risk.bands``);
* ``by_risk_band`` — M12's prioritisation metric, banded by the same tiling.

Nothing here computes a score. ``risk_score`` is the column M12 wrote; an alert
M12 has not correlated still carries M11's placeholder ``0`` and is therefore
banded ``minimal``, which the schema documents as "not yet scored" rather than
"assessed as minimal". The live incident block is where a scored judgement is
reported, and it is not duplicated here.

The rule ranking groups by the leading component of the deduplication key
(M11.9), which is the only place a *string* rule id is recoverable — the
``detection_rules`` foreign key is ``NULL`` whenever the catalogue holds no row
for the detector. Alerts with no key cannot be ranked and their count is reported
by ``without_rule_key`` instead, so the ranking's omission is a stated fact
rather than a silent gap.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.alerts.severity import SEVERITY_VALUES
from app.alerts.status import STORED_STATUS_VALUES
from app.analytics.alert_queries import MAX_RULES, AlertAnalytics
from app.analytics.distributions import CONFIDENCE_RANGE_LABELS
from app.analytics.window import AnalyticsWindow, iso_from_epoch
from app.risk.bands import BAND_RANGES
from app.schemas.analytics import AlertSeriesPoint, StoredAlertsData, ThreatRuleCount

#: How many detectors the rule ranking names when the caller does not say.
#: Twenty is enough to describe the shape of a period's detections without
#: turning the block into a listing; the query caps it at ``MAX_RULES`` anyway.
DEFAULT_RULE_LIMIT = 20

#: The four severities in the order the M13 threat block already renders them
#: (most serious first). Derived from M11's ascending vocabulary rather than
#: re-spelled, so the two blocks cannot name different sets.
SEVERITY_KEYS: tuple[str, ...] = tuple(reversed(SEVERITY_VALUES))

#: Every risk-band value, derived from the one table M12 defines (M12.27).
RISK_BAND_KEYS: tuple[str, ...] = tuple(band.value for band, _low, _high in BAND_RANGES)


def build_stored_alerts(
    db: Session,
    window: AnalyticsWindow,
    *,
    rule_limit: int = DEFAULT_RULE_LIMIT,
) -> StoredAlertsData:
    """Return the stored-alert block for one window (M16.6).

    Args:
        db: A session the caller owns and closes.
        window: The resolved, bounded window, applied to ``created_at`` — the
            *observation* instant M11 writes explicitly, not the row's insert
            time, so a trend follows when detections happened.
        rule_limit: How many detectors the rule ranking names, capped at
            :data:`~app.analytics.alert_queries.MAX_RULES`.
    """
    analytics = AlertAnalytics(db)
    totals = analytics.totals(window)
    limit = max(1, min(int(rule_limit), MAX_RULES))
    return StoredAlertsData(
        total=totals.alerts,
        without_rule_key=totals.without_rule_key,
        first_timestamp=_iso(totals.first_epoch),
        last_timestamp=_iso(totals.last_epoch),
        by_severity=_counts(analytics.count_by_severity(window), SEVERITY_KEYS),
        by_status=_counts(analytics.count_by_status(window), STORED_STATUS_VALUES),
        by_risk_band=_counts(analytics.count_by_risk_band(window), RISK_BAND_KEYS),
        by_confidence_range=_counts(
            analytics.count_by_confidence_range(window), CONFIDENCE_RANGE_LABELS
        ),
        rules=[
            ThreatRuleCount(rule_key=row.rule_key, alerts=row.alerts)
            for row in analytics.top_rules(window, limit=limit)
        ],
        series=_series(analytics, window),
    )


def _counts(counted: dict[str, int], vocabulary: tuple[str, ...]) -> dict[str, int]:
    """Return ``vocabulary`` counted, zero-filling whatever the window lacks.

    Only values the owning milestone defines can be zero-filled. A count map for a
    vocabulary that *cannot* be enumerated (protocols, addresses) is reported as
    it stands, because inventing keys there would be inventing categories.
    """
    return {key: int(counted.get(key, 0)) for key in vocabulary}


def _series(
    analytics: AlertAnalytics, window: AnalyticsWindow
) -> list[AlertSeriesPoint]:
    """Return the window's buckets, each with its alert count.

    Zero-filled over the window's own buckets so a period with quiet stretches
    plots as a trend rather than as a gap between two distant observations, and
    bounded by the window's bucket count (M16.7).
    """
    counted = {row.bucket_start: row.alerts for row in analytics.series(window)}
    starts = sorted(set(window.bucket_starts()) | set(counted))
    return [
        AlertSeriesPoint(
            start=iso_from_epoch(start), alerts=int(counted.get(start, 0))
        )
        for start in starts
    ]


def _iso(epoch: float | None) -> str | None:
    """Render an optional stored instant as ISO-8601 UTC, or ``None``."""
    return None if epoch is None else iso_from_epoch(epoch)


__all__ = [
    "DEFAULT_RULE_LIMIT",
    "RISK_BAND_KEYS",
    "SEVERITY_KEYS",
    "build_stored_alerts",
]
