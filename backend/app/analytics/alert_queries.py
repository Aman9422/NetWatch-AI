"""Read-only aggregate queries over the persisted ``alerts`` table (M16.6).

The M13 analytics response already reports what the M10 finding counters, the M11
read service and the M12 incident registry hold *right now*. Those are live
in-process numbers: M10 retains findings in memory, M11's summary counts the alert
table, and M12's incidents never leave memory at all. What none of them can answer
is "over this window, how did stored alerts break down" — a question only the
``alerts`` table can answer, because it is the one security record this system
persists with a timestamp.

Four things this module is careful about, and they are the whole of M16.6's
"keep the distinction" requirement:

**A finding, an alert and an incident stay distinct.** This module reads alerts
only. It does not count findings (they are not stored) and it does not count
incidents (they are M12's in-memory registry, reported by the live block). A single
"threats" number would be a fourth thing that no milestone produces.

**Severity, confidence and risk stay distinct.** ``count_by_severity`` reports
M11's evidence-based judgement, ``count_by_confidence_range`` reports how strongly
M11 believed its own evidence, and ``count_by_risk_band`` reports M12's
prioritisation metric. Three different questions with three different answers.

**No score is computed here.** ``count_by_risk_band`` reads the ``risk_score``
column M12 already wrote (M12.24) and bands it with
:func:`~app.risk.bands.band_for`'s own ranges. M16 does not derive a score, and the
band boundaries are not restated — they are read from the module that owns them.

**A NULL ``correlation_key`` is reported, not hidden.** The rule ranking groups by
the key's leading rule component (M11.9), so an alert with no key cannot be ranked
by rule. Its count is returned separately by :meth:`totals` so the ranking's
omission is visible, in the same spirit as the packet port ranking (M16.3).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import case, func, literal, select
from sqlalchemy.orm import Session

from app.alerts.dedup import KEY_SEPARATOR
from app.analytics.distributions import CONFIDENCE_RANGES
from app.analytics.metrics import MAX_GROUPS
from app.analytics.window import (
    MAX_SERIES_POINTS,
    AnalyticsWindow,
    bucket_expression,
    to_utc_datetime,
)
from app.models.alert import Alert
from app.risk.bands import BAND_RANGES

#: Most rule groups returned in one breakdown. The rule vocabulary is bounded by
#: the detectors that exist, but a cap is still applied so the statement's row
#: count never depends on the contents of the table.
MAX_RULES = 50


@dataclass(frozen=True)
class AlertTotals:
    """Stored alerts inside a window (M16.6).

    Attributes:
        alerts: How many alert rows were created inside the window.
        without_rule_key: How many of them carry no ``correlation_key``, and so
            appear in no rule-grouped breakdown. Reported so the ranking's
            omission is a stated fact rather than a silent gap (M16.6).
        first_epoch / last_epoch: The window's earliest and latest ``created_at``,
            or ``None`` when nothing was stored. ``None`` means "no alert was
            created in this window", which is not the same answer as epoch 0.
    """

    alerts: int = 0
    without_rule_key: int = 0
    first_epoch: float | None = None
    last_epoch: float | None = None


@dataclass(frozen=True)
class RuleCount:
    """How many alerts one detector raised inside a window (M16.6).

    ``rule_key`` is the detector's *string* rule id — the leading component of
    the deduplication key M11 stores (M11.9) — not the ``detection_rules``
    foreign key, which is ``NULL`` whenever the catalogue holds no row for the
    detector. The string id is the one every finding carries, so the ranking is
    answerable for every alert that has a key at all.
    """

    rule_key: str
    alerts: int


@dataclass(frozen=True)
class BucketCount:
    """One time bucket's alert count (M16.6)."""

    bucket_start: int
    alerts: int


class AlertAnalytics:
    """Aggregate reads over ``alerts``, scoped to one window (M16.6)."""

    def __init__(self, db: Session) -> None:
        """Bind the queries to a session the caller owns and closes."""
        self._db = db

    # -- totals ------------------------------------------------------------

    def totals(self, window: AnalyticsWindow) -> AlertTotals:
        """Return the window's alert count, keyless count and bounds."""
        statement = select(
            func.count(),
            func.coalesce(
                func.sum(case((Alert.correlation_key.is_(None), 1), else_=0)), 0
            ),
            func.min(Alert.created_at),
            func.max(Alert.created_at),
        ).where(*self._bounds(window))
        row = self._db.execute(statement).one()
        return AlertTotals(
            alerts=int(row[0] or 0),
            without_rule_key=int(row[1] or 0),
            first_epoch=_epoch(row[2]),
            last_epoch=_epoch(row[3]),
        )

    # -- distributions -----------------------------------------------------

    def count_by_severity(self, window: AnalyticsWindow) -> dict[str, int]:
        """Return how many alerts carry each M11 severity (M16.6)."""
        return self._grouped(Alert.severity, window)

    def count_by_status(self, window: AnalyticsWindow) -> dict[str, int]:
        """Return how many alerts are in each M11 lifecycle state (M16.6)."""
        return self._grouped(Alert.status, window)

    def count_by_risk_band(self, window: AnalyticsWindow) -> dict[str, int]:
        """Return how many alerts fall in each M12 risk band (M16.6).

        The bands come from :data:`~app.risk.bands.BAND_RANGES` — the same table
        the incident view and the risk scorer use — so M16 cannot band a score
        differently from the milestone that produced it (M12.27).

        Note what a ``minimal`` count includes: M11 writes ``risk_score = 0`` and
        leaves it there until M12 correlates the alert (M11's own note on the
        column). An alert M12 has not seen is therefore banded ``minimal``, which
        is the truthful reading of its stored score — but it is "not yet scored",
        not "assessed as minimal". Only alerts an incident has reached are
        genuinely scored, and the live incident block is where that judgement is
        reported.
        """
        return self._grouped_case(_band_case(), window)

    def count_by_confidence_range(self, window: AnalyticsWindow) -> dict[str, int]:
        """Return how many alerts fall in each confidence range (M16.6).

        The ranges are the project's one documented 0-100 tiling (M12.27), applied
        to M11's ``confidence`` column as a *distribution*; the labels are the
        numeric bounds, so a count here reads as "how many alerts M11 was this
        confident about" and never as a severity or risk verdict.
        """
        return self._grouped_case(_confidence_case(), window)

    # -- rule ranking ------------------------------------------------------

    def top_rules(self, window: AnalyticsWindow, *, limit: int) -> list[RuleCount]:
        """Rank detectors by how many alerts they raised inside the window.

        The grouping key is the deduplication key's leading component (M11.9).
        Alerts whose key is ``NULL`` hold no rule and are excluded here; their
        count is reported by :meth:`totals` instead. Ordering is by count
        descending with the rule key as tie-break, so equal counts order the same
        way on every request (M13.24).
        """
        capped = max(1, min(int(limit), MAX_RULES))
        key = _rule_key_expression()
        statement = (
            select(key.label("rule_key"), func.count().label("alerts"))
            .where(*self._bounds(window))
            .where(Alert.correlation_key.is_not(None))
            .group_by(key)
            .order_by(func.count().desc(), key.asc())
            .limit(capped)
        )
        return [
            RuleCount(rule_key=str(row.rule_key), alerts=int(row.alerts or 0))
            for row in self._db.execute(statement)
        ]

    # -- series ------------------------------------------------------------

    def series(self, window: AnalyticsWindow) -> list[BucketCount]:
        """Return per-bucket alert counts by ``created_at``, oldest first.

        ``created_at`` is the *observation* instant, not the row's insert time —
        M11 writes it explicitly for exactly that reason — so a trend here follows
        when detections happened rather than when they were stored.
        """
        bucket = bucket_expression(Alert.created_at, window.bucket_seconds)
        statement = (
            select(bucket.label("bucket"), func.count().label("alerts"))
            .where(*self._bounds(window))
            .group_by(bucket)
            .order_by(bucket)
            .limit(MAX_SERIES_POINTS)
        )
        return [
            BucketCount(bucket_start=int(row.bucket), alerts=int(row.alerts or 0))
            for row in self._db.execute(statement)
        ]

    # -- internals ---------------------------------------------------------

    def _grouped(self, column, window: AnalyticsWindow) -> dict[str, int]:
        """Return ``{value: count}`` for one column inside the window."""
        statement = (
            select(column, func.count()).where(*self._bounds(window)).group_by(column)
        )
        return {
            str(value): int(count or 0) for value, count in self._db.execute(statement)
        }

    def _grouped_case(self, expression, window: AnalyticsWindow) -> dict[str, int]:
        """Return ``{label: count}`` for a CASE expression inside the window."""
        statement = (
            select(expression, func.count())
            .where(*self._bounds(window))
            .group_by(expression)
        )
        return {
            str(value): int(count or 0) for value, count in self._db.execute(statement)
        }

    @staticmethod
    def _bounds(window: AnalyticsWindow) -> tuple:
        """Return the window predicate on ``created_at``, ``until`` exclusive."""
        return (
            Alert.created_at >= to_utc_datetime(window.since),
            Alert.created_at < to_utc_datetime(window.until),
        )


def _band_case():
    """Return a CASE expression labelling ``risk_score`` with its M12 band.

    Built from :data:`~app.risk.bands.BAND_RANGES`, which tiles ``0..100`` with no
    gap and no overlap, so every branch but the last is an upper bound and the
    last is the remainder.
    """
    branches = [
        (Alert.risk_score <= high, literal(band.value))
        for band, _low, high in BAND_RANGES[:-1]
    ]
    return case(*branches, else_=literal(BAND_RANGES[-1][0].value))


def _confidence_case():
    """Return a CASE expression labelling ``confidence`` with its range.

    The same construction as :func:`_band_case`, over the confidence ranges rather
    than the risk bands, so the two histograms cannot use different boundaries.
    """
    branches = [
        (Alert.confidence <= high, literal(label))
        for label, _low, high in CONFIDENCE_RANGES[:-1]
    ]
    return case(*branches, else_=literal(CONFIDENCE_RANGES[-1][0]))


def _rule_key_expression():
    """Return the SQL expression for an alert's detector rule id (M11.9).

    The deduplication key is ``rule_id | source_ip | ...``, so the rule id is
    everything before the first separator. A key written without a separator at
    all is the rule id on its own, which is why the ``instr`` result is checked
    rather than used directly: ``substr(x, 1, -1)`` returns the empty string, which
    would silently merge such a key into a nameless group.
    """
    position = func.instr(Alert.correlation_key, KEY_SEPARATOR)
    return case(
        (position == 0, Alert.correlation_key),
        else_=func.substr(Alert.correlation_key, 1, position - 1),
    )


def _epoch(value: object) -> float | None:
    """Return a stored ``created_at`` as epoch seconds, or ``None``.

    ``created_at`` is a naive UTC wall-clock value, so UTC is attached before the
    conversion: a naive ``timestamp()`` would read it as local time and shift
    every reported instant by the host's offset.
    """
    if not isinstance(value, datetime):
        return None
    return float(value.replace(tzinfo=timezone.utc).timestamp())


__all__ = [
    "MAX_RULES",
    "AlertAnalytics",
    "AlertTotals",
    "BucketCount",
    "RuleCount",
]
