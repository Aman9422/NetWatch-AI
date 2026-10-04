"""Read-only alert queries: listings, detail, evidence and diagnostics (M11.18).

The write path lives in :mod:`app.alerts.service`; this module answers questions
about what is already stored. Nothing here mutates a record, so every method is
safe to call from an API handler.

Two conversions happen here and nowhere else:

* a caller filters with **epoch seconds**, because that is how an M10 finding
  expresses a time (so a finding's timestamp can be passed straight through);
* the API speaks **ISO-8601 UTC**, because that is how M3–M10 expose time.

The rows store naive UTC datetimes, so both directions are handled by
:mod:`app.alerts.timestamps` and a filter is never silently off by a timezone.

Evidence counts are fetched **once per page** rather than once per alert
(:meth:`~app.repositories.alert_evidence.AlertEvidenceRepository.count_for_alerts`),
so a fifty-row listing issues a bounded number of queries regardless of size.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TypedDict

from app.alerts.alert import Alert
from app.alerts.timestamps import to_iso_timestamp, to_utc_datetime
from app.models.alert_evidence import AlertEvidence
from app.persistence.session_factory import SessionFactory
from app.repositories.alert import AlertRepository
from app.repositories.alert_evidence import AlertEvidenceRepository

logger = logging.getLogger(__name__)

#: The four severity levels, most serious first, for a stable summary shape.
_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")


class AlertSummary(TypedDict):
    """The aggregation block :meth:`AlertQueries.summary` returns (M11.18).

    A ``TypedDict`` rather than a plain ``dict`` because the three keys have
    different value types: a count, and two nested count maps. Spelling that out
    is what lets the diagnostics endpoint read ``by_severity`` as a
    ``dict[str, int]`` instead of an opaque ``object`` that every consumer has to
    narrow by hand.
    """

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]


class AlertFilters(TypedDict):
    """The keyword arguments :meth:`AlertQueries._filters` produces (M11.18).

    It mirrors the filter parameters of
    :meth:`~app.repositories.alert.AlertRepository.list_alerts` exactly, which is
    what lets the statement helper be called with ``**filters`` without the type
    checker having to treat every value as an opaque ``object``.
    """

    severity: str | None
    min_severity: str | None
    statuses: tuple[str, ...] | None
    rule_id: int | None
    correlation_rule_key: str | None
    source_ip: str | None
    destination_ip: str | None
    since: datetime | None
    until: datetime | None


@dataclass(frozen=True)
class AlertQuery:
    """A set of alert filters (M11.18).

    Every field is optional; ``None`` means "no filter", so an omitted argument
    never narrows a result. ``since`` is inclusive and ``until`` exclusive,
    matching M10's finding query, so a window has an unambiguous start and end.

    Attributes:
        severity: Exact severity.
        min_severity: Minimum severity. Mutually exclusive with ``severity``;
            the repository rejects both being set rather than guessing a
            precedence.
        statuses: Stored status values to include. An empty tuple selects
            nothing, which is different from ``None`` (select everything).
        rule_id: ``detection_rules`` foreign key.
        rule_key: The detector's stable string id, matched against
            ``correlation_key`` so a detector with no catalogue row is still
            queryable (M11.18).
        source_ip / destination_ip: Endpoint filters.
        since / until: Observation window, in epoch seconds.
        limit / offset: Paging window.
    """

    severity: str | None = None
    min_severity: str | None = None
    statuses: tuple[str, ...] | None = None
    rule_id: int | None = None
    rule_key: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    since: float | None = None
    until: float | None = None
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True)
class AlertPage:
    """One page of alerts plus the total a client needs to page through them.

    Attributes:
        alerts: The alerts in this page, newest first.
        total: How many alerts match the filters overall, not just this page.
        limit / offset: The window that produced the page.
    """

    alerts: tuple[Alert, ...] = ()
    total: int = 0
    limit: int = 100
    offset: int = 0

    @property
    def count(self) -> int:
        """Return how many alerts are in this page."""
        return len(self.alerts)

    @property
    def has_more(self) -> bool:
        """Return True when further pages exist after this one."""
        return (self.offset + self.count) < self.total


@dataclass(frozen=True)
class AlertDetail:
    """One alert with its evidence, as the detail endpoint needs it (M11.18).

    Attributes:
        evidence: The evidence rows, oldest first, in the order they were
            attached.
        evidence_by_type: Count per ``evidence_type``, so a client can describe
            an alert as "2 packets, 1 connection, 1 rule" without walking the
            rows itself.
    """

    alert: Alert
    evidence: tuple[AlertEvidence, ...] = ()
    evidence_by_type: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceRecord:
    """One evidence row together with the alert that owns it (M13.14).

    Attributes:
        evidence: The stored evidence row.
        alert_id: The alert the evidence supports, so a client holding an
            evidence reference can navigate to the alert without searching.
    """

    evidence: AlertEvidence
    alert_id: int


class AlertQueries:
    """Read-only queries over stored alerts (M11.18)."""

    def __init__(self, *, session_factory: SessionFactory) -> None:
        """Create the query service.

        Args:
            session_factory: Opens a session per call. A session is not
                thread-safe and the API serves requests from a thread pool, so
                one is never shared between calls.
        """
        self._session_factory = session_factory

    # -- listings ---------------------------------------------------------

    def list_alerts(self, query: AlertQuery) -> AlertPage:
        """Return a page of alerts matching ``query``, newest first (M11.18).

        Raises:
            ValueError: If the filter is unusable — an unknown severity, both
                ``severity`` and ``min_severity``, an empty ``rule_key``, a
                non-positive ``limit``, or a negative ``offset``. A rejected
                filter is better than one that silently returns everything.
        """
        session = self._session_factory()
        try:
            repository = AlertRepository(session)
            filters = self._filters(query)
            rows = repository.list_alerts(
                **filters, limit=query.limit, offset=query.offset
            )
            total = repository.count_alerts(**filters)
            return AlertPage(
                alerts=self._runtime_rows(session, rows),
                total=total,
                limit=query.limit,
                offset=query.offset,
            )
        finally:
            session.close()

    def get_alert(self, alert_id: int) -> Alert | None:
        """Return one alert by id, or ``None`` when it does not exist."""
        session = self._session_factory()
        try:
            repository = AlertRepository(session)
            row = repository.get(alert_id)
            if row is None:
                return None
            evidence = AlertEvidenceRepository(session)
            return Alert.from_record(
                row, evidence_count=evidence.count_for_alert(alert_id)
            )
        finally:
            session.close()

    def get_detail(self, alert_id: int) -> AlertDetail | None:
        """Return one alert with its evidence and evidence counts (M11.18)."""
        session = self._session_factory()
        try:
            repository = AlertRepository(session)
            row = repository.get(alert_id)
            if row is None:
                return None
            evidence = AlertEvidenceRepository(session)
            rows = evidence.list_for_alert(alert_id)
            return AlertDetail(
                alert=Alert.from_record(row, evidence_count=len(rows)),
                evidence=tuple(rows),
                evidence_by_type=evidence.count_by_type(alert_id),
            )
        finally:
            session.close()

    def get_evidence(
        self, alert_id: int, *, evidence_type: str | None = None
    ) -> list[AlertEvidence]:
        """Return one alert's evidence, optionally filtered by type (M11.18)."""
        session = self._session_factory()
        try:
            return AlertEvidenceRepository(session).list_for_alert(
                alert_id, evidence_type=evidence_type
            )
        finally:
            session.close()

    def get_evidence_record(self, evidence_id: int) -> EvidenceRecord | None:
        """Return one evidence row with the alert it belongs to (M13.14).

        The standalone evidence endpoint has to answer "which alert does this
        evidence support?", so the owning ``alert_id`` is returned beside the row
        rather than left for a client to discover by walking every alert.

        Returns:
            The record, or ``None`` when the id is unknown.
        """
        session = self._session_factory()
        try:
            row = AlertEvidenceRepository(session).get(int(evidence_id))
            if row is None:
                return None
            return EvidenceRecord(evidence=row, alert_id=int(row.alert_id))
        finally:
            session.close()

    # -- aggregations (M11.18) -------------------------------------------

    def count_by_severity(self) -> dict[str, int]:
        """Return the number of stored alerts per severity."""
        session = self._session_factory()
        try:
            return AlertRepository(session).count_by_severity()
        finally:
            session.close()

    def count_by_status(self) -> dict[str, int]:
        """Return the number of stored alerts per stored status."""
        session = self._session_factory()
        try:
            return AlertRepository(session).count_by_status()
        finally:
            session.close()

    def summary(self) -> AlertSummary:
        """Return the aggregation block the diagnostics endpoint exposes.

        Severities with no alerts are reported as ``0`` rather than omitted, so a
        client never has to distinguish "none of this severity" from "the field
        is missing". Statuses are reported as stored, including any legacy value
        a pre-M11 database still holds.
        """
        by_severity = self.count_by_severity()
        by_status = self.count_by_status()
        return AlertSummary(
            total=sum(by_severity.values()),
            by_severity={
                severity: by_severity.get(severity, 0) for severity in _SEVERITY_ORDER
            },
            by_status=dict(sorted(by_status.items())),
        )

    # -- internals --------------------------------------------------------

    @staticmethod
    def _filters(query: AlertQuery) -> AlertFilters:
        """Translate a query object into repository keyword arguments.

        The epoch→datetime conversion happens here, at the one boundary where a
        caller's seconds meet the columns' datetimes.
        """
        return AlertFilters(
            severity=query.severity,
            min_severity=query.min_severity,
            statuses=query.statuses,
            rule_id=query.rule_id,
            correlation_rule_key=query.rule_key,
            source_ip=query.source_ip,
            destination_ip=query.destination_ip,
            since=None if query.since is None else to_utc_datetime(query.since),
            until=None if query.until is None else to_utc_datetime(query.until),
        )

    @staticmethod
    def _runtime_rows(session, rows) -> tuple[Alert, ...]:
        """Project ORM rows onto runtime alerts with one evidence-count query.

        Counting per row would issue one query per alert in the page, so the
        counts for the whole page are fetched together (M11.18).
        """
        if not rows:
            return ()
        counts = AlertEvidenceRepository(session).count_for_alerts(
            row.id for row in rows
        )
        return tuple(
            Alert.from_record(row, evidence_count=counts.get(row.id, 0))
            for row in rows
        )


__all__ = [
    "AlertDetail",
    "AlertPage",
    "AlertQueries",
    "AlertQuery",
    "AlertSummary",
    "EvidenceRecord",
    "to_iso_timestamp",
]
