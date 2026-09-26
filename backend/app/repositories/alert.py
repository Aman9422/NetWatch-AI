"""Alert repository: the ``alerts`` table, and nothing else (M11.16-M11.18).

This repository owns every SQL statement that touches ``alerts``. It stores and
retrieves alerts; it never decides what an alert *is*, never assigns a severity,
never opens a transition and never scores anything. Those decisions live in the
M11 alert package, which is why this module is deliberately dumb: it is the only
place that knows the column names, and the only place a query can be wrong.

The M2 query helpers (``get_by_severity``, ``get_unresolved``, …) are kept: they
are the documented contract other milestones already rely on. ``get_unresolved``
was *corrected* rather than replaced — see its docstring — because the M11
lifecycle adds states the M2 version did not know about.

**On lifecycles and status literals.** This module does not import
``app.alerts.status``. That is deliberate and not an oversight: the alert package
imports this repository, so importing the package back would be a genuine cycle.
The persisted status vocabulary is therefore spelled out here as a literal, with
:data:`TERMINAL_STATUS_VALUES` asserted against the runtime table by the M11
repository tests — the same arrangement as the model's CHECK constraint, which
is also a literal.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.repositories.base import BaseRepository

#: Severity ordering, so "high and above" can be expressed as an ``IN`` clause.
#: Mirrors ``app.alerts.severity.SEVERITY_RANK``, which the runtime layer owns.
_SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Every severity value, least serious first.
SEVERITY_VALUES: tuple[str, ...] = tuple(_SEVERITY_RANK)

#: The M11 terminal statuses: an alert in one of these can move no further
#: (M11.19). Mirrors ``app.alerts.status.TERMINAL_STATUSES``.
TERMINAL_STATUS_VALUES: frozenset[str] = frozenset(
    {"resolved", "dismissed", "false_positive"}
)

#: The M11 active statuses: an alert still needing attention (M11.6).
#: Mirrors ``app.alerts.status.ACTIVE_STATUSES``.
ACTIVE_STATUS_VALUES: frozenset[str] = frozenset({"open", "acknowledged"})

#: Legacy M2 status names, accepted when *filtering* so a pre-M11 row stays
#: findable. Nothing writes them any more (M11.6).
LEGACY_STATUS_ALIASES: dict[str, str] = {
    "new": "open",
    "investigating": "acknowledged",
}


class AlertRepository(BaseRepository[Alert]):
    """Repository for persisting and querying alerts (M11.16)."""

    def __init__(self, db: Session) -> None:
        super().__init__(db, Alert)

    # -- reads by attribute (M2 contract) ---------------------------------

    def get_by_severity(self, severity: str, *, limit: int = 100) -> list[Alert]:
        """Return alerts matching a severity level."""
        stmt = (
            select(Alert)
            .where(Alert.severity == severity)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_status(self, status: str, *, limit: int = 100) -> list[Alert]:
        """Return alerts matching a status."""
        stmt = (
            select(Alert)
            .where(Alert.status == status)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_device(self, device_id: int, *, limit: int = 100) -> list[Alert]:
        """Return alerts linked to a device row."""
        stmt = (
            select(Alert)
            .where(Alert.device_id == device_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_by_rule(self, rule_id: int, *, limit: int = 100) -> list[Alert]:
        """Return alerts triggered by a detection-rule row (M11.18).

        ``rule_id`` is the ``detection_rules`` primary key — the foreign key the
        ``alerts`` table stores. The *string* detector id a finding carries is
        carried in ``correlation_key`` and matched by
        :meth:`get_by_correlation_rule`; the two are different questions and both
        are answerable.
        """
        stmt = (
            select(Alert)
            .where(Alert.rule_id == rule_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_unresolved(self, *, limit: int = 100) -> list[Alert]:
        """Return alerts that still need attention (M11.6/M11.18).

        Corrected in M11: the M2 version excluded only ``resolved`` and
        ``false_positive``, so an alert a user had **dismissed** still counted as
        unresolved. Every state M11 defines as terminal is excluded now, and the
        legacy ``new``/``investigating`` names are still accepted as active.
        """
        active = ACTIVE_STATUS_VALUES | {
            name
            for name, mapped in LEGACY_STATUS_ALIASES.items()
            if mapped in ACTIVE_STATUS_VALUES
        }
        stmt = (
            select(Alert)
            .where(Alert.status.in_(sorted(active)))
            .order_by(Alert.created_at.desc(), Alert.id.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    def get_high_priority(
        self, min_severity: str = "high", *, limit: int = 100
    ) -> list[Alert]:
        """Return alerts at or above a severity threshold.

        Raises:
            ValueError: If ``min_severity`` is not a known level, so a typo
                cannot silently return everything or nothing.
        """
        threshold = _rank(min_severity)
        severities = sorted(
            value for value, rank in _SEVERITY_RANK.items() if rank >= threshold
        )
        stmt = (
            select(Alert)
            .where(Alert.severity.in_(severities))
            .order_by(Alert.severity, Alert.created_at.desc())
            .limit(limit)
        )
        return list(self.db.scalars(stmt).all())

    # -- deduplication (M11.9) -------------------------------------------

    def find_duplicate_candidate(
        self,
        correlation_key: str,
        *,
        cutoff: datetime,
        statuses: Iterable[str] | None = None,
    ) -> Alert | None:
        """Return the newest matching alert created at or after ``cutoff``.

        This is the one query that implements M11.9: an alert is a duplicate when
        it shares the deduplication key and was created inside the window. The
        boundary is inclusive on both sides, matching
        :meth:`app.alerts.dedup.DeduplicationWindow.contains`, so the window has
        one definition rather than two that can disagree at the edge.

        Args:
            correlation_key: The deduplication key to match, exactly.
            cutoff: Earliest ``created_at`` still inside the window.
            statuses: Restrict to these stored statuses. Defaults to *every*
                status, because an alert still being observed belongs to its
                incident whether or not a human has acknowledged it — folding a
                repeated observation into an acknowledged alert is correct.

        Raises:
            ValueError: If ``correlation_key`` is empty. An empty key would match
                any alert, which is the opposite of deduplication.
        """
        key = str(correlation_key).strip()
        if not key:
            raise ValueError("correlation_key must not be empty")
        stmt = select(Alert).where(
            Alert.correlation_key == key, Alert.created_at >= cutoff
        )
        if statuses is not None:
            values = [str(status) for status in statuses]
            if not values:
                return None
            stmt = stmt.where(Alert.status.in_(values))
        stmt = stmt.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(1)
        return self.db.scalar(stmt)

    # -- filtered listing (M11.18) ---------------------------------------

    def list_alerts(
        self,
        *,
        severity: str | None = None,
        min_severity: str | None = None,
        statuses: Sequence[str] | None = None,
        rule_id: int | None = None,
        correlation_rule_key: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        correlation_key: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """Return alerts matching the filters, newest first (M11.18).

        ``since`` is inclusive and ``until`` exclusive, matching M10's finding
        query, so a window has an explicit start and end.

        ``correlation_rule_key`` matches by the detector's *string* rule id rather
        than the catalogue foreign key: the deduplication key's leading component
        is the rule id (M11.9), so a prefix match answers "every alert this
        detector raised" even when ``rule_id`` is ``NULL`` because the catalogue
        has no row for it. Both filters exist because they are different
        questions, and either may be combined with the rest.

        Raises:
            ValueError: If ``limit`` is below 1, ``offset`` is negative, a
                severity filter is unknown, or ``correlation_rule_key`` is empty.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if offset < 0:
            raise ValueError("offset must not be negative")
        stmt = self._filtered(
            select(Alert),
            severity=severity,
            min_severity=min_severity,
            statuses=statuses,
            rule_id=rule_id,
            correlation_rule_key=correlation_rule_key,
            source_ip=source_ip,
            destination_ip=destination_ip,
            correlation_key=correlation_key,
            since=since,
            until=until,
        )
        stmt = (
            stmt.order_by(Alert.created_at.desc(), Alert.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())

    def count_alerts(
        self,
        *,
        severity: str | None = None,
        min_severity: str | None = None,
        statuses: Sequence[str] | None = None,
        rule_id: int | None = None,
        correlation_rule_key: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        correlation_key: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        """Count alerts matching the same filters as :meth:`list_alerts`."""
        stmt = self._filtered(
            select(func.count()).select_from(Alert),
            severity=severity,
            min_severity=min_severity,
            statuses=statuses,
            rule_id=rule_id,
            correlation_rule_key=correlation_rule_key,
            source_ip=source_ip,
            destination_ip=destination_ip,
            correlation_key=correlation_key,
            since=since,
            until=until,
        )
        return int(self.db.scalar(stmt) or 0)

    # -- aggregations (M11.18) -------------------------------------------

    def count_by_severity(
        self, *, statuses: Sequence[str] | None = None
    ) -> dict[str, int]:
        """Return how many alerts exist per severity (M11.18)."""
        return self._grouped_count(Alert.severity, statuses=statuses)

    def count_by_status(self) -> dict[str, int]:
        """Return how many alerts exist per stored status (M11.18)."""
        return self._grouped_count(Alert.status)

    # -- writes -----------------------------------------------------------

    def insert(self, **values: object) -> Alert:
        """Create one alert row, committing it and reading it back.

        ``created_at``/``updated_at`` are supplied explicitly by the service so an
        alert is dated to the *observation*, not to the moment the row happened
        to be written (M11.3). Passing them overrides the columns' server
        defaults, which is exactly what is wanted here.
        """
        alert = Alert(**values)
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def update_status(
        self,
        alert: Alert,
        *,
        status: str,
        updated_at: datetime,
        resolved_at: datetime | None = None,
    ) -> Alert:
        """Write a validated lifecycle change onto a row (M11.19/M11.20).

        Validation happens *before* this call, in ``app.alerts.status``. This
        method's job is only to persist the outcome, including stamping
        ``updated_at`` from the caller's clock and ``resolved_at`` when the new
        state is terminal.
        """
        alert.status = status
        alert.updated_at = updated_at
        alert.resolved_at = resolved_at
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def touch_correlation_key(self, alert: Alert, correlation_key: str) -> Alert:
        """Set the deduplication key on an alert row, committing it."""
        alert.correlation_key = correlation_key
        self.db.commit()
        self.db.refresh(alert)
        return alert

    # -- internals --------------------------------------------------------

    @staticmethod
    def _filtered(
        statement,
        *,
        severity: str | None,
        min_severity: str | None,
        statuses: Sequence[str] | None,
        rule_id: int | None,
        correlation_rule_key: str | None,
        source_ip: str | None,
        destination_ip: str | None,
        correlation_key: str | None,
        since: datetime | None,
        until: datetime | None,
    ):
        """Apply the shared alert filters to a select statement.

        Raises:
            ValueError: If ``severity``/``min_severity`` is unknown, both are
                supplied (two severity constraints in one query is ambiguous, so
                it is rejected rather than resolved by an undocumented
                precedence), or ``correlation_rule_key`` is empty (an empty prefix
                matches every alert, which is a query bug, not a wide result).
        """
        # Imported locally because the alert package imports this repository:
        # reaching for the real separator over a module-level import would be the
        # genuine cycle this module's docstring warns about.
        from app.alerts.dedup import KEY_SEPARATOR

        if severity is not None and min_severity is not None:
            raise ValueError("Use either severity or min_severity, not both")
        if correlation_rule_key is not None:
            key = str(correlation_rule_key).strip()
            if not key:
                raise ValueError("correlation_rule_key must not be empty")
            statement = statement.where(
                Alert.correlation_key.like(f"{key}{KEY_SEPARATOR}%")
            )
        if severity is not None:
            statement = statement.where(Alert.severity == _validated(severity))
        if min_severity is not None:
            threshold = _rank(min_severity)
            statement = statement.where(
                Alert.severity.in_(
                    sorted(
                        value
                        for value, rank in _SEVERITY_RANK.items()
                        if rank >= threshold
                    )
                )
            )
        if statuses is not None:
            values = [str(status) for status in statuses]
            if not values:
                # An explicitly empty status filter selects nothing. Returning
                # everything instead would silently ignore the filter.
                statement = statement.where(Alert.id < 0)
            else:
                statement = statement.where(Alert.status.in_(values))
        if rule_id is not None:
            statement = statement.where(Alert.rule_id == rule_id)
        if source_ip is not None:
            statement = statement.where(Alert.source_ip == source_ip)
        if destination_ip is not None:
            statement = statement.where(Alert.destination_ip == destination_ip)
        if correlation_key is not None:
            statement = statement.where(Alert.correlation_key == correlation_key)
        if since is not None:
            statement = statement.where(Alert.created_at >= since)
        if until is not None:
            statement = statement.where(Alert.created_at < until)
        return statement

    def _grouped_count(
        self, column, *, statuses: Sequence[str] | None = None
    ) -> dict[str, int]:
        """Return ``{value: count}`` for a column, optionally status-filtered."""
        stmt = select(column, func.count()).select_from(Alert)
        if statuses is not None:
            values = [str(status) for status in statuses]
            if not values:
                return {}
            stmt = stmt.where(Alert.status.in_(values))
        stmt = stmt.group_by(column)
        return {str(value): int(count) for value, count in self.db.execute(stmt).all()}


def _validated(severity: str) -> str:
    """Return a known severity value.

    Raises:
        ValueError: If ``severity`` is not one of the four levels.
    """
    value = str(severity).strip().lower()
    if value not in _SEVERITY_RANK:
        allowed = ", ".join(SEVERITY_VALUES)
        raise ValueError(
            f"Unknown alert severity: {severity!r} (expected one of: {allowed})"
        )
    return value


def _rank(severity: str) -> int:
    """Return the rank of a severity value.

    Raises:
        ValueError: If ``severity`` is not one of the four levels.
    """
    return _SEVERITY_RANK[_validated(severity)]
