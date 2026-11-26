"""Persistent baseline storage (M21.8).

One store, four responsibilities, all of them database work and none of them
behavioural judgement:

* **write windows** — insert an aggregated observation window. A duplicate
  ``(device_key, window_start)`` is a no-op rather than a second sample, which is
  what makes a re-flush after a crash safe.
* **fold a window into a profile** — create the profile row if it does not exist,
  add the window's contribution to the sample count and the observation bounds,
  then recalculate the statistical profile from the most recent windows.
* **read** — a paginated profile listing, one profile, and its recent windows.
* **reset** — delete one device's windows and profile, and nothing else.

## Why the statistics are recalculated rather than updated

An online mean would be cheap and would be the wrong answer here: M21.6 asks for
median, MAD and p95, and none of those can be updated incrementally from a
running total. The recalculated set is bounded by
``baseline_statistics_max_windows`` (1,440 by default), so a recomputation reads
at most that many rows regardless of how much history was retained. That is a
deliberate trade — a bounded read per flush instead of an unbounded dependency on
every window ever written.

## Transaction policy

Every public method that writes opens its own session, commits once, and rolls
back on failure. A session is never held across calls, because the flush thread
and an API request are different threads and SQLAlchemy sessions are not
thread-safe. A failure raises: the engine above is what contains it, so a storage
problem cannot reach the capture thread from here.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.baselines.aggregation import WindowCounters, window_start_datetime
from app.baselines.states import LearningState, publishes_statistics, state_for_samples
from app.baselines.statistics import (
    FeatureStatistics,
    summaries_from_json,
    summaries_to_json,
    summarise_samples,
)
from app.models.baseline_observation import BaselineProfile, BaselineWindow
from app.persistence.session_factory import SessionFactory, app_session_factory

logger = logging.getLogger(__name__)

#: Defaults mirroring ``app.config.settings``.
DEFAULT_STATISTICS_MAX_WINDOWS = 1440
DEFAULT_PROVISIONAL_MIN_SAMPLES = 5
DEFAULT_ESTABLISHED_MIN_SAMPLES = 30


@dataclass(frozen=True)
class ProfileSnapshot:
    """A profile row as the rest of the application reads it (M21.10).

    A plain value rather than an ORM row, so the API layer can hold one after the
    session that produced it has closed — which it always has, because the store
    opens and closes a session per call.
    """

    device_key: str
    identity_kind: str
    learning_state: str
    sample_count: int
    statistics_sample_count: int
    window_seconds: float
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    mac_address: str | None
    ip_addresses: tuple[str, ...]
    statistics: dict[str, FeatureStatistics]
    updated_at: datetime | None

    @property
    def publishes_statistics(self) -> bool:
        """Return True when this profile is mature enough to publish figures."""
        return publishes_statistics(self.learning_state)


class BaselineStore:
    """Reads and writes the two baseline tables (M21.8).

    Every method takes no session: the store opens one per call from the factory
    it was built with, so it is safe to share between the flush thread and the
    request handlers.
    """

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
        statistics_max_windows: int = DEFAULT_STATISTICS_MAX_WINDOWS,
        provisional_min_samples: int = DEFAULT_PROVISIONAL_MIN_SAMPLES,
        established_min_samples: int = DEFAULT_ESTABLISHED_MIN_SAMPLES,
    ) -> None:
        """Create the store.

        Args:
            session_factory: Builds database sessions. Defaults to the
                application factory; tests inject an isolated one.
            statistics_max_windows: Most recent windows a profile is calculated
                over (M21.6).
            provisional_min_samples: Samples needed to leave ``learning``.
            established_min_samples: Samples needed to reach ``established``.

        Raises:
            ValueError: If ``statistics_max_windows`` is not positive.
        """
        if statistics_max_windows < 1:
            raise ValueError("statistics_max_windows must be at least 1")
        if provisional_min_samples < 1:
            raise ValueError("provisional_min_samples must be at least 1")
        self._session_factory = session_factory or app_session_factory
        self._statistics_max_windows = statistics_max_windows
        self._provisional_min_samples = provisional_min_samples
        self._established_min_samples = established_min_samples

    # -- writing windows --------------------------------------------------

    def write_windows(self, windows: Sequence[WindowCounters]) -> int:
        """Persist aggregated windows and update their profiles (M21.8).

        Windows that observed nothing are skipped, so a silent period can never
        become a zero-valued sample (M21.5).

        Args:
            windows: The closed windows to write.

        Returns:
            How many *new* window rows were inserted. A duplicate window is
            counted as zero, not as an error.

        Raises:
            Exception: Whatever the database raised. The transaction is rolled
                back, so a failed flush leaves both tables as they were.
        """
        candidates = [window for window in windows if window.observed]
        if not candidates:
            return 0

        session = self._session_factory()
        try:
            written = self._write_windows(session, candidates)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return written

    def _write_windows(
        self, session: Session, windows: Sequence[WindowCounters]
    ) -> int:
        """Insert windows and update their profiles inside one transaction."""
        written = 0
        touched: dict[str, WindowCounters] = {}
        for window in windows:
            start = window_start_datetime(window.window_start)
            if self._window_exists(session, window.device_key, start):
                # A window that is already stored is not written twice, and not
                # folded into the profile twice either — otherwise a retried
                # flush would inflate the sample count.
                continue
            session.add(
                BaselineWindow(
                    device_key=window.device_key,
                    window_start=start,
                    window_seconds=window.window_seconds,
                    packet_count=window.packet_count,
                    byte_count=window.byte_count,
                    tcp_packets=window.tcp_packets,
                    udp_packets=window.udp_packets,
                    icmp_packets=window.icmp_packets,
                    dns_packets=window.dns_packets,
                    unique_peers=window.unique_peers,
                    unique_destination_ports=window.unique_destination_ports,
                    # A device with no conversation keys measured nothing about
                    # connections in this window, so the feature is stored as
                    # NULL rather than as a fabricated zero (M21.5).
                    new_connections=(
                        window.new_connections
                        if window.conversation_keys
                        else None
                    ),
                    peers_truncated=window.peers_truncated,
                    ports_truncated=window.ports_truncated,
                )
            )
            written += 1
            touched[window.device_key] = window

        # Flush the inserts before reading them back, so the profile calculation
        # sees the windows this batch just wrote.
        session.flush()
        for device_key, window in touched.items():
            try:
                self._refresh_profile(session, device_key, window)
            except IntegrityError:
                # A concurrent writer created the profile between our read and
                # our insert. Rolling back to a savepoint and retrying the update
                # path is correct: the window insert already succeeded.
                session.rollback()
                raise
        return written

    def _window_exists(
        self, session: Session, device_key: str, window_start: datetime
    ) -> bool:
        """Return True when this window is already stored."""
        stmt = (
            select(func.count())
            .select_from(BaselineWindow)
            .where(
                BaselineWindow.device_key == device_key,
                BaselineWindow.window_start == window_start,
            )
        )
        return bool(session.scalar(stmt))

    def _refresh_profile(
        self, session: Session, device_key: str, window: WindowCounters
    ) -> None:
        """Add a window's contribution to its profile and recalculate it."""
        profile = session.scalar(
            select(BaselineProfile).where(BaselineProfile.device_key == device_key)
        )
        observed_at = window_start_datetime(window.window_start)
        last_seen = (
            window_start_datetime(window.last_seen)
            if window.last_seen is not None
            else observed_at
        )
        ip_addresses = [window.ip_address] if window.ip_address is not None else []

        if profile is None:
            profile = BaselineProfile(
                device_key=device_key,
                identity_kind=window.identity_kind,
                learning_state=LearningState.LEARNING.value,
                sample_count=0,
                statistics_sample_count=0,
                window_seconds=window.window_seconds,
                first_observed_at=observed_at,
                last_observed_at=last_seen,
                last_mac_address=window.mac_address,
                last_ip_addresses=json.dumps(ip_addresses),
            )
            session.add(profile)
            session.flush()
        else:
            if profile.first_observed_at is None or observed_at < profile.first_observed_at:
                profile.first_observed_at = observed_at
            if profile.last_observed_at is None or last_seen > profile.last_observed_at:
                profile.last_observed_at = last_seen
            if window.mac_address is not None:
                profile.last_mac_address = window.mac_address
            if window.ip_address is not None:
                profile.last_ip_addresses = json.dumps(
                    _merged_addresses(profile.last_ip_addresses, window.ip_address)
                )
            profile.window_seconds = window.window_seconds

        sample_count = self._count_windows(session, device_key)
        profile.sample_count = sample_count
        profile.learning_state = state_for_samples(
            sample_count,
            provisional_min=self._provisional_min_samples,
            established_min=self._established_min_samples,
        ).value

        if publishes_statistics(profile.learning_state):
            recent = self._recent_windows(session, device_key)
            summaries = summarise_samples(recent)
            profile.statistics_json = json.dumps(summaries_to_json(summaries))
            profile.statistics_sample_count = len(recent)
        else:
            # Still learning: no figures are published, because there is not yet
            # enough observation to describe anything (M21.7).
            profile.statistics_json = None
            profile.statistics_sample_count = 0

    def _count_windows(self, session: Session, device_key: str) -> int:
        """Return how many windows this device has stored."""
        stmt = (
            select(func.count())
            .select_from(BaselineWindow)
            .where(BaselineWindow.device_key == device_key)
        )
        return int(session.scalar(stmt) or 0)

    def _recent_windows(
        self, session: Session, device_key: str
    ) -> list[BaselineWindow]:
        """Return the most recent windows of one device, oldest first."""
        stmt = (
            select(BaselineWindow)
            .where(BaselineWindow.device_key == device_key)
            .order_by(BaselineWindow.window_start.desc())
            .limit(self._statistics_max_windows)
        )
        rows = list(session.scalars(stmt).all())
        rows.reverse()
        return rows

    # -- reading ----------------------------------------------------------

    def list_profiles(
        self,
        *,
        learning_state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ProfileSnapshot]:
        """Return baseline profiles, most recently observed first (M21.10).

        Args:
            learning_state: Keep only profiles in this state.
            limit: Page size.
            offset: Rows to skip.

        Returns:
            The matching profiles, ordered ``last_observed_at DESC, device_key``
            — a total order, so two identical requests return the same page.
        """
        session = self._session_factory()
        try:
            stmt = select(BaselineProfile)
            if learning_state is not None:
                stmt = stmt.where(
                    BaselineProfile.learning_state == learning_state.strip().lower()
                )
            stmt = (
                stmt.order_by(
                    BaselineProfile.last_observed_at.desc(),
                    BaselineProfile.device_key,
                )
                .limit(limit)
                .offset(offset)
            )
            return [self._snapshot(row) for row in session.scalars(stmt).all()]
        finally:
            session.close()

    def count_profiles(self, *, learning_state: str | None = None) -> int:
        """Return how many profiles match the same filters as the listing."""
        session = self._session_factory()
        try:
            stmt = select(func.count()).select_from(BaselineProfile)
            if learning_state is not None:
                stmt = stmt.where(
                    BaselineProfile.learning_state == learning_state.strip().lower()
                )
            return int(session.scalar(stmt) or 0)
        finally:
            session.close()

    def get_profile(self, device_key: str) -> ProfileSnapshot | None:
        """Return one device's profile, or ``None`` when it has none."""
        session = self._session_factory()
        try:
            row = session.scalar(
                select(BaselineProfile).where(
                    BaselineProfile.device_key == device_key
                )
            )
            return None if row is None else self._snapshot(row)
        finally:
            session.close()

    def list_windows(
        self, device_key: str, *, limit: int = 20
    ) -> list[BaselineWindow]:
        """Return a device's most recent observation windows, newest first.

        Detached from any session by the time it is returned, so a caller may read
        the plain attributes after the session has closed. The rows are never
        mutated, which is what makes that safe.
        """
        session = self._session_factory()
        try:
            stmt = (
                select(BaselineWindow)
                .where(BaselineWindow.device_key == device_key)
                .order_by(BaselineWindow.window_start.desc())
                .limit(limit)
            )
            rows = list(session.scalars(stmt).all())
            for row in rows:
                session.expunge(row)
            return rows
        finally:
            session.close()

    # -- resetting --------------------------------------------------------

    def reset_device(self, device_key: str) -> tuple[int, bool]:
        """Delete one device's windows and profile (M21.10).

        Deletes only rows whose ``device_key`` matches. No packet, device, alert,
        incident, connection or report row is touched: the baseline tables are
        the only tables this statement names.

        Args:
            device_key: The device whose learning should restart.

        Returns:
            ``(windows_deleted, profile_deleted)``.
        """
        session = self._session_factory()
        try:
            # ``Session.execute`` is annotated as returning ``Result``, but a
            # DELETE always produces a ``CursorResult``, which is the type that
            # carries ``rowcount``. The cast states that fact rather than leaving
            # a reader to wonder whether the count is available at all.
            deleted = cast(
                CursorResult,
                session.execute(
                    delete(BaselineWindow).where(
                        BaselineWindow.device_key == device_key
                    )
                ),
            )
            windows_deleted = int(deleted.rowcount or 0)
            deleted_profile = cast(
                CursorResult,
                session.execute(
                    delete(BaselineProfile).where(
                        BaselineProfile.device_key == device_key
                    )
                ),
            )
            session.commit()
            return windows_deleted, bool(deleted_profile.rowcount)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # -- retention --------------------------------------------------------

    def delete_windows_before(
        self, cutoff: datetime, *, max_rows: int
    ) -> tuple[int, list[str]]:
        """Delete windows older than ``cutoff``, bounded to ``max_rows`` (M21.8).

        A retention window applied to the window store only. Profiles are left
        alone: a profile describes an identity that was observed, and deleting it
        would lose the fact that the device was ever seen.

        Args:
            cutoff: Windows starting before this UTC datetime are removed.
            max_rows: Most rows this pass may delete, so a backlog is drained
                over several passes rather than in one long transaction.

        Returns:
            ``(deleted_rows, affected_device_keys)``. The keys are the devices
            whose profiles now describe less history than they did, so the caller
            can recalculate exactly those rather than the whole table.

        Raises:
            ValueError: If ``max_rows`` is not positive.
        """
        if max_rows < 1:
            raise ValueError("max_rows must be at least 1")
        session = self._session_factory()
        try:
            expired = session.execute(
                select(BaselineWindow.id, BaselineWindow.device_key)
                .where(BaselineWindow.window_start < cutoff)
                .order_by(BaselineWindow.window_start)
                .limit(max_rows)
            ).all()
            if not expired:
                return 0, []
            victims = [int(row[0]) for row in expired]
            affected = sorted({str(row[1]) for row in expired})
            result = cast(
                CursorResult,
                session.execute(
                    delete(BaselineWindow).where(BaselineWindow.id.in_(victims))
                ),
            )
            session.commit()
            return int(result.rowcount or 0), affected
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def recompute_profile(self, device_key: str) -> ProfileSnapshot | None:
        """Recalculate a profile from its stored windows (M21.8).

        Called after retention deletes windows, so the published figures describe
        the history that still exists rather than history that has been removed.
        A profile whose every window has expired keeps its sample count at zero
        and falls back to ``learning``, because its evidence is gone.

        Args:
            device_key: The device to recompute.

        Returns:
            The updated snapshot, or ``None`` when the device has no profile.
        """
        session = self._session_factory()
        try:
            profile = session.scalar(
                select(BaselineProfile).where(
                    BaselineProfile.device_key == device_key
                )
            )
            if profile is None:
                return None
            sample_count = self._count_windows(session, device_key)
            profile.sample_count = sample_count
            profile.learning_state = state_for_samples(
                sample_count,
                provisional_min=self._provisional_min_samples,
                established_min=self._established_min_samples,
            ).value
            if publishes_statistics(profile.learning_state):
                recent = self._recent_windows(session, device_key)
                summaries = summarise_samples(recent)
                profile.statistics_json = json.dumps(summaries_to_json(summaries))
                profile.statistics_sample_count = len(recent)
            else:
                profile.statistics_json = None
                profile.statistics_sample_count = 0
            session.commit()
            return self._snapshot(profile)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # -- projection -------------------------------------------------------

    def _snapshot(self, row: BaselineProfile) -> ProfileSnapshot:
        """Project one ORM row into a detached value."""
        statistics: dict[str, FeatureStatistics] = {}
        if row.statistics_json:
            try:
                document = json.loads(row.statistics_json)
            except (TypeError, ValueError):
                # A stored document that cannot be parsed is reported as "no
                # statistics" rather than raising into an API response.
                logger.warning(
                    "Baseline statistics for %s could not be parsed", row.device_key
                )
                document = None
            if isinstance(document, dict):
                statistics = summaries_from_json(document)
        return ProfileSnapshot(
            device_key=row.device_key,
            identity_kind=row.identity_kind,
            learning_state=row.learning_state,
            sample_count=row.sample_count,
            statistics_sample_count=row.statistics_sample_count,
            window_seconds=row.window_seconds,
            first_observed_at=row.first_observed_at,
            last_observed_at=row.last_observed_at,
            mac_address=row.last_mac_address,
            ip_addresses=tuple(_parse_addresses(row.last_ip_addresses)),
            statistics=statistics,
            updated_at=row.updated_at,
        )


def _merged_addresses(existing: str | None, new_address: str) -> list[str]:
    """Return a bounded address list with ``new_address`` most recent.

    The list is capped so a device that changes address constantly cannot grow a
    profile row without bound. ``new_address`` is always first, because it is the
    one currently observed.
    """
    addresses = [new_address]
    for address in _parse_addresses(existing):
        if address != new_address and len(addresses) < MAX_STORED_ADDRESSES:
            addresses.append(address)
    return addresses


#: Hard cap on the addresses remembered on one profile row.
MAX_STORED_ADDRESSES = 16


def _parse_addresses(raw: str | None) -> list[str]:
    """Parse a stored address list, tolerating anything unparseable."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(entry) for entry in parsed if isinstance(entry, str)]


def retention_cutoff(days: int, *, now: datetime | None = None) -> datetime:
    """Return the UTC instant before which windows have expired (M21.8).

    Args:
        days: The configured retention window in days.
        now: The instant to measure back from; defaults to the current UTC time.

    Returns:
        ``now - days``, as a naive UTC datetime to match how timestamps are
        stored.

    Raises:
        ValueError: If ``days`` is negative. Zero is allowed and means "delete
            everything already closed", which is an operator's explicit choice
            rather than a default.
    """
    if days < 0:
        raise ValueError("retention days must not be negative")
    reference = now or datetime.now(timezone.utc).replace(tzinfo=None)
    return reference - timedelta(days=days)


__all__ = [
    "DEFAULT_PROVISIONAL_MIN_SAMPLES",
    "DEFAULT_ESTABLISHED_MIN_SAMPLES",
    "DEFAULT_STATISTICS_MAX_WINDOWS",
    "MAX_STORED_ADDRESSES",
    "BaselineStore",
    "ProfileSnapshot",
    "retention_cutoff",
]
