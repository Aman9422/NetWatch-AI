"""Historical training-data selection (M22.5).

A window must never be part of the dataset used to score it (M22.8). M21 has
already persisted the window by the time M22 sees it, so "the most recent N
windows" would include the window under evaluation. Every query here carries a
strict ``window_start < before`` bound taken from the window being evaluated.

``max_windows`` caps how many rows are read into memory (M22.5) and is applied to
the *newest* rows before the cutoff, so a device with months of history trains on
its recent behaviour. The result is returned oldest first, because a deterministic
order is what makes a training matrix reproducible.

Where enough history remains, windows M22 already classified as anomalous are
excluded: an Isolation Forest fitted on the very outliers it found would learn
them as normal. The exclusion applies only while at least ``min_windows`` windows
survive it, so a mostly-flagged device is still trained on what it has.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.anomaly import AnomalyEvaluation
from app.models.baseline_observation import BaselineWindow
from app.persistence.session_factory import SessionFactory, app_session_factory


@dataclass(frozen=True)
class TrainingDataset:
    """A bounded historical training set for one device (M22.5)."""

    windows: list[Any] = field(default_factory=list)
    excluded_anomalies: int = 0
    offered: int = 0

    @property
    def count(self) -> int:
        """Return how many windows are usable for training."""
        return len(self.windows)


class TrainingDatasetReader:
    """Selects the historical windows a model may be trained on (M22.5)."""

    def __init__(self, *, session_factory: SessionFactory | None = None) -> None:
        """Create the reader."""
        self._session_factory = session_factory or app_session_factory

    def select(
        self,
        device_key: str,
        *,
        before: datetime,
        max_windows: int,
        exclude_anomalies: bool = True,
        min_windows: int = 0,
    ) -> TrainingDataset:
        """Return a device's historical windows strictly before ``before``.

        Raises:
            ValueError: If ``max_windows`` is not positive.
        """
        if max_windows < 1:
            raise ValueError("max_windows must be at least 1")
        session = self._session_factory()
        try:
            rows = list(
                session.scalars(
                    select(BaselineWindow)
                    .where(
                        BaselineWindow.device_key == device_key,
                        BaselineWindow.window_start < before,
                    )
                    .order_by(BaselineWindow.window_start.desc())
                    .limit(max_windows)
                ).all()
            )
            offered = len(rows)
            excluded = 0
            if exclude_anomalies and rows:
                rows, excluded = self._exclude_flagged(
                    session,
                    device_key=device_key,
                    before=before,
                    rows=rows,
                    min_windows=min_windows,
                )
            for row in rows:
                session.expunge(row)
            rows.reverse()
            return TrainingDataset(
                windows=rows, excluded_anomalies=excluded, offered=offered
            )
        finally:
            session.close()

    def _exclude_flagged(
        self,
        session: Session,
        *,
        device_key: str,
        before: datetime,
        rows: list[BaselineWindow],
        min_windows: int,
    ) -> tuple[list[BaselineWindow], int]:
        """Withhold previously flagged windows while enough history survives."""
        flagged = session.scalars(
            select(AnomalyEvaluation.window_start).where(
                AnomalyEvaluation.device_key == device_key,
                AnomalyEvaluation.is_anomaly.is_(True),
                AnomalyEvaluation.window_start < before,
            )
        ).all()
        if not flagged:
            return rows, 0
        flagged_starts = set(flagged)
        kept = [row for row in rows if row.window_start not in flagged_starts]
        if len(kept) < max(min_windows, 1):
            return rows, 0
        return kept, len(rows) - len(kept)

    def get_window(self, device_key: str, window_start: datetime) -> Any | None:
        """Return one persisted observation window, or ``None``.

        The engine uses this to confirm the window it was handed really exists
        before evaluating it, so a verdict can never describe an observation that
        was never stored.

        The row is detached before it is returned, because the caller reads plain
        attributes after the session closes.
        """
        session = self._session_factory()
        try:
            row = session.scalar(
                select(BaselineWindow).where(
                    BaselineWindow.device_key == device_key,
                    BaselineWindow.window_start == window_start,
                )
            )
            if row is not None:
                session.expunge(row)
            return row
        finally:
            session.close()

    def count_before(self, device_key: str, *, before: datetime) -> int:
        """Return how many of a device's windows precede ``before``."""
        session = self._session_factory()
        try:
            stmt = (
                select(func.count())
                .select_from(BaselineWindow)
                .where(
                    BaselineWindow.device_key == device_key,
                    BaselineWindow.window_start < before,
                )
            )
            return int(session.scalar(stmt) or 0)
        finally:
            session.close()

    def latest_window_start(self, device_key: str) -> datetime | None:
        """Return the start of a device's most recent persisted window."""
        session = self._session_factory()
        try:
            return session.scalar(
                select(BaselineWindow.window_start)
                .where(BaselineWindow.device_key == device_key)
                .order_by(BaselineWindow.window_start.desc())
                .limit(1)
            )
        finally:
            session.close()


__all__ = ["TrainingDataset", "TrainingDatasetReader"]
