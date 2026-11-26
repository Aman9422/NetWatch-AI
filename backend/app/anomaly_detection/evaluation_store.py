"""Persistence of M22 evaluation outcomes (M22.8/M22.10).

One row per ``(device_key, window_start)``. The unique constraint is what makes a
repeated flush, a retried evaluation, a backend restart and a WebSocket reconnect
all idempotent (M22.8).

## Why a retry does not overwrite the first verdict

:meth:`EvaluationStore.write` returns ``(snapshot, created)`` and leaves an
existing row untouched. A second verdict on the same observation, reached by a
model retrained on data that now includes it, is neither more truthful nor
comparable to the first: the first was reached without leakage, the second cannot
be. Keeping the first and reporting ``created=False`` is the honest answer.

## Retention is asymmetric on purpose

Evaluation rows age out; model metadata does not. A model describes a device's
learned behaviour and the fact that it was ever trained, and deleting it because
its verdicts expired would lose that and force a pointless retrain. The asymmetry
is the same one M21 applies to profiles versus windows (M22.10).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from app.anomaly_detection.features import FEATURE_SCHEMA_VERSION
from app.models.anomaly import AnomalyEvaluation
from app.persistence.session_factory import SessionFactory, app_session_factory

logger = logging.getLogger(__name__)

#: Statuses an evaluation row can carry.
STATUS_SCORED = "scored"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"

#: Every accepted status, for validation and the API's closed vocabulary.
EVALUATION_STATUSES: tuple[str, ...] = (
    STATUS_SCORED,
    STATUS_SKIPPED,
    STATUS_FAILED,
)

#: Stable skip reasons, so the UI can explain a non-verdict in words rather than
#: inventing one. Recorded on the row rather than inferred later.
SKIP_INSUFFICIENT_DATA = "insufficient_training_data"
SKIP_NO_MODEL = "model_unavailable"
SKIP_NOT_ENOUGH_FEATURES = "insufficient_features"
SKIP_MODEL_FAILED = "model_failed"


@dataclass(frozen=True)
class EvaluationSnapshot:
    """One persisted evaluation outcome (M22.12).

    Attributes:
        decision_score: Raw ``decision_function`` output; lower is more unusual.
            ``None`` for a row that was not scored. **Never a probability.**
        status: ``scored``, ``skipped`` or ``failed``. "Could not be evaluated"
            and "was evaluated as normal" are different answers, and only the
            second is a claim about the traffic.
    """

    evaluation_id: int
    device_key: str
    window_start: datetime
    window_seconds: float
    algorithm: str
    model_version: int
    model_trained_at: datetime | None
    feature_schema_version: int
    training_sample_count: int
    contamination: float | None
    decision_score: float | None
    is_anomaly: bool
    status: str
    skip_reason: str | None
    feature_context: list[dict[str, Any]] = field(default_factory=list)
    alert_id: int | None = None
    created_at: datetime | None = None

    @property
    def was_scored(self) -> bool:
        """Return True when this row is a model verdict rather than a skip."""
        return self.status == STATUS_SCORED


class EvaluationStore:
    """Reads and writes the ``anomaly_evaluations`` table (M22.8/M22.10)."""

    def __init__(self, *, session_factory: SessionFactory | None = None) -> None:
        """Create the store."""
        self._session_factory = session_factory or app_session_factory

    # -- writing ----------------------------------------------------------

    def write(
        self,
        *,
        device_key: str,
        window_start: datetime,
        window_seconds: float,
        algorithm: str,
        model_version: int,
        model_trained_at: datetime | None,
        training_sample_count: int,
        contamination: float | None,
        decision_score: float | None,
        is_anomaly: bool,
        status: str,
        skip_reason: str | None = None,
        feature_context: list[dict[str, Any]] | None = None,
        alert_id: int | None = None,
    ) -> tuple[EvaluationSnapshot | None, bool]:
        """Persist one evaluation outcome, idempotently (M22.8).

        Returns:
            ``(snapshot, created)``. ``created`` is False when a row already
            existed for this device and window, in which case the stored row is
            returned unchanged — a retried evaluation must not overwrite the first
            verdict with a later model's opinion.

        Raises:
            ValueError: If ``status`` is not a known value.
        """
        if status not in EVALUATION_STATUSES:
            raise ValueError(f"unknown evaluation status: {status!r}")
        session = self._session_factory()
        try:
            existing = session.scalar(
                select(AnomalyEvaluation).where(
                    AnomalyEvaluation.device_key == device_key,
                    AnomalyEvaluation.window_start == window_start,
                )
            )
            if existing is not None:
                snapshot = to_evaluation_snapshot(existing)
                session.expunge(existing)
                return snapshot, False

            row = AnomalyEvaluation(
                device_key=device_key,
                window_start=window_start,
                window_seconds=window_seconds,
                algorithm=algorithm,
                model_version=model_version,
                model_trained_at=model_trained_at,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                training_sample_count=training_sample_count,
                contamination=contamination,
                decision_score=decision_score,
                is_anomaly=is_anomaly,
                status=status,
                skip_reason=skip_reason,
                feature_context_json=(
                    json.dumps(feature_context) if feature_context else None
                ),
                alert_id=alert_id,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            snapshot = to_evaluation_snapshot(row)
            session.expunge(row)
            return snapshot, True
        except IntegrityError:
            # A concurrent evaluation of the same window won the race. The unique
            # constraint is what makes that safe; the loser reports the stored row.
            session.rollback()
            return self.for_window(device_key, window_start), False
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def set_alert_id(self, evaluation_id: int, alert_id: int | None) -> None:
        """Attach the alert an anomalous evaluation produced (M22.11).

        Best effort: the anomaly record is the primary evidence and must survive
        an alerting failure, so a failure here is logged, never raised.
        """
        if alert_id is None:
            return
        session = self._session_factory()
        try:
            row = session.get(AnomalyEvaluation, evaluation_id)
            if row is None:
                return
            row.alert_id = alert_id
            session.commit()
        except Exception:  # noqa: BLE001 - alert linkage is enrichment
            session.rollback()
            logger.warning(
                "Could not link alert %s to anomaly evaluation %s",
                alert_id,
                evaluation_id,
            )
        finally:
            session.close()

    # -- reading ----------------------------------------------------------

    def get(self, evaluation_id: int) -> EvaluationSnapshot | None:
        """Return one evaluation by identifier, or ``None``."""
        session = self._session_factory()
        try:
            row = session.get(AnomalyEvaluation, evaluation_id)
            if row is None:
                return None
            snapshot = to_evaluation_snapshot(row)
            session.expunge(row)
            return snapshot
        finally:
            session.close()

    def for_window(
        self, device_key: str, window_start: datetime
    ) -> EvaluationSnapshot | None:
        """Return the stored evaluation of one window, or ``None``.

        The idempotency probe: a repeated flush, a service retry, a restart and a
        WebSocket reconnect all reduce to this question (M22.8).
        """
        session = self._session_factory()
        try:
            row = session.scalar(
                select(AnomalyEvaluation).where(
                    AnomalyEvaluation.device_key == device_key,
                    AnomalyEvaluation.window_start == window_start,
                )
            )
            if row is None:
                return None
            snapshot = to_evaluation_snapshot(row)
            session.expunge(row)
            return snapshot
        finally:
            session.close()

    def list(
        self,
        *,
        device_key: str | None = None,
        is_anomaly: bool | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvaluationSnapshot]:
        """Return evaluation outcomes, newest window first (M22.12).

        Filters combine with AND. ``since`` is inclusive and ``until`` exclusive,
        so two adjacent windows never both claim the same instant (M13.26).
        Ordering is ``window_start DESC, id DESC`` — a total order, so pagination
        cannot repeat or skip a row when two windows share a start.
        """
        session = self._session_factory()
        try:
            stmt = self._filtered(
                device_key=device_key,
                is_anomaly=is_anomaly,
                status=status,
                since=since,
                until=until,
            )
            stmt = (
                stmt.order_by(
                    AnomalyEvaluation.window_start.desc(),
                    AnomalyEvaluation.id.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
            rows = list(session.scalars(stmt).all())
            snapshots = [to_evaluation_snapshot(row) for row in rows]
            for row in rows:
                session.expunge(row)
            return snapshots
        finally:
            session.close()

    def count(
        self,
        *,
        device_key: str | None = None,
        is_anomaly: bool | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        """Return how many evaluations match the same filters as the listing."""
        session = self._session_factory()
        try:
            base = self._filtered(
                device_key=device_key,
                is_anomaly=is_anomaly,
                status=status,
                since=since,
                until=until,
            )
            return int(
                session.scalar(select(func.count()).select_from(base.subquery())) or 0
            )
        finally:
            session.close()

    def summary(self) -> dict[str, int]:
        """Return counted totals for the page tiles (M22.13).

        One indexed aggregate per figure rather than a scan of every row.
        """
        session = self._session_factory()
        try:
            total = int(
                session.scalar(select(func.count()).select_from(AnomalyEvaluation))
                or 0
            )
            anomalous = int(
                session.scalar(
                    select(func.count())
                    .select_from(AnomalyEvaluation)
                    .where(AnomalyEvaluation.is_anomaly.is_(True))
                )
                or 0
            )
            affected = int(
                session.scalar(
                    select(func.count(func.distinct(AnomalyEvaluation.device_key)))
                    .select_from(AnomalyEvaluation)
                    .where(AnomalyEvaluation.is_anomaly.is_(True))
                )
                or 0
            )
            scored = int(
                session.scalar(
                    select(func.count())
                    .select_from(AnomalyEvaluation)
                    .where(AnomalyEvaluation.status == STATUS_SCORED)
                )
                or 0
            )
            return {
                "evaluations": total,
                "anomalies": anomalous,
                "affected_devices": affected,
                "scored": scored,
                "skipped": total - scored,
            }
        finally:
            session.close()

    def _filtered(
        self,
        *,
        device_key: str | None,
        is_anomaly: bool | None,
        status: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> Any:
        """Build the statement the listing and the count share.

        Shared so a reported total can never disagree with the page it
        accompanies (M13.24).
        """
        stmt = select(AnomalyEvaluation)
        if device_key is not None:
            stmt = stmt.where(AnomalyEvaluation.device_key == device_key.strip())
        if is_anomaly is not None:
            stmt = stmt.where(AnomalyEvaluation.is_anomaly.is_(bool(is_anomaly)))
        if status is not None:
            stmt = stmt.where(AnomalyEvaluation.status == status.strip().lower())
        if since is not None:
            stmt = stmt.where(AnomalyEvaluation.window_start >= since)
        if until is not None:
            stmt = stmt.where(AnomalyEvaluation.window_start < until)
        return stmt

    # -- retention --------------------------------------------------------

    def delete_before(self, cutoff: datetime, *, max_rows: int) -> int:
        """Delete evaluation rows older than ``cutoff``, bounded (M22.10).

        Args:
            cutoff: Evaluations created before this UTC datetime are removed.
            max_rows: Most rows one pass may delete, so a backlog drains over
                several passes rather than inside one long transaction.

        Returns:
            How many rows were removed.

        Raises:
            ValueError: If ``max_rows`` is not positive.
        """
        if max_rows < 1:
            raise ValueError("max_rows must be at least 1")
        session = self._session_factory()
        try:
            victims = session.scalars(
                select(AnomalyEvaluation.id)
                .where(AnomalyEvaluation.created_at < cutoff)
                .order_by(AnomalyEvaluation.created_at)
                .limit(max_rows)
            ).all()
            if not victims:
                return 0
            result = cast(
                CursorResult,
                session.execute(
                    delete(AnomalyEvaluation).where(
                        AnomalyEvaluation.id.in_(
                            [int(identifier) for identifier in victims]
                        )
                    )
                ),
            )
            session.commit()
            return int(result.rowcount or 0)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def to_evaluation_snapshot(row: AnomalyEvaluation) -> EvaluationSnapshot:
    """Project one ORM row into a detached value.

    A stored context document that will not parse is reported as absent rather
    than raising: one malformed context must not make an otherwise readable
    verdict unreadable.
    """
    context: list[dict[str, Any]] = []
    if row.feature_context_json:
        try:
            parsed = json.loads(row.feature_context_json)
        except (TypeError, ValueError):
            logger.warning(
                "Feature context for anomaly evaluation %s could not be parsed",
                row.id,
            )
            parsed = None
        if isinstance(parsed, list):
            context = [entry for entry in parsed if isinstance(entry, dict)]
    return EvaluationSnapshot(
        evaluation_id=int(row.id or 0),
        device_key=row.device_key,
        window_start=row.window_start,
        window_seconds=row.window_seconds,
        algorithm=row.algorithm,
        model_version=row.model_version,
        model_trained_at=row.model_trained_at,
        feature_schema_version=row.feature_schema_version,
        training_sample_count=row.training_sample_count,
        contamination=row.contamination,
        decision_score=row.decision_score,
        is_anomaly=row.is_anomaly,
        status=row.status,
        skip_reason=row.skip_reason,
        feature_context=context,
        alert_id=row.alert_id,
        created_at=row.created_at,
    )


def retention_cutoff(days: int, *, now: datetime | None = None) -> datetime:
    """Return the UTC instant before which evaluations have expired (M22.10).

    Args:
        days: The configured retention window in days.
        now: The instant to measure back from; defaults to the current UTC time.

    Returns:
        ``now - days`` as a naive UTC datetime, matching how timestamps are
        stored.

    Raises:
        ValueError: If ``days`` is negative. Zero is allowed and means "delete
            everything already recorded", which is an operator's explicit choice
            rather than a default.
    """
    if days < 0:
        raise ValueError("retention days must not be negative")
    reference = now or datetime.now(timezone.utc).replace(tzinfo=None)
    return reference - timedelta(days=days)


__all__ = [
    "EVALUATION_STATUSES",
    "SKIP_INSUFFICIENT_DATA",
    "SKIP_MODEL_FAILED",
    "SKIP_NO_MODEL",
    "SKIP_NOT_ENOUGH_FEATURES",
    "STATUS_FAILED",
    "STATUS_SCORED",
    "STATUS_SKIPPED",
    "EvaluationSnapshot",
    "EvaluationStore",
    "retention_cutoff",
    "to_evaluation_snapshot",
]
