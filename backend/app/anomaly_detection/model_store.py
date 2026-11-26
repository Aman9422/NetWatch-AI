"""Persistence of M22 model metadata (M22.7/M22.10).

One row per device identity, upserted on each training pass. It carries the
lifecycle state, the model version, the persisted preprocessing plan and the
Isolation Forest configuration.

**Why the plan and configuration are stored rather than the estimator.** No
pickle is written to disk (M22.7 forbids loading a model artifact from an
untrusted path). The plan plus the configuration plus M21's retained windows are
enough to rebuild the forest deterministically — the seed is stored too — so a
restart reconstructs the model instead of trusting a binary file. Until that
reconstruction succeeds the device is reported as unavailable rather than as
having a model.

**What is not stored.** Nothing here retains a packet, a payload, a peer address
or a port. A model row describes *how many* features it uses and *what* it was
configured with, which is the whole of what an operator needs and far less than
what a packet dump would expose.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from app.anomaly_detection.features import FEATURE_SCHEMA_VERSION
from app.anomaly_detection.model import ModelConfig
from app.anomaly_detection.preprocessing import PreprocessingPlan
from app.models.anomaly import AnomalyModel
from app.persistence.session_factory import SessionFactory, app_session_factory

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelSnapshot:
    """A model row as the rest of the application reads it (M22.12).

    A plain value rather than an ORM row, so the API can hold one after the
    session that produced it has closed — which it always has, because the store
    opens and closes a session per call.
    """

    device_key: str
    identity_kind: str
    algorithm: str
    state: str
    model_version: int
    feature_names: tuple[str, ...]
    feature_schema_version: int
    preprocessing: PreprocessingPlan | None
    config: ModelConfig | None
    training_sample_count: int
    training_window_count: int
    min_training_windows: int
    contamination: float | None
    trained_at: datetime | None
    last_evaluated_at: datetime | None
    windows_since_training: int
    last_error: str | None
    updated_at: datetime | None

    @property
    def has_model(self) -> bool:
        """Return True when this row describes a fitted model's configuration."""
        return self.model_version > 0 and self.preprocessing is not None


class ModelStore:
    """Reads and writes the ``anomaly_models`` table (M22.7)."""

    def __init__(self, *, session_factory: SessionFactory | None = None) -> None:
        """Create the store."""
        self._session_factory = session_factory or app_session_factory

    def get(self, device_key: str) -> ModelSnapshot | None:
        """Return one device's model row, or ``None`` when it has none."""
        session = self._session_factory()
        try:
            row = session.scalar(
                select(AnomalyModel).where(AnomalyModel.device_key == device_key)
            )
            return None if row is None else to_model_snapshot(row)
        finally:
            session.close()

    def list(
        self, *, state: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[ModelSnapshot]:
        """Return model rows, most recently evaluated first (M22.12).

        Ordering is ``last_evaluated_at DESC, device_key`` — a total order, so two
        identical requests return the same page (M13.24). A model that has never
        been evaluated sorts last rather than being dropped: a device still
        collecting data is a real answer to "which devices have models".
        """
        session = self._session_factory()
        try:
            stmt = select(AnomalyModel)
            if state is not None:
                stmt = stmt.where(AnomalyModel.state == state.strip().lower())
            stmt = (
                stmt.order_by(
                    AnomalyModel.last_evaluated_at.desc(),
                    AnomalyModel.device_key,
                )
                .limit(limit)
                .offset(offset)
            )
            return [to_model_snapshot(row) for row in session.scalars(stmt).all()]
        finally:
            session.close()

    def count(self, *, state: str | None = None) -> int:
        """Return how many model rows match the same filter as the listing."""
        session = self._session_factory()
        try:
            stmt = select(func.count()).select_from(AnomalyModel)
            if state is not None:
                stmt = stmt.where(AnomalyModel.state == state.strip().lower())
            return int(session.scalar(stmt) or 0)
        finally:
            session.close()

    def save(
        self,
        *,
        device_key: str,
        identity_kind: str,
        state: str,
        model_version: int,
        plan: PreprocessingPlan | None = None,
        config: ModelConfig | None = None,
        training_sample_count: int = 0,
        training_window_count: int = 0,
        min_training_windows: int = 0,
        windows_since_training: int = 0,
        trained_at: datetime | None = None,
        last_error: str | None = None,
    ) -> ModelSnapshot:
        """Create or update one device's model metadata (M22.7).

        The row is upserted rather than inserted so the identity stays unique and
        a retrain is an update, not a second model for the same device.

        Raises:
            Exception: Whatever the database raised. The transaction is rolled
                back, so a failed write leaves the table as it was.
        """
        session = self._session_factory()
        try:
            row = session.scalar(
                select(AnomalyModel).where(AnomalyModel.device_key == device_key)
            )
            if row is None:
                row = AnomalyModel(device_key=device_key)
                session.add(row)
            row.identity_kind = identity_kind
            row.state = state
            row.model_version = model_version
            # The plan is stored whenever the row has one, so a *failed* refresh
            # keeps the previous working model's schema rather than blanking it
            # (M22.7: a failed retrain must preserve the working model).
            if plan is not None:
                row.feature_names_json = json.dumps(list(plan.feature_names))
                row.preprocessing_json = plan.to_json()
                row.feature_schema_version = FEATURE_SCHEMA_VERSION
            if config is not None:
                row.config_json = json.dumps(config.to_dict())
                row.contamination = config.contamination
            row.training_sample_count = training_sample_count
            row.training_window_count = training_window_count
            row.min_training_windows = min_training_windows
            row.windows_since_training = windows_since_training
            if trained_at is not None:
                row.trained_at = trained_at
            row.last_error = last_error
            session.commit()
            session.refresh(row)
            snapshot = to_model_snapshot(row)
            session.expunge(row)
            return snapshot
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def mark_evaluated(self, device_key: str, *, at: datetime) -> None:
        """Record that a device's model was used to score a window (M22.12).

        Best effort: a failure here only makes the "last evaluated" column stale,
        so it is logged rather than raised into the evaluation path.
        """
        session = self._session_factory()
        try:
            row = session.scalar(
                select(AnomalyModel).where(AnomalyModel.device_key == device_key)
            )
            if row is None:
                return
            if row.last_evaluated_at is None or at > row.last_evaluated_at:
                row.last_evaluated_at = at
            session.commit()
        except Exception:  # noqa: BLE001 - a stale timestamp is not a failure
            session.rollback()
            logger.warning("Could not record the evaluation time for %s", device_key)
        finally:
            session.close()


def to_model_snapshot(row: AnomalyModel) -> ModelSnapshot:
    """Project one ORM row into a detached value.

    A stored plan or configuration that will not parse is reported as absent
    rather than raising: the model is then treated as unavailable and retrained,
    which is the safe direction — a model whose columns cannot be named must not
    be used to score anything.
    """
    features: tuple[str, ...] = ()
    if row.feature_names_json:
        features = _parse_string_list(row.feature_names_json)
    return ModelSnapshot(
        device_key=row.device_key,
        identity_kind=row.identity_kind,
        algorithm=row.algorithm,
        state=row.state,
        model_version=row.model_version,
        feature_names=features,
        feature_schema_version=row.feature_schema_version,
        preprocessing=PreprocessingPlan.from_json(row.preprocessing_json),
        config=ModelConfig.from_dict(_parse_json_object(row.config_json)),
        training_sample_count=row.training_sample_count,
        training_window_count=row.training_window_count,
        min_training_windows=row.min_training_windows,
        contamination=row.contamination,
        trained_at=row.trained_at,
        last_evaluated_at=row.last_evaluated_at,
        windows_since_training=row.windows_since_training,
        last_error=row.last_error,
        updated_at=row.updated_at,
    )


def _parse_json_object(raw: str | None) -> dict[str, Any] | None:
    """Parse a stored JSON object, tolerating anything unparseable."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _parse_string_list(raw: str) -> tuple[str, ...]:
    """Parse a stored JSON string list, tolerating anything unparseable."""
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(str(entry) for entry in parsed)


__all__ = ["ModelSnapshot", "ModelStore", "to_model_snapshot"]
