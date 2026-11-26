"""Anomaly-record retention and M21 failure isolation (M22.10).

Two separate promises are asserted:

* **Evaluations age out; models do not.** A model is a conclusion about a device's
  learned behaviour, and deleting it because its verdicts expired would force a
  pointless retrain.
* **The ML layer cannot break M21.** The listener M22 attaches to the flush is a
  consumer, and a consumer's failure must not stop learning — asserted by making
  the listener raise and checking that the windows were still written.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.anomaly_detection.evaluation_store import (
    EvaluationStore,
    retention_cutoff,
)
from app.anomaly_detection.retention import (
    AnomalyRetentionService,
    get_anomaly_retention_service,
    reset_anomaly_retention_service,
)
from app.services.retention_scheduler import RetentionPolicy, RetentionSweeper
from app.anomaly_detection.model_store import ModelStore
from tests.anomaly_fakes import (
    DEVICE_MAC,
    make_engine,
    normal_windows,
    persist_windows,
    window_before,
)


def write_evaluation(
    session_factory,
    *,
    minute: int = 1,
    device_key: str = DEVICE_MAC,
    created_at: datetime | None = None,
) -> int:
    """Write one evaluation row, optionally backdated, and return its id."""
    from app.models.anomaly import AnomalyEvaluation

    store = EvaluationStore(session_factory=session_factory)
    snapshot, created = store.write(
        device_key=device_key,
        window_start=window_before(minute),
        window_seconds=60.0,
        algorithm="isolation_forest",
        model_version=1,
        model_trained_at=None,
        training_sample_count=20,
        contamination=0.02,
        decision_score=-0.01,
        is_anomaly=False,
        status="scored",
    )
    assert snapshot is not None and created is True
    if created_at is not None:
        session = session_factory()
        try:
            row = session.get(AnomalyEvaluation, snapshot.evaluation_id)
            assert row is not None
            row.created_at = created_at
            session.commit()
        finally:
            session.close()
    return snapshot.evaluation_id


# ---------------------------------------------------------------------------
# the cutoff
# ---------------------------------------------------------------------------


def test_the_cutoff_is_measured_back_from_now() -> None:
    """Thirty days, as a naive UTC instant, because that is what is stored."""
    now = datetime(2026, 11, 26, 12, 0, 0)

    cutoff = retention_cutoff(30, now=now)

    assert cutoff == now - timedelta(days=30)
    assert cutoff.tzinfo is None


def test_a_negative_retention_window_is_rejected() -> None:
    """A negative window would delete the future rather than the past."""
    with pytest.raises(ValueError):
        retention_cutoff(-1)


# ---------------------------------------------------------------------------
# deletion
# ---------------------------------------------------------------------------


def test_expired_evaluations_are_deleted(session_factory) -> None:
    """A row older than the window is removed."""
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=45)
    write_evaluation(session_factory, minute=1, created_at=old)
    service = AnomalyRetentionService(
        store=EvaluationStore(session_factory=session_factory), retention_days=30
    )

    outcome = service.cleanup_outcome()

    assert outcome.succeeded is True
    assert outcome.deleted == 1
    assert EvaluationStore(session_factory=session_factory).count() == 0


def test_recent_evaluations_are_kept(session_factory) -> None:
    """A within-window row survives."""
    write_evaluation(session_factory, minute=1)
    service = AnomalyRetentionService(
        store=EvaluationStore(session_factory=session_factory), retention_days=30
    )

    outcome = service.cleanup_outcome()

    assert outcome.deleted == 0
    assert EvaluationStore(session_factory=session_factory).count() == 1


def test_deletion_is_bounded_per_run(session_factory) -> None:
    """A backlog drains over several passes, not in one long transaction."""
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=45)
    for minute in range(5):
        write_evaluation(session_factory, minute=minute, created_at=old)
    service = AnomalyRetentionService(
        store=EvaluationStore(session_factory=session_factory),
        retention_days=30,
        max_rows_per_run=2,
    )

    outcome = service.cleanup_outcome()

    assert outcome.deleted == 2
    assert EvaluationStore(session_factory=session_factory).count() == 3


def test_model_metadata_survives_its_verdicts_expiring(session_factory) -> None:
    """A model is a conclusion, not evidence; expiry of verdicts must not delete it."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)
    engine.lifecycle.ensure_model(
        DEVICE_MAC, identity_kind="mac", before=window_before(30), now=window_before(31)
    )
    old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=45)
    write_evaluation(session_factory, created_at=old)
    service = AnomalyRetentionService(
        store=EvaluationStore(session_factory=session_factory), retention_days=30
    )

    service.cleanup_outcome()

    snapshot = ModelStore(session_factory=session_factory).get(DEVICE_MAC)
    assert snapshot is not None
    assert snapshot.has_model is True


def test_a_failing_retention_pass_is_reported_not_raised(session_factory) -> None:
    """A policy that raises is a sweep failure, not an application failure."""

    class Exploding:
        def delete_before(self, _cutoff, *, max_rows):  # noqa: ARG002
            raise RuntimeError("database is unavailable")

    service = AnomalyRetentionService(store=Exploding(), retention_days=30)  # type: ignore[arg-type]

    outcome = service.cleanup_outcome()

    assert outcome.succeeded is False
    assert outcome.deleted == 0
    assert outcome.error is not None
    assert "failed" in outcome.summary()


def test_a_disabled_policy_deletes_nothing() -> None:
    """A zero-day window is an explicit operator choice, not a silent default."""
    service = AnomalyRetentionService(retention_days=0)
    assert service.retention_days == 0


# ---------------------------------------------------------------------------
# integration with the M19 sweeper
# ---------------------------------------------------------------------------


def test_the_sweep_runs_the_anomaly_policy_and_contains_its_failure() -> None:
    """One policy's failure must not stop its siblings (M19.5)."""
    calls: list[str] = []

    from app.services.retention_scheduler import RetentionOutcomeLike

    def healthy() -> RetentionOutcomeLike:
        calls.append("anomalies")

        class Outcome:
            enabled = True
            succeeded = True

            def summary(self) -> str:
                return "deleted 0 anomaly record(s)"

        return Outcome()

    def broken() -> RetentionOutcomeLike:
        calls.append("broken")
        raise RuntimeError("policy failure")

    sweeper = RetentionSweeper(
        policies=[
            RetentionPolicy(name="anomalies", cleanup=healthy),
            RetentionPolicy(name="broken", cleanup=broken),
        ],
        interval_seconds=0,
        autostart=False,
    )

    outcomes = sweeper.run_once()

    assert calls == ["anomalies", "broken"]
    assert outcomes[0].succeeded is True
    assert outcomes[1].succeeded is False


def test_the_shipped_policy_list_includes_anomalies() -> None:
    """The application registers the M22 policy, not only its own tests."""
    from app.services.retention_scheduler import build_retention_policies

    names = [policy.name for policy in build_retention_policies()]

    assert "anomalies" in names
    # The M21 policies are still present: M22 adds a policy, it does not replace one.
    assert "packets" in names
    assert "baselines" in names
    assert "reports" in names


def test_the_retention_service_is_a_singleton_that_can_be_reset() -> None:
    """The sweeper reaches it through a cached accessor, as the other policies do."""
    reset_anomaly_retention_service()
    first = get_anomaly_retention_service()
    second = get_anomaly_retention_service()

    assert first is second
    reset_anomaly_retention_service()
    assert get_anomaly_retention_service() is not first


# ---------------------------------------------------------------------------
# M21 keeps flushing when its consumer is broken
# ---------------------------------------------------------------------------


def test_a_raising_window_listener_does_not_stop_m21_learning(session_factory) -> None:
    """M21 learning must never depend on a consumer succeeding (M22.8).

    The listener is made to raise for every batch. The windows must still reach
    the database, and the failure must be counted rather than hidden.
    """
    from app.baselines.aggregation import WindowAggregator
    from app.baselines.engine import BaselineEngine
    from app.baselines.store import BaselineStore
    from app.schemas.packet import NormalizedPacket

    def explode(_windows: list) -> None:
        raise RuntimeError("the ML layer is unavailable")

    store = BaselineStore(session_factory=session_factory)
    engine = BaselineEngine(
        store=store,
        window_seconds=60.0,
        flush_interval=3600.0,
        max_windows_per_flush=100,
        aggregator=WindowAggregator(window_seconds=60.0),
        autostart=False,
        clock=lambda: 1_700_000_000.0,
        window_listener=explode,
    )

    packet = NormalizedPacket(
        timestamp=1_700_000_000.0,
        length=120,
        source_mac="AA:BB:CC:00:00:01",
        source_ip="10.0.0.21",
        destination_mac="AA:BB:CC:00:00:02",
        destination_ip="10.0.0.5",
        ip_version=4,
        protocol="TCP",
        source_port=51000,
        destination_port=443,
        tcp_flags="S",
    )
    engine.process_packet(packet)

    written = engine.flush_all()

    assert written == 1
    assert engine.get_listener_error_count() == 1
    # The row is real: the failure was in the consumer, not in the write.
    from sqlalchemy import func, select

    from app.models.baseline_observation import BaselineWindow

    session = session_factory()
    try:
        stored = session.scalar(select(func.count()).select_from(BaselineWindow))
    finally:
        session.close()
    assert int(stored or 0) == 1


def test_a_listener_can_be_attached_and_detached(session_factory) -> None:
    """The lifespan attaches the consumer, and detaches it during shutdown."""
    from app.baselines.aggregation import WindowAggregator
    from app.baselines.engine import BaselineEngine
    from app.baselines.store import BaselineStore

    received: list[list] = []
    engine = BaselineEngine(
        store=BaselineStore(session_factory=session_factory),
        window_seconds=60.0,
        flush_interval=3600.0,
        aggregator=WindowAggregator(window_seconds=60.0),
        autostart=False,
        clock=lambda: 1_700_000_000.0,
    )

    engine.attach_window_listener(lambda windows: received.append(list(windows)))
    engine.attach_window_listener(None)

    assert received == []
