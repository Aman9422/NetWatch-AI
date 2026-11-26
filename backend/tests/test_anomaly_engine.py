"""The M22 engine: evaluation, idempotency, inference and alerting (M22.8-M22.11).

These tests drive the engine the way the lifespan does, over a real (in-memory)
database, so the dataset cutoff, the store's uniqueness constraint and the finding
hand-off are all exercised together rather than mocked apart.

The properties asserted here are the ones whose failure is invisible in the logs:

* a window is never scored against a model trained on itself;
* a repeated flush does not create a second verdict or a second alert;
* a window the model could not evaluate is stored as *skipped*, never as normal;
* an anomaly record survives even when alerting is unavailable;
* a failure anywhere in the ML layer leaves M21 learning untouched.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.anomaly_detection.engine import PendingWindow, windows_from_counters
from app.anomaly_detection.evaluation_store import (
    STATUS_FAILED,
    STATUS_SCORED,
    STATUS_SKIPPED,
    SKIP_INSUFFICIENT_DATA,
)
from app.anomaly_detection.inference import (
    FAR_FROM_CENTRE_MADS,
    build_context,
    evaluate_window,
)
from app.anomaly_detection.features import build_feature_vector
from app.anomaly_detection.preprocessing import build_plan, to_matrix, to_row
from app.anomaly_detection.model import ModelConfig, build_model
from tests.anomaly_fakes import (
    BASE_TIME,
    DEVICE_MAC,
    RecordingAlertSink,
    make_engine,
    make_window,
    normal_windows,
    persist_windows,
    unusual_window,
    window_before,
)


def epoch(minute: int) -> float:
    """Return a window start as epoch seconds, which is what M21 hands over."""
    return window_before(minute).replace(tzinfo=timezone.utc).timestamp()


def pending(minute: int, device_key: str = DEVICE_MAC) -> PendingWindow:
    """Build one evaluation request for a synthetic window."""
    return PendingWindow(
        device_key=device_key, window_start=epoch(minute), window_seconds=60.0
    )


# ---------------------------------------------------------------------------
# conversion from M21's counters
# ---------------------------------------------------------------------------


def test_m21_counters_convert_to_evaluation_requests() -> None:
    """The listener's input is M21's own object; the shapes must line up."""

    class Counters:
        device_key = DEVICE_MAC
        window_start = 1_700_000_000.0
        window_seconds = 60.0

    requests = windows_from_counters([Counters()])

    assert len(requests) == 1
    assert requests[0].device_key == DEVICE_MAC
    assert requests[0].window_start == 1_700_000_000.0
    assert requests[0].window_seconds == 60.0


def test_an_unusable_counter_object_is_skipped_rather_than_raising() -> None:
    """A consumer must not break M21's flush with a shape it did not expect."""
    assert windows_from_counters([object(), None]) == []


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def test_a_normal_window_is_scored_and_persisted(session_factory) -> None:
    """The ordinary path: a fitted model produces and stores a verdict."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)

    snapshot = engine.evaluate(pending(20))

    assert snapshot is not None
    assert snapshot.status == STATUS_SCORED
    assert snapshot.decision_score is not None
    assert snapshot.training_sample_count == 20
    assert snapshot.model_version == 1


def test_the_evaluated_window_is_not_in_its_own_training_set(session_factory) -> None:
    """The strict cutoff, asserted at the engine rather than only at the query.

    Thirty windows exist and the twentieth is evaluated, so exactly the twenty
    before it may be used. If the evaluated window leaked in, the count would be
    twenty-one.
    """
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=10)

    snapshot = engine.evaluate(pending(20))

    assert snapshot is not None
    assert snapshot.training_sample_count == 20


def test_insufficient_history_stores_a_skip_not_a_verdict(session_factory) -> None:
    """ "Could not be evaluated" is a stored, visible outcome (M22.8).

    Reporting it as a normal verdict would be the page's most misleading possible
    statement: the absence of evidence presented as evidence of normality.
    """
    persist_windows(session_factory, normal_windows(5))
    engine = make_engine(session_factory, min_training_windows=20)

    snapshot = engine.evaluate(pending(4))

    assert snapshot is not None
    assert snapshot.status == STATUS_SKIPPED
    assert snapshot.decision_score is None
    assert snapshot.is_anomaly is False
    assert snapshot.skip_reason == SKIP_INSUFFICIENT_DATA


def test_a_repeated_evaluation_creates_no_second_row(session_factory) -> None:
    """A re-flush, a retry and a reconnect all reduce to one verdict (M22.8)."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)

    first = engine.evaluate(pending(20))
    second = engine.evaluate(pending(20))

    assert first is not None and second is not None
    assert first.evaluation_id == second.evaluation_id
    assert engine.store.count(device_key=DEVICE_MAC) == 1


def test_a_duplicate_flush_through_the_queue_is_idempotent(session_factory) -> None:
    """Two enqueues of one window do not produce two verdicts."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)

    engine.enqueue([pending(20), pending(20)])
    engine.drain_once()

    assert engine.store.count(device_key=DEVICE_MAC) == 1


def test_a_missing_window_row_produces_no_verdict(session_factory) -> None:
    """Retention may remove a row between the flush and the evaluation."""
    engine = make_engine(session_factory, min_training_windows=5)

    assert engine.evaluate(pending(3)) is None
    assert engine.store.count(device_key=DEVICE_MAC) == 0


def test_the_anomaly_record_survives_an_unavailable_alert_layer(
    session_factory,
) -> None:
    """The verdict is primary evidence; alerting is enrichment (M22.11)."""
    persist_windows(session_factory, normal_windows(40) + [unusual_window(index=40)])
    engine = make_engine(session_factory, min_training_windows=20, alert_sink=None)

    snapshot = engine.evaluate(pending(40))

    assert snapshot is not None
    assert snapshot.status == STATUS_SCORED
    assert snapshot.alert_id is None


def test_an_anomalous_verdict_raises_a_distinct_detector_finding(
    session_factory,
) -> None:
    """ML findings are identified by ``ml_anomaly``, never as a deterministic rule."""
    sink = RecordingAlertSink()
    persist_windows(session_factory, normal_windows(60) + [unusual_window(index=60)])
    engine = make_engine(
        session_factory, min_training_windows=20, alert_sink=sink
    )

    snapshot = engine.evaluate(pending(60))

    assert snapshot is not None and snapshot.is_anomaly is True
    assert sink.rule_ids == ["ml_anomaly"]
    evidence = sink.findings[0].evidence
    assert "decision_score" in evidence
    assert "contamination" in evidence
    # The finding says what it is not, in its own metadata.
    assert "not proof" in sink.findings[0].metadata["note"]


def test_a_duplicate_evaluation_raises_no_second_finding(session_factory) -> None:
    """Idempotency reaches the alert path too, not only the store (M22.11)."""
    sink = RecordingAlertSink()
    persist_windows(session_factory, normal_windows(60) + [unusual_window(index=60)])
    engine = make_engine(
        session_factory, min_training_windows=20, alert_sink=sink
    )

    engine.evaluate(pending(60))
    engine.evaluate(pending(60))

    assert sink.rule_ids == ["ml_anomaly"]


def test_a_normal_verdict_raises_no_finding(session_factory) -> None:
    """Only a classification of anomalous becomes a finding."""
    sink = RecordingAlertSink()
    persist_windows(session_factory, normal_windows(40))
    engine = make_engine(
        session_factory, min_training_windows=20, alert_sink=sink
    )

    snapshot = engine.evaluate(pending(35))

    assert snapshot is not None and snapshot.is_anomaly is False
    assert sink.findings == []


def test_a_failing_alert_sink_does_not_lose_the_verdict(session_factory) -> None:
    """An alerting fault is contained; the anomaly record is already written."""

    def explode(_findings: list) -> list:
        raise RuntimeError("alert engine unavailable")

    persist_windows(session_factory, normal_windows(60) + [unusual_window(index=60)])
    engine = make_engine(
        session_factory, min_training_windows=20, alert_sink=explode
    )

    snapshot = engine.evaluate(pending(60))

    assert snapshot is not None
    assert snapshot.is_anomaly is True
    assert engine.store.count(device_key=DEVICE_MAC) == 1


def test_the_queue_is_bounded_and_drops_the_oldest(session_factory) -> None:
    """A full queue loses the least useful entry and counts it (M22.14)."""
    engine = make_engine(session_factory)
    for minute in range(70):
        engine.enqueue([pending(minute)])

    assert engine.pending() == 64
    assert engine.get_dropped_count() == 6


def test_a_pass_is_bounded_by_the_configured_budget(session_factory) -> None:
    """A backlog drains gradually rather than in one long pass."""
    engine = make_engine(session_factory)
    for minute in range(20):
        engine.enqueue([pending(minute)])

    processed = engine.drain_once(limit=5)

    assert processed == 5
    assert engine.pending() == 15


def test_start_and_stop_are_idempotent(session_factory) -> None:
    """The lifespan starts and stops it; a second call must be harmless."""
    engine = make_engine(session_factory)

    assert engine.start() is True
    assert engine.start() is False
    engine.stop(drain=False)
    engine.shutdown()


# ---------------------------------------------------------------------------
# inference context
# ---------------------------------------------------------------------------


def test_the_context_compares_against_the_training_set_not_the_window() -> None:
    """The median comes from history; a window cannot be its own reference."""
    windows = [make_window(index=i, packet_count=100) for i in range(5)]
    windows.append(make_window(index=9, packet_count=400))
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)
    model.fit(to_matrix(vectors, plan))

    result = evaluate_window(
        windows[-1], model=model, training_vectors=vectors
    )

    packet_context = next(
        entry for entry in result.feature_context if entry.feature == "packet_count"
    )
    assert packet_context.observed == 400.0
    assert packet_context.training_median == 100.0
    assert packet_context.difference == 300.0
    assert packet_context.far_from_centre is True


def test_a_feature_with_no_spread_is_described_rather_than_divided_by() -> None:
    """Every training window identical is a real state, not an error."""
    windows = [make_window(index=i, packet_count=100) for i in range(5)]
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)
    model.fit(to_matrix(vectors, plan))

    result = evaluate_window(
        make_window(packet_count=400), model=model, training_vectors=vectors
    )

    packet_context = next(
        entry for entry in result.feature_context if entry.feature == "packet_count"
    )
    assert packet_context.deviation_mads is None
    assert packet_context.far_from_centre is True


def test_the_context_covers_only_the_features_the_model_uses() -> None:
    """A comparison for a column the forest ignores would invite attribution."""
    windows = normal_windows(10)
    for window in windows:
        window.new_connections = None
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors, min_availability=0.9)

    contexts = build_context(
        vectors[0], vectors, feature_names=plan.feature_names
    )

    assert [entry.feature for entry in contexts] == list(plan.feature_names)
    assert "new_connections" not in [entry.feature for entry in contexts]


def test_a_window_with_none_of_the_model_features_is_unscored() -> None:
    """An all-imputed row is not a measurement of anything (M22.9)."""
    vectors = [build_feature_vector(window) for window in normal_windows(5)]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)
    model.fit(to_matrix(vectors, plan))

    class Empty:
        device_key = DEVICE_MAC
        window_start = BASE_TIME
        window_seconds = 60.0
        packet_count = None
        byte_count = None
        tcp_packets = None
        udp_packets = None
        icmp_packets = None
        dns_packets = None
        unique_peers = None
        unique_destination_ports = None
        new_connections = None

    result = evaluate_window(Empty(), model=model, training_vectors=vectors)

    assert result.scored is False
    assert result.decision_score is None
    assert result.reason == "no_usable_features_for_model"


def test_the_context_documents_are_json_ready() -> None:
    """What is stored must be plain JSON scalars and lists."""
    import json

    windows = normal_windows(5)
    vectors = [build_feature_vector(window) for window in windows]
    plan = build_plan(vectors)
    model = build_model(config=ModelConfig(), plan=plan)
    model.fit(to_matrix(vectors, plan))

    result = evaluate_window(
        windows[0], model=model, training_vectors=vectors
    )

    # A round trip is the assertion: anything unserialisable raises here.
    assert json.loads(json.dumps(result.context_documents()))
    assert FAR_FROM_CENTRE_MADS == 3.0


def test_the_pending_window_exposes_the_naive_utc_start_m21_stores() -> None:
    """The store keys on a naive UTC datetime, so the conversion is asserted."""
    request = pending(7)

    assert request.window_start_datetime == window_before(7)
    assert request.window_start_datetime.tzinfo is None


def test_a_scoring_failure_is_recorded_as_failed(session_factory, monkeypatch) -> None:
    """A library error becomes a ``failed`` row, not a missing one."""
    persist_windows(session_factory, normal_windows(30))
    engine = make_engine(session_factory, min_training_windows=20)

    def explode(*_args, **_kwargs):
        raise RuntimeError("fitted library failure")

    monkeypatch.setattr("app.anomaly_detection.engine.evaluate_window", explode)

    snapshot = engine.evaluate(pending(20))

    assert snapshot is not None
    assert snapshot.status == STATUS_FAILED
    assert snapshot.skip_reason == "scoring_failed"
    assert engine.get_error_count() == 1
