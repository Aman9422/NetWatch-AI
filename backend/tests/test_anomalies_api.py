"""The M22 REST surface (M22.12).

Two things are asserted: the endpoints answer in the project's own envelope with
the documented status codes, and every payload refuses to present a raw model
score as a probability. A regression in the second would be silent — the page
would simply start claiming something the model cannot support.
"""

from __future__ import annotations

from datetime import timezone

import pytest
from fastapi.testclient import TestClient

from app.anomaly_detection import get_anomaly_engine, reset_anomaly_engine
from app.anomaly_detection.engine import PendingWindow
from app.anomaly_detection.evaluation_store import EvaluationStore
from app.api.v1.anomalies import get_engine
from app.main import app
from tests.anomaly_fakes import (
    DEVICE_MAC,
    make_engine,
    normal_windows,
    persist_windows,
    unusual_window,
    window_before,
)


@pytest.fixture
def anomaly_client(session_factory):
    """A test client whose anomaly routes use the isolated database.

    The dependency is overridden rather than the module global patched, so the
    route under test is unchanged and the engine it receives is the real one.
    """
    engine = make_engine(session_factory, min_training_windows=20)
    app.dependency_overrides[get_engine] = lambda: engine
    try:
        with TestClient(app) as client:
            yield client, engine
    finally:
        app.dependency_overrides.pop(get_engine, None)
        reset_anomaly_engine()


# ---------------------------------------------------------------------------
# listing
# ---------------------------------------------------------------------------


def test_the_listing_answers_in_the_shared_envelope(anomaly_client) -> None:
    """Success, message and data, exactly as every other collection does."""
    client, _engine = anomaly_client

    response = client.get("/api/v1/anomalies")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert "anomalies" in body["data"]
    assert "summary" in body["data"]


def test_the_listing_carries_the_disclaimer(anomaly_client) -> None:
    """Every anomaly payload states what an anomaly is not (M22.13)."""
    client, _engine = anomaly_client

    body = client.get("/api/v1/anomalies").json()

    assert "not confirmation of malicious activity" in body["data"]["disclaimer"]


def test_the_listing_pages_newest_first(anomaly_client, session_factory) -> None:
    """Ordering is total and newest-first, so pagination cannot repeat a row."""
    client, engine = anomaly_client
    store = EvaluationStore(session_factory=session_factory)
    for minute in (1, 5, 3):
        store.write(
            device_key=DEVICE_MAC,
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

    body = client.get("/api/v1/anomalies").json()["data"]

    starts = [row["window_start"] for row in body["anomalies"]]
    assert starts == sorted(starts, reverse=True)
    assert body["total"] == 3


def test_the_listing_respects_limit_and_offset(anomaly_client, session_factory) -> None:
    """The shared pagination contract, asserted against real rows."""
    client, _engine = anomaly_client
    store = EvaluationStore(session_factory=session_factory)
    for minute in range(5):
        store.write(
            device_key=DEVICE_MAC,
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

    body = client.get("/api/v1/anomalies?limit=2&offset=2").json()["data"]

    assert body["count"] == 2
    assert body["limit"] == 2
    assert body["offset"] == 2
    assert body["has_more"] is True


def test_the_listing_filters_by_classification(anomaly_client, session_factory) -> None:
    """``is_anomaly`` narrows the listing without changing its order."""
    client, _engine = anomaly_client
    store = EvaluationStore(session_factory=session_factory)
    for minute, flagged in ((1, True), (2, False)):
        store.write(
            device_key=DEVICE_MAC,
            window_start=window_before(minute),
            window_seconds=60.0,
            algorithm="isolation_forest",
            model_version=1,
            model_trained_at=None,
            training_sample_count=20,
            contamination=0.02,
            decision_score=-0.01,
            is_anomaly=flagged,
            status="scored",
        )

    body = client.get("/api/v1/anomalies?is_anomaly=true").json()["data"]

    assert body["count"] == 1
    assert body["anomalies"][0]["is_anomaly"] is True


def test_the_listing_filters_by_device(anomaly_client, session_factory) -> None:
    """A device filter returns only that device's windows."""
    client, _engine = anomaly_client
    store = EvaluationStore(session_factory=session_factory)
    for device in (DEVICE_MAC, "ip:10.0.0.9"):
        store.write(
            device_key=device,
            window_start=window_before(1),
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

    body = client.get(
        f"/api/v1/anomalies?device_key={DEVICE_MAC}"
    ).json()["data"]

    assert body["count"] == 1
    assert body["anomalies"][0]["device_key"] == DEVICE_MAC


def test_an_unparseable_timestamp_is_a_named_400(anomaly_client) -> None:
    """An unparseable filter must not silently widen the window (M13.25)."""
    client, _engine = anomaly_client

    response = client.get("/api/v1/anomalies?since=not-a-date")

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert "not-a-date" in body["message"]


def test_an_inverted_time_range_is_a_400(anomaly_client) -> None:
    """A window whose start is after its end can never match."""
    client, _engine = anomaly_client

    response = client.get(
        "/api/v1/anomalies?since=2026-11-20T05:00:00Z&until=2026-11-20T01:00:00Z"
    )

    assert response.status_code == 400


def test_an_out_of_range_limit_is_rejected_before_the_handler(anomaly_client) -> None:
    """The shared maximum is declared on the parameter, so it is a 422."""
    client, _engine = anomaly_client

    assert client.get("/api/v1/anomalies?limit=5000").status_code == 422
    assert client.get("/api/v1/anomalies?limit=0").status_code == 422


def test_no_probability_field_is_exposed(anomaly_client, session_factory) -> None:
    """The payload names a decision score and offers no probability (M22.9)."""
    client, _engine = anomaly_client
    store = EvaluationStore(session_factory=session_factory)
    store.write(
        device_key=DEVICE_MAC,
        window_start=window_before(1),
        window_seconds=60.0,
        algorithm="isolation_forest",
        model_version=1,
        model_trained_at=None,
        training_sample_count=20,
        contamination=0.02,
        decision_score=-0.04,
        is_anomaly=True,
        status="scored",
    )

    row = client.get("/api/v1/anomalies").json()["data"]["anomalies"][0]

    assert "decision_score" in row
    assert "not a probability" in row["decision_score_note"]
    for forbidden in ("probability", "confidence", "likelihood"):
        assert forbidden not in row


# ---------------------------------------------------------------------------
# detail
# ---------------------------------------------------------------------------


def test_the_detail_carries_the_feature_context(anomaly_client, session_factory) -> None:
    """The listing omits context; the detail is where it belongs."""
    client, _engine = anomaly_client
    store = EvaluationStore(session_factory=session_factory)
    snapshot, _created = store.write(
        device_key=DEVICE_MAC,
        window_start=window_before(1),
        window_seconds=60.0,
        algorithm="isolation_forest",
        model_version=1,
        model_trained_at=None,
        training_sample_count=20,
        contamination=0.02,
        decision_score=-0.04,
        is_anomaly=True,
        status="scored",
        feature_context=[
            {
                "feature": "packet_count",
                "observed": 400.0,
                "training_median": 200.0,
                "difference": 200.0,
                "deviation_mads": 8.0,
                "far_from_centre": True,
            }
        ],
    )
    assert snapshot is not None

    body = client.get(f"/api/v1/anomalies/{snapshot.evaluation_id}").json()["data"]

    assert body["feature_context"][0]["feature"] == "packet_count"
    assert body["feature_context"][0]["label"] == "Packets per window"
    assert body["feature_context"][0]["far_from_centre"] is True


def test_an_unknown_evaluation_id_is_a_404(anomaly_client) -> None:
    """The error envelope names the field that failed."""
    client, _engine = anomaly_client

    response = client.get("/api/v1/anomalies/999999")

    assert response.status_code == 404
    errors = response.json()["errors"]
    assert errors[0]["field"] == "evaluation_id"


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------


def test_the_model_listing_includes_a_collecting_device(
    anomaly_client, session_factory
) -> None:
    """A device with no model is a row, never an omission (M22.13)."""
    client, engine = anomaly_client
    persist_windows(session_factory, normal_windows(5))

    engine.evaluate(
        PendingWindow(
            device_key=DEVICE_MAC,
            window_start=window_before(4)
            .replace(tzinfo=timezone.utc)
            .timestamp(),
            window_seconds=60.0,
        )
    )

    body = client.get("/api/v1/anomalies/models").json()["data"]

    assert body["count"] >= 1
    row = body["models"][0]
    assert row["state"] == "collecting_data"
    assert row["ready"] is False
    assert row["state_label"] == "Collecting data"


def test_a_model_detail_for_an_unseen_device_is_a_404(anomaly_client) -> None:
    """No model row at all is a real answer, reported as one."""
    client, _engine = anomaly_client

    response = client.get("/api/v1/anomalies/models/ip:10.9.9.9")

    assert response.status_code == 404
    assert response.json()["errors"][0]["field"] == "device_key"


def test_the_model_state_vocabulary_is_closed(anomaly_client) -> None:
    """An unknown state is rejected by request validation, not by the handler."""
    client, _engine = anomaly_client

    assert client.get("/api/v1/anomalies/models?state=invented").status_code == 422


# ---------------------------------------------------------------------------
# retraining
# ---------------------------------------------------------------------------


def test_a_retrain_without_history_is_a_404(anomaly_client) -> None:
    """There is nothing a retrain could be trained from."""
    client, _engine = anomaly_client

    response = client.post("/api/v1/anomalies/models/ip:10.9.9.9/retrain")

    assert response.status_code == 404
    assert response.json()["errors"][0]["field"] == "device_key"


def test_a_retrain_with_history_reports_what_happened(
    anomaly_client, session_factory
) -> None:
    """The outcome is read from ``trained``, not inferred from the status code."""
    client, _engine = anomaly_client
    persist_windows(session_factory, normal_windows(30))

    response = client.post(f"/api/v1/anomalies/models/{DEVICE_MAC}/retrain")

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["requested"] is True
    assert body["trained"] is True
    assert body["model_version"] == 1
    assert "does not change M21" in body["message"]


def test_a_retrain_with_too_little_history_reports_a_refusal(
    anomaly_client, session_factory
) -> None:
    """A refusal is a 200 with ``trained: false`` and a reason, not an error."""
    client, _engine = anomaly_client
    persist_windows(session_factory, normal_windows(3))

    body = client.post(f"/api/v1/anomalies/models/{DEVICE_MAC}/retrain").json()["data"]

    assert body["trained"] is False
    assert body["reason"] == "insufficient_training_data"
    assert body["model_version"] == 0
    assert "not yet" in body["message"]


def test_a_retrain_never_deletes_m21_history(anomaly_client, session_factory) -> None:
    """The retrain reads windows and writes a model row; nothing is removed."""
    from app.models.baseline_observation import BaselineWindow
    from sqlalchemy import func, select

    client, _engine = anomaly_client
    persist_windows(session_factory, normal_windows(30))

    client.post(f"/api/v1/anomalies/models/{DEVICE_MAC}/retrain")

    session = session_factory()
    try:
        remaining = session.scalar(
            select(func.count()).select_from(BaselineWindow)
        )
    finally:
        session.close()
    assert int(remaining or 0) == 30
