"""API tests for the alert endpoints (M11.18/M11.19).

Verifies the response envelope, the empty and populated states, every filter the
M11.18 contract promises (severity, minimum severity, status, detector rule,
source, destination, time window, paging), the detail and evidence views, the
lifecycle transition endpoint with its valid and rejected moves, the summary and
diagnostics surface, and the HTTP routing conventions.

The alert API is a verification surface for M11; the public alert API is M13.
The shared engine and query service are overridden with instances bound to an
isolated in-memory database, so these tests never touch ``netwatch.db``.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.alerts.engine import AlertEngine
from app.alerts.queries import AlertQueries
from app.alerts.service import AlertService
from app.api.v1.alerts import get_alert_engine, get_alert_queries
from app.config.settings import settings
from app.main import app
from tests.alert_fakes import (
    ALERT_BASE_TIME,
    OTHER_DESTINATION_IP,
    OTHER_SOURCE_IP,
    SOURCE_IP,
    make_finding,
    make_service,
)

ALERTS_URL = "/api/v1/alerts"
SUMMARY_URL = f"{ALERTS_URL}/summary"
DIAGNOSTICS_URL = f"{ALERTS_URL}/diagnostics"

DESTINATION_IP = "8.8.8.8"


@pytest.fixture
def alert_engine(session_factory) -> AlertEngine:
    """An alert engine writing to the isolated test database."""
    service: AlertService = make_service(session_factory)
    return AlertEngine(service)


@pytest.fixture
def client(
    session_factory, alert_engine: AlertEngine
) -> Generator[TestClient, None, None]:
    """Test client with the alert engine and queries bound to the test database.

    The application environment is temporarily set to ``"test"`` so the lifespan
    skips ``init_db()`` and never touches the real database, and the two alert
    dependencies are overridden so reads and writes stay isolated.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    queries = AlertQueries(session_factory=session_factory)
    app.dependency_overrides[get_alert_engine] = lambda: alert_engine
    app.dependency_overrides[get_alert_queries] = lambda: queries
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_alert_engine, None)
        app.dependency_overrides.pop(get_alert_queries, None)
        settings.app_env = original_env


def seed(engine: AlertEngine, *findings) -> None:
    """Turn ``findings`` into stored alerts through the real service."""
    for finding in findings:
        engine.process_finding(finding)


def alerts_of(response) -> list[dict]:
    """Return the alerts list from a successful collection response."""
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    return body["data"]["alerts"]


# ---------------------------------------------------------------------------
# Empty and populated states
# ---------------------------------------------------------------------------


def test_empty_state_returns_an_empty_collection(client: TestClient) -> None:
    """No stored alerts reports a well-formed empty page."""
    response = client.get(ALERTS_URL)
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["count"] == 0
    assert body["data"]["total"] == 0
    assert body["data"]["alerts"] == []


def test_response_uses_the_standard_envelope(client: TestClient) -> None:
    """The collection response carries success/message/data like the rest of the API."""
    body = client.get(ALERTS_URL).json()
    assert set(body) == {"success", "message", "data"}
    assert isinstance(body["message"], str) and body["message"]


def test_seeded_alerts_are_returned(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """Alerts created from findings are returned and counted."""
    seed(alert_engine, make_finding(), make_finding(rule_id="syn_flood"))
    body = client.get(ALERTS_URL).json()["data"]
    assert body["count"] == 2
    assert body["total"] == 2


def test_alert_view_exposes_the_model(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """A serialized alert carries the M11.3 fields and no risk score (M11.5)."""
    seed(alert_engine, make_finding(confidence=0.92))
    alert = alerts_of(client.get(ALERTS_URL))[0]
    assert alert["rule_id"] == "port_scan"
    assert alert["title"] == "Port Scan"
    assert alert["severity"] == "high"
    assert alert["status"] == "open"
    assert alert["source_ip"] == SOURCE_IP
    assert alert["destination_ip"] == DESTINATION_IP
    assert alert["confidence"] == pytest.approx(0.92, abs=0.01)
    assert alert["evidence_count"] >= 2
    assert "risk_score" not in alert


def test_timestamps_are_iso8601(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """Alert times cross the wire as ISO-8601 UTC strings (M11.18)."""
    seed(alert_engine, make_finding(timestamp=ALERT_BASE_TIME))
    alert = alerts_of(client.get(ALERTS_URL))[0]
    assert alert["created_at"] == "2026-01-01T12:00:00+00:00"
    assert alert["updated_at"] is not None
# ---------------------------------------------------------------------------
# Filters (M11.18)
# ---------------------------------------------------------------------------


def test_filter_by_exact_severity(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """``severity`` keeps only that level (M11.4)."""
    seed(alert_engine, make_finding(rule_id="port_scan"), make_finding(rule_id="icmp_flood"))
    alerts = alerts_of(client.get(ALERTS_URL, params={"severity": "medium"}))
    assert [alert["severity"] for alert in alerts] == ["medium"]


def test_filter_by_min_severity(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """``min_severity`` keeps that level and above (M11.4)."""
    seed(
        alert_engine,
        make_finding(rule_id="icmp_flood"),  # medium
        make_finding(rule_id="port_scan", source_ip=OTHER_SOURCE_IP),   # high
        make_finding(rule_id="syn_flood", source_ip="192.168.1.9"),   # critical
    )
    alerts = alerts_of(client.get(ALERTS_URL, params={"min_severity": "high"}))
    assert sorted(alert["severity"] for alert in alerts) == ["critical", "high"]


def test_filter_by_status(client: TestClient, alert_engine: AlertEngine) -> None:
    """``status`` keeps only alerts in the named lifecycle states."""
    seed(alert_engine, make_finding(rule_id="port_scan"))
    seed(alert_engine, make_finding(rule_id="syn_flood"))
    open_alert = alerts_of(client.get(ALERTS_URL))[0]
    client.post(
        f"{ALERTS_URL}/{open_alert['alert_id']}/status",
        json={"status": "acknowledged"},
    )

    acknowledged = alerts_of(client.get(ALERTS_URL, params={"status": "acknowledged"}))
    assert [alert["status"] for alert in acknowledged] == ["acknowledged"]


def test_filter_by_rule_key(client: TestClient, alert_engine: AlertEngine) -> None:
    """``rule_key`` matches the detector's string rule id (M11.18)."""
    seed(alert_engine, make_finding(rule_id="port_scan"), make_finding(rule_id="syn_flood"))
    alerts = alerts_of(client.get(ALERTS_URL, params={"rule_key": "syn_flood"}))
    assert [alert["rule_id"] for alert in alerts] == ["syn_flood"]


def test_filter_by_source_ip(client: TestClient, alert_engine: AlertEngine) -> None:
    """``source_ip`` matches the stored source exactly."""
    seed(
        alert_engine,
        make_finding(source_ip=SOURCE_IP),
        make_finding(source_ip=OTHER_SOURCE_IP),
    )
    alerts = alerts_of(client.get(ALERTS_URL, params={"source_ip": OTHER_SOURCE_IP}))
    assert [alert["source_ip"] for alert in alerts] == [OTHER_SOURCE_IP]


def test_filter_by_destination_ip(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """``destination_ip`` matches the stored destination exactly."""
    seed(
        alert_engine,
        make_finding(destination_ip=DESTINATION_IP),
        make_finding(destination_ip=OTHER_DESTINATION_IP),
    )
    alerts = alerts_of(
        client.get(ALERTS_URL, params={"destination_ip": OTHER_DESTINATION_IP})
    )
    assert [alert["destination_ip"] for alert in alerts] == [OTHER_DESTINATION_IP]


def test_filter_by_since_is_inclusive(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """``since`` keeps alerts at or after the bound (M11.18)."""
    seed(
        alert_engine,
        make_finding(timestamp=ALERT_BASE_TIME),
        make_finding(timestamp=ALERT_BASE_TIME + 10, source_ip=OTHER_SOURCE_IP),
    )
    # 2026-01-01T12:00:10Z is the second alert's own time.
    alerts = alerts_of(
        client.get(ALERTS_URL, params={"since": "2026-01-01T12:00:10+00:00"})
    )
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == OTHER_SOURCE_IP


def test_filter_by_until_is_exclusive(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """``until`` keeps alerts strictly before the bound (M11.18)."""
    seed(
        alert_engine,
        make_finding(timestamp=ALERT_BASE_TIME),
        make_finding(timestamp=ALERT_BASE_TIME + 10, source_ip=OTHER_SOURCE_IP),
    )
    alerts = alerts_of(
        client.get(ALERTS_URL, params={"until": "2026-01-01T12:00:10+00:00"})
    )
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == SOURCE_IP


def test_paging_keeps_the_newest_matches(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """``limit``/``offset`` frame a stable page while ``total`` reports everything."""
    seed(
        alert_engine,
        make_finding(timestamp=ALERT_BASE_TIME),
        make_finding(timestamp=ALERT_BASE_TIME + 10, source_ip=OTHER_SOURCE_IP),
        make_finding(timestamp=ALERT_BASE_TIME + 20, source_ip="192.168.1.9"),
    )
    body = client.get(ALERTS_URL, params={"limit": 2, "offset": 0}).json()["data"]
    assert body["count"] == 2
    assert body["total"] == 3
    assert body["alerts"][0]["source_ip"] == "192.168.1.9"


def test_unknown_filter_value_returns_nothing(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """A filter that matches nothing returns an empty page, not an error."""
    seed(alert_engine, make_finding())
    body = client.get(ALERTS_URL, params={"rule_key": "does_not_exist"}).json()["data"]
    assert body["count"] == 0


# ---------------------------------------------------------------------------
# Filter validation
# ---------------------------------------------------------------------------


def test_invalid_severity_is_rejected(client: TestClient) -> None:
    """An unknown severity fails loudly rather than returning everything (M11.4)."""
    response = client.get(ALERTS_URL, params={"severity": "urgent"})
    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["field"] == "filter"
    assert body["errors"][0]["code"] == "INVALID_FILTER"


def test_invalid_timestamp_is_rejected(client: TestClient) -> None:
    """An unusable ``since`` fails loudly and names the filter (M11.18)."""
    response = client.get(ALERTS_URL, params={"since": "not-a-timestamp"})
    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "INVALID_FILTER"


def test_empty_rule_key_is_rejected(client: TestClient) -> None:
    """A blank ``rule_key`` is a typo, not a request to widen the query."""
    response = client.get(ALERTS_URL, params={"rule_key": "   "})
    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "INVALID_FILTER"


def test_limit_below_minimum_is_rejected(client: TestClient) -> None:
    """A limit of zero is rejected by request validation."""
    assert client.get(ALERTS_URL, params={"limit": 0}).status_code == 422


def test_limit_above_maximum_is_rejected(client: TestClient) -> None:
    """An over-large limit is rejected so a response stays bounded (M11.18)."""
    over_max = settings.alert_max_page_size + 1
    assert client.get(ALERTS_URL, params={"limit": over_max}).status_code == 422


# ---------------------------------------------------------------------------
# Alert detail and evidence (M11.18)
# ---------------------------------------------------------------------------


def _first_alert_id(client: TestClient) -> int:
    """Return the id of the newest stored alert."""
    return int(alerts_of(client.get(ALERTS_URL))[0]["alert_id"])


def test_detail_returns_the_alert_with_evidence(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """The detail view carries the alert, its evidence and the per-type counts."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)

    body = client.get(f"{ALERTS_URL}/{alert_id}").json()

    assert body["success"] is True
    data = body["data"]
    assert data["alert"]["alert_id"] == alert_id
    assert {record["evidence_type"] for record in data["evidence"]} == {
        "rule",
        "behavioral",
    }
    assert data["evidence_by_type"] == {"rule": 1, "behavioral": 1}


def test_unknown_alert_returns_404(client: TestClient) -> None:
    """An unknown alert id returns the standard not-found envelope."""
    response = client.get(f"{ALERTS_URL}/99999")
    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "alert_id", "code": "ALERT_NOT_FOUND"}]


def test_evidence_endpoint_returns_only_evidence(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """The evidence endpoint returns the alert's evidence, optionally filtered."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)

    body = client.get(f"{ALERTS_URL}/{alert_id}/evidence").json()

    assert body["success"] is True
    assert body["data"]["count"] == 2


def test_evidence_can_be_filtered_by_type(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """An ``evidence_type`` filter narrows to that kind (M11.11)."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)

    body = client.get(
        f"{ALERTS_URL}/{alert_id}/evidence", params={"evidence_type": "rule"}
    ).json()

    assert body["data"]["count"] == 1
    assert body["data"]["evidence"][0]["evidence_type"] == "rule"


def test_evidence_for_unknown_alert_returns_404(client: TestClient) -> None:
    """Evidence for a missing alert is a 404, not an empty list (M11.18)."""
    assert client.get(f"{ALERTS_URL}/99999/evidence").status_code == 404


def test_invalid_evidence_type_is_rejected(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """An unknown evidence type fails loudly rather than being ignored."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)
    response = client.get(
        f"{ALERTS_URL}/{alert_id}/evidence", params={"evidence_type": "ghost"}
    )
    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "evidence_type"
# ---------------------------------------------------------------------------
# Lifecycle transitions (M11.19/M11.20)
# ---------------------------------------------------------------------------


def test_acknowledge_then_resolve(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """open → acknowledged → resolved is accepted and persisted (M11.19)."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)

    first = client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "acknowledged"})
    second = client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "resolved"})

    assert first.status_code == 200
    assert first.json()["data"]["status"] == "acknowledged"
    assert second.status_code == 200
    assert second.json()["data"]["status"] == "resolved"
    assert second.json()["data"]["resolved_at"] is not None


def test_dismiss_is_a_terminal_move(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """open → dismissed is accepted, and no further move follows (M11.19)."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)

    dismissed = client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "dismissed"})
    after = client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "acknowledged"})

    assert dismissed.status_code == 200
    assert dismissed.json()["data"]["status"] == "dismissed"
    assert after.status_code == 409
    assert after.json()["errors"][0]["code"] == "INVALID_TRANSITION"


def test_invalid_transition_is_rejected(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """A move the lifecycle forbids returns 409 and leaves the row unchanged (M11.19)."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)
    client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "resolved"})

    response = client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "open"})

    assert response.status_code == 409
    assert response.json()["errors"][0]["field"] == "status"
    # The alert is still resolved: a rejected move never mutates the stored row.
    assert client.get(f"{ALERTS_URL}/{alert_id}").json()["data"]["alert"]["status"] == "resolved"


def test_transition_to_unknown_alert_returns_404(client: TestClient) -> None:
    """A lifecycle move on a missing alert returns 404."""
    response = client.post(f"{ALERTS_URL}/99999/status", json={"status": "resolved"})
    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "ALERT_NOT_FOUND"


def test_unknown_status_value_is_rejected_by_validation(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """A status outside the five M11 states fails request validation."""
    seed(alert_engine, make_finding())
    alert_id = _first_alert_id(client)
    response = client.post(f"{ALERTS_URL}/{alert_id}/status", json={"status": "escalated"})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Summary and diagnostics (M11.18/M11.31)
# ---------------------------------------------------------------------------


def test_summary_reports_every_severity(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """Summary counts by severity, reporting zeroes rather than omitting (M11.18)."""
    seed(alert_engine, make_finding(rule_id="port_scan"), make_finding(rule_id="syn_flood"))
    data = client.get(SUMMARY_URL).json()["data"]
    assert data["total"] == 2
    assert data["by_severity"]["high"] == 1
    assert data["by_severity"]["critical"] == 1
    assert data["by_severity"]["low"] == 0
    assert data["by_status"]["open"] == 2


def test_summary_on_an_empty_store(client: TestClient) -> None:
    """An empty store reports a total of zero and the full severity shape."""
    data = client.get(SUMMARY_URL).json()["data"]
    assert data["total"] == 0
    assert set(data["by_severity"]) == {"critical", "high", "medium", "low"}


def test_diagnostics_reports_the_engine_counters(
    client: TestClient, alert_engine: AlertEngine
) -> None:
    """Diagnostics expose the engine's counters and the stored totals (M11.31)."""
    seed(
        alert_engine,
        make_finding(),
        make_finding(rule_id="syn_flood"),
        make_finding(rule_id="not_real"),  # unsupported: counted, no alert
    )
    data = client.get(DIAGNOSTICS_URL).json()["data"]
    assert data["enabled"] is True
    assert data["findings_seen"] == 3
    assert data["alerts_created"] == 2
    assert data["unsupported_findings"] == 1
    assert data["total"] == 2


# ---------------------------------------------------------------------------
# HTTP / routing conventions
# ---------------------------------------------------------------------------


def test_collection_rejects_post(client: TestClient) -> None:
    """The alert collection is read-only; only the status route accepts a POST."""
    assert client.post(ALERTS_URL).status_code == 405


def test_collection_rejects_delete(client: TestClient) -> None:
    """Alerts are not deleted through the collection."""
    assert client.delete(ALERTS_URL).status_code == 405


def test_unknown_route_is_404(client: TestClient) -> None:
    """An unknown alert sub-route returns 404."""
    assert client.get(f"{ALERTS_URL}/nested/path/extra").status_code == 404
