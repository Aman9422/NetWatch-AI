"""API tests for the read-only detection endpoints (M10.22).

Verifies the response envelope, the empty and populated states, every filter the
M10 contract promises (rule, source, destination, device, time window, limit),
the rules/diagnostics surface, and the reset helper. The M10 API is a
verification surface only; the public detection API is M13 and the alert API is
M11.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config.settings import settings
from app.detection import DetectionEngine, DetectionRule, get_detection_engine
from app.detection.finding import DetectionFinding
from app.detection.rules.high_bandwidth import HighBandwidthRule
from app.detection.rules.port_scan import PortScanRule
from app.main import app
from tests.detection_fakes import (
    DETECTION_BASE_TIME,
    make_context,
    make_syn_packet,
)

DETECTIONS_URL = "/api/v1/detections"
RULES_URL = f"{DETECTIONS_URL}/rules"
RESET_URL = f"{DETECTIONS_URL}/reset"

SOURCE_IP = "192.168.1.10"
DESTINATION_IP = "8.8.8.8"
OTHER_SOURCE_IP = "192.168.1.55"
SOURCE_DEVICE_ID = "mac:AA:BB:CC:DD:EE:FF"
DESTINATION_DEVICE_ID = "mac:22:33:44:55:66:77"


# ---------------------------------------------------------------------------
# Test doubles and builders
# ---------------------------------------------------------------------------


class ScriptedRule(DetectionRule):
    """A rule returning preset findings, one per evaluation (M10.6)."""

    rule_id = "scripted"
    rule_name = "Scripted Rule"
    description = "Test rule returning preset findings"

    def __init__(self, findings: list[DetectionFinding]) -> None:
        super().__init__(window_seconds=10.0)
        self._pending = list(findings)

    def evaluate(self, context: Any) -> DetectionFinding | None:
        """Return the next preset finding, or ``None`` once exhausted."""
        if not self._pending:
            return None
        return self._pending.pop(0)


def make_finding(**overrides: Any) -> DetectionFinding:
    """Build a detection finding for the API tests."""
    values: dict[str, Any] = {
        "rule_id": "port_scan",
        "rule_name": "Port Scan",
        "timestamp": DETECTION_BASE_TIME,
        "source_ip": SOURCE_IP,
        "destination_ip": DESTINATION_IP,
        "protocol": "TCP",
        "description": "Possible port scan detected",
    }
    values.update(overrides)
    return DetectionFinding(**values)


def iso(epoch: float) -> str:
    """Render an epoch time as an ISO-8601 UTC string, as the API expects."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


@pytest.fixture
def engine() -> DetectionEngine:
    """An empty engine owned by one test."""
    return DetectionEngine([])


@pytest.fixture
def client(engine: DetectionEngine) -> Generator[TestClient, None, None]:
    """Test client with the shared detection engine overridden by ``engine``.

    The application environment is temporarily set to ``"test"`` so the lifespan
    skips ``init_db()`` and never touches the real database.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    app.dependency_overrides[get_detection_engine] = lambda: engine
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_detection_engine, None)
        settings.app_env = original_env


def seed(engine: DetectionEngine, *findings: DetectionFinding) -> None:
    """Retain ``findings`` in ``engine``'s history via the public API.

    A temporary scripted rule is registered, evaluated once per finding, then
    removed. Findings stay in the bounded history; only the helper rule and its
    counters go away, so a test seeds observations without reaching into engine
    internals.
    """
    rule = ScriptedRule(list(findings))
    engine.register(rule)
    try:
        for _ in findings:
            engine.evaluate(make_context())
    finally:
        engine.unregister(rule.rule_id)


def findings_of(response: Any) -> list[dict]:
    """Return the findings list from a successful collection response."""
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    return body["data"]["findings"]


# ---------------------------------------------------------------------------
# Empty and populated states
# ---------------------------------------------------------------------------


def test_empty_state_returns_an_empty_collection(
    client: TestClient,
) -> None:
    """An engine that has observed nothing reports a well-formed empty list."""
    response = client.get(DETECTIONS_URL)
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["count"] == 0
    assert body["data"]["findings"] == []


def test_response_uses_the_standard_envelope(client: TestClient) -> None:
    """The collection response carries success/message/data like the rest of the API."""
    body = client.get(DETECTIONS_URL).json()
    assert set(body) == {"success", "message", "data"}
    assert isinstance(body["message"], str) and body["message"]


def test_returns_seeded_findings(
    client: TestClient, engine: DetectionEngine
) -> None:
    """Seeded findings are returned and counted."""
    seed(engine, make_finding(), make_finding(rule_id="syn_flood"))
    response = client.get(DETECTIONS_URL)
    assert response.json()["data"]["count"] == 2
    assert len(findings_of(response)) == 2


def test_findings_are_returned_newest_first(
    client: TestClient, engine: DetectionEngine
) -> None:
    """Retained findings are ordered newest first (M10.22)."""
    seed(
        engine,
        make_finding(timestamp=DETECTION_BASE_TIME),
        make_finding(timestamp=DETECTION_BASE_TIME + 10),
        make_finding(timestamp=DETECTION_BASE_TIME + 20),
    )
    timestamps = [finding["timestamp"] for finding in findings_of(client.get(DETECTIONS_URL))]
    assert timestamps == sorted(timestamps, reverse=True)


def test_finding_view_exposes_the_observation(
    client: TestClient, engine: DetectionEngine
) -> None:
    """A serialized finding carries the M10.5 fields and its evidence (M10.14)."""
    seed(
        engine,
        make_finding(
            protocol="TCP",
            evidence={"unique_destination_ports": 37, "unique_port_threshold": 20},
            confidence=0.8,
            metadata={"scan_characterisation": "syn"},
            source_device_id=SOURCE_DEVICE_ID,
        ),
    )
    finding = findings_of(client.get(DETECTIONS_URL))[0]
    assert finding["rule_id"] == "port_scan"
    assert finding["rule_name"] == "Port Scan"
    assert finding["source_ip"] == SOURCE_IP
    assert finding["destination_ip"] == DESTINATION_IP
    assert finding["protocol"] == "TCP"
    assert finding["description"] == "Possible port scan detected"
    assert finding["evidence"]["unique_destination_ports"] == 37
    assert finding["confidence"] == 0.8
    assert finding["source_device_id"] == SOURCE_DEVICE_ID
    assert finding["finding_id"]


def test_timestamp_is_serialized_as_iso8601(
    client: TestClient, engine: DetectionEngine
) -> None:
    """A finding's epoch time is projected as an ISO-8601 UTC string (M10.22)."""
    seed(engine, make_finding(timestamp=DETECTION_BASE_TIME))
    timestamp = findings_of(client.get(DETECTIONS_URL))[0]["timestamp"]
    assert timestamp == iso(DETECTION_BASE_TIME)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_filter_by_rule_id(client: TestClient, engine: DetectionEngine) -> None:
    """``rule_id`` keeps only the named detector's findings."""
    seed(engine, make_finding(rule_id="port_scan"), make_finding(rule_id="syn_flood"))
    findings = findings_of(client.get(DETECTIONS_URL, params={"rule_id": "syn_flood"}))
    assert [finding["rule_id"] for finding in findings] == ["syn_flood"]


def test_filter_by_source_ip(client: TestClient, engine: DetectionEngine) -> None:
    """``source_ip`` matches the finding's source exactly."""
    seed(engine, make_finding(), make_finding(source_ip=OTHER_SOURCE_IP))
    findings = findings_of(client.get(DETECTIONS_URL, params={"source_ip": SOURCE_IP}))
    assert [finding["source_ip"] for finding in findings] == [SOURCE_IP]


def test_filter_by_destination_ip(
    client: TestClient, engine: DetectionEngine
) -> None:
    """``destination_ip`` matches the finding's destination exactly."""
    seed(engine, make_finding(), make_finding(destination_ip="1.1.1.1"))
    findings = findings_of(
        client.get(DETECTIONS_URL, params={"destination_ip": "1.1.1.1"})
    )
    assert [finding["destination_ip"] for finding in findings] == ["1.1.1.1"]


def test_filter_by_source_device(client: TestClient, engine: DetectionEngine) -> None:
    """``device_id`` matches a finding attributed to that device as source."""
    seed(
        engine,
        make_finding(source_device_id=SOURCE_DEVICE_ID),
        make_finding(source_device_id="mac:DE:AD:BE:EF:00:01"),
    )
    findings = findings_of(
        client.get(DETECTIONS_URL, params={"device_id": SOURCE_DEVICE_ID})
    )
    assert len(findings) == 1
    assert findings[0]["source_device_id"] == SOURCE_DEVICE_ID


def test_filter_by_device_matches_either_end(
    client: TestClient, engine: DetectionEngine
) -> None:
    """``device_id`` matches the destination side too (M10.22)."""
    seed(engine, make_finding(destination_device_id=DESTINATION_DEVICE_ID))
    findings = findings_of(
        client.get(DETECTIONS_URL, params={"device_id": DESTINATION_DEVICE_ID})
    )
    assert len(findings) == 1
    assert findings[0]["destination_device_id"] == DESTINATION_DEVICE_ID


def test_filter_by_since_is_inclusive(
    client: TestClient, engine: DetectionEngine
) -> None:
    """``since`` keeps findings at or after the bound (M10.13)."""
    seed(
        engine,
        make_finding(timestamp=DETECTION_BASE_TIME),
        make_finding(timestamp=DETECTION_BASE_TIME + 10),
        make_finding(timestamp=DETECTION_BASE_TIME + 20),
    )
    findings = findings_of(
        client.get(DETECTIONS_URL, params={"since": iso(DETECTION_BASE_TIME + 10)})
    )
    assert len(findings) == 2
    assert findings[-1]["timestamp"] == iso(DETECTION_BASE_TIME + 10)


def test_filter_by_until_is_exclusive(
    client: TestClient, engine: DetectionEngine
) -> None:
    """``until`` keeps findings strictly before the bound (M10.13)."""
    seed(
        engine,
        make_finding(timestamp=DETECTION_BASE_TIME),
        make_finding(timestamp=DETECTION_BASE_TIME + 10),
        make_finding(timestamp=DETECTION_BASE_TIME + 20),
    )
    findings = findings_of(
        client.get(DETECTIONS_URL, params={"until": iso(DETECTION_BASE_TIME + 20)})
    )
    assert len(findings) == 2
    assert findings[0]["timestamp"] == iso(DETECTION_BASE_TIME + 10)


def test_filters_combine_with_and(
    client: TestClient, engine: DetectionEngine
) -> None:
    """A rule filter and a window filter narrow to their intersection."""
    seed(
        engine,
        make_finding(rule_id="port_scan", timestamp=DETECTION_BASE_TIME),
        make_finding(rule_id="port_scan", timestamp=DETECTION_BASE_TIME + 10),
        make_finding(rule_id="syn_flood", timestamp=DETECTION_BASE_TIME + 10),
    )
    findings = findings_of(
        client.get(
            DETECTIONS_URL,
            params={
                "rule_id": "port_scan",
                "since": iso(DETECTION_BASE_TIME + 5),
            },
        )
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "port_scan"
    assert findings[0]["timestamp"] == iso(DETECTION_BASE_TIME + 10)


def test_unknown_filter_value_returns_nothing(
    client: TestClient, engine: DetectionEngine
) -> None:
    """A filter that matches no finding returns an empty collection, not an error."""
    seed(engine, make_finding())
    response = client.get(DETECTIONS_URL, params={"rule_id": "does_not_exist"})
    assert response.status_code == 200
    assert response.json()["data"]["count"] == 0


def test_limit_keeps_the_newest_matches(
    client: TestClient, engine: DetectionEngine
) -> None:
    """``limit`` caps the result after ordering, so the newest survive (M10.22)."""
    seed(
        engine,
        make_finding(timestamp=DETECTION_BASE_TIME),
        make_finding(timestamp=DETECTION_BASE_TIME + 10),
        make_finding(timestamp=DETECTION_BASE_TIME + 20),
    )
    findings = findings_of(client.get(DETECTIONS_URL, params={"limit": 2}))
    assert len(findings) == 2
    assert findings[0]["timestamp"] == iso(DETECTION_BASE_TIME + 20)
    assert findings[1]["timestamp"] == iso(DETECTION_BASE_TIME + 10)


def test_limit_below_minimum_is_rejected(client: TestClient) -> None:
    """A limit of zero is rejected by validation rather than returning everything."""
    assert client.get(DETECTIONS_URL, params={"limit": 0}).status_code == 422


def test_limit_above_maximum_is_rejected(client: TestClient) -> None:
    """An over-large limit is rejected so a response stays bounded."""
    assert client.get(DETECTIONS_URL, params={"limit": 100_000}).status_code == 422


# ---------------------------------------------------------------------------
# Filter validation
# ---------------------------------------------------------------------------


def test_invalid_since_is_rejected(client: TestClient) -> None:
    """An unusable ``since`` fails loudly and names the field (M10.13)."""
    response = client.get(DETECTIONS_URL, params={"since": "not-a-timestamp"})
    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["field"] == "since"
    assert body["errors"][0]["code"] == "INVALID_FILTER"


def test_invalid_until_is_rejected_and_names_until(client: TestClient) -> None:
    """An unusable ``until`` is reported against ``until``, not ``since``."""
    response = client.get(DETECTIONS_URL, params={"until": "nonsense"})
    assert response.status_code == 400
    body = response.json()
    assert body["errors"][0]["field"] == "until"


def test_empty_since_is_rejected(client: TestClient) -> None:
    """A blank ``since`` is a typo, not a request to widen the window."""
    response = client.get(DETECTIONS_URL, params={"since": "   "})
    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "since"


def test_zulu_timestamps_are_accepted(client: TestClient) -> None:
    """A trailing ``Z`` is accepted as UTC, as the rest of the API accepts it."""
    response = client.get(
        DETECTIONS_URL, params={"since": "2025-01-01T00:00:00Z"}
    )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Rules and diagnostics
# ---------------------------------------------------------------------------


def test_rules_lists_registered_detectors(
    client: TestClient, engine: DetectionEngine
) -> None:
    """The rules endpoint names every registered detector with its window."""
    engine.register(PortScanRule(unique_port_threshold=5, window_seconds=10.0))
    engine.register(HighBandwidthRule(window_seconds=5.0))
    body = client.get(RULES_URL).json()
    assert body["success"] is True
    assert body["data"]["count"] == 2
    by_id = {rule["rule_id"]: rule for rule in body["data"]["rules"]}
    assert by_id["port_scan"]["rule_name"] == "Port Scan"
    assert by_id["port_scan"]["window_seconds"] == 10.0
    assert by_id["high_bandwidth"]["enabled"] is True


def test_rules_report_enabled_state(
    client: TestClient, engine: DetectionEngine
) -> None:
    """A disabled detector is still listed, and reports itself disabled."""
    rule = PortScanRule(unique_port_threshold=5)
    engine.register(rule)
    engine.disable(rule.rule_id)
    rules = client.get(RULES_URL).json()["data"]["rules"]
    assert rules[0]["rule_id"] == "port_scan"
    assert rules[0]["enabled"] is False


def test_rules_expose_engine_diagnostics(
    client: TestClient, engine: DetectionEngine
) -> None:
    """Diagnostics report the counts the engine tracked (M10.6/M10.17)."""
    engine.register(PortScanRule(unique_port_threshold=5))
    seed(engine, make_finding())
    diagnostics = client.get(RULES_URL).json()["data"]["diagnostics"]
    assert diagnostics["registered_rules"] == 1
    assert diagnostics["enabled_rules"] == 1
    assert diagnostics["retained_findings"] == 1


def test_rules_state_size_is_bounded_and_reported(
    client: TestClient, engine: DetectionEngine
) -> None:
    """A detector reports how many subjects it currently tracks (M10.19)."""
    rule = PortScanRule(unique_port_threshold=5)
    engine.register(rule)
    rule.evaluate(
        make_context(packet=make_syn_packet(source_ip=SOURCE_IP, destination_port=80))
    )
    rules = client.get(RULES_URL).json()["data"]["rules"]
    assert rules[0]["state_size"] == 1


def test_rules_empty_when_none_registered(
    client: TestClient, engine: DetectionEngine
) -> None:
    """An engine with no rules reports an empty rule list, not an error."""
    body = client.get(RULES_URL).json()
    assert body["data"]["count"] == 0
    assert body["data"]["rules"] == []


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_clears_retained_findings(
    client: TestClient, engine: DetectionEngine
) -> None:
    """Reset discards retained findings so the next read is empty (M10.22)."""
    seed(engine, make_finding(), make_finding())
    assert client.post(RESET_URL).status_code == 200
    assert client.get(DETECTIONS_URL).json()["data"]["count"] == 0


def test_reset_discards_detector_state(
    client: TestClient, engine: DetectionEngine
) -> None:
    """Reset clears accumulated detector state as well as findings (M10.19)."""
    rule = PortScanRule(unique_port_threshold=5)
    engine.register(rule)
    rule.evaluate(
        make_context(packet=make_syn_packet(source_ip=SOURCE_IP, destination_port=80))
    )
    assert client.get(RULES_URL).json()["data"]["rules"][0]["state_size"] == 1
    client.post(RESET_URL)
    assert client.get(RULES_URL).json()["data"]["rules"][0]["state_size"] == 0


def test_reset_returns_fresh_diagnostics(
    client: TestClient, engine: DetectionEngine
) -> None:
    """Reset responds with the diagnostics it just zeroed."""
    seed(engine, make_finding())
    body = client.post(RESET_URL).json()
    assert body["success"] is True
    assert body["data"]["retained_findings"] == 0
    assert body["data"]["findings"] == 0


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


def test_collection_rejects_post(client: TestClient) -> None:
    """The findings collection is read-only; only ``/reset`` accepts a POST."""
    assert client.post(DETECTIONS_URL).status_code == 405


def test_collection_rejects_put(client: TestClient) -> None:
    """A finding is an observation, so it cannot be replaced."""
    assert client.put(DETECTIONS_URL).status_code == 405


def test_collection_rejects_delete(client: TestClient) -> None:
    """Findings are discarded through ``/reset``, not by deleting the collection."""
    assert client.delete(DETECTIONS_URL).status_code == 405
