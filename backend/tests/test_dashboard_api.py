"""API tests for the consolidated dashboard endpoint (M13.19).

The dashboard aggregates seven services, so the tests are arranged around three
questions: does every block appear, does each block report the number the
*owning* service reports rather than a recomputed one, and does one failing
service leave the rest of the summary intact (M13.29).

The third is the one that matters most. A dashboard that answers ``500`` because
one of its dependencies is unhappy is far less useful than one that answers with
six sections and says which is missing, so the isolation is exercised directly
rather than assumed.
"""

from __future__ import annotations

from collections.abc import Callable, Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.api.v1.deps import get_alert_queries
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.detection import DetectionEngine, get_detection_engine
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.schemas.device import DeviceStatus
from app.services.capture_manager import get_capture_manager
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager
from tests.correlation_fakes import make_alert, make_engine
from tests.detection_fakes import FixedRule, make_context
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet
from tests.m13_fakes import api_client, capture_manager_override

SUMMARY_URL = "/api/v1/dashboard/summary"

#: The severities the alert block always names (M13.19).
SEVERITIES = ("critical", "high", "medium", "low")

#: The sections the payload always carries.
SECTIONS = (
    "capture",
    "traffic",
    "devices",
    "connections",
    "alerts",
    "incidents",
    "detections",
)


class FailingAlertQueries:
    """An alert read service whose only call fails (M13.29).

    Deliberately not a ``Mock``: the dashboard has to survive a *real* failure
    of one collaborator, and a raising method is the smallest honest way to
    produce one.
    """

    def summary(self) -> dict:
        """Fail, standing in for an unusable alert store."""
        raise RuntimeError("simulated alert store outage")


@pytest.fixture
def statistics() -> TrafficStatisticsManager:
    """A fresh statistics manager owned by one test."""
    return TrafficStatisticsManager()


@pytest.fixture
def devices() -> DeviceDiscoveryManager:
    """A device registry over a deterministic clock."""
    return DeviceDiscoveryManager(
        inactivity_threshold=60.0,
        retention_seconds=600.0,
        clock=FakeClock(PACKET_BASE_TIME),
    )


@pytest.fixture
def tracker() -> ConnectionTracker:
    """A thread-free connection tracker over a deterministic clock."""
    return ConnectionTracker(autostart_cleanup=False, clock=FakeClock(PACKET_BASE_TIME))


@pytest.fixture
def detections() -> DetectionEngine:
    """An engine with one rule that fires on demand."""
    return DetectionEngine([FixedRule()])


@pytest.fixture
def correlations() -> CorrelationEngine:
    """A correlation engine over deterministic collaborators."""
    return make_engine()


@pytest.fixture
def client(
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    detections: DetectionEngine,
    correlations: CorrelationEngine,
    session_factory: Callable[[], Session],
) -> Generator[TestClient, None, None]:
    """A client whose seven dashboard collaborators are all overridden.

    Every override is a zero-argument callable, which is what FastAPI requires
    of a dependency: passing a builder with parameters would make FastAPI read
    those parameters as request inputs.
    """
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_statistics_manager: lambda: statistics,
            get_device_manager: lambda: devices,
            get_connection_tracker: lambda: tracker,
            get_detection_engine: lambda: detections,
            get_correlation_engine: lambda: correlations,
            get_alert_queries: lambda: AlertQueries(session_factory=session_factory),
        }
    ) as test_client:
        yield test_client


def seed_device(devices: DeviceDiscoveryManager) -> None:
    """Track one device through the real M8 path."""
    devices.process_packet(
        make_normalized_packet(
            source_mac="AA:BB:CC:DD:EE:FF",
            source_ip="192.168.1.10",
            destination_ip=None,
            timestamp=PACKET_BASE_TIME,
        )
    )


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_summary_carries_every_section(client: TestClient) -> None:
    """Every section is present, so a client renders a fixed layout (M13.19)."""
    body = client.get(SUMMARY_URL).json()

    assert body["success"] is True
    assert set(body["data"]) == {"generated_at", "unavailable_sections", *SECTIONS}


def test_every_section_is_available_when_services_answer(
    client: TestClient,
) -> None:
    """Nothing is reported unavailable while every collaborator works."""
    data = client.get(SUMMARY_URL).json()["data"]

    assert data["unavailable_sections"] == []
    for name in SECTIONS:
        assert data[name]["available"] is True, name
        assert data[name]["error"] is None, name


def test_generated_at_is_iso8601_utc(client: TestClient) -> None:
    """The summary carries one documented timestamp format (M13.26)."""
    generated = client.get(SUMMARY_URL).json()["data"]["generated_at"]

    assert generated.endswith("+00:00")


# ---------------------------------------------------------------------------
# Empty services
# ---------------------------------------------------------------------------


def test_empty_services_report_zeroes_rather_than_absences(
    client: TestClient,
) -> None:
    """A service that holds nothing reports zeroes, not a missing block.

    "Nothing observed" and "could not be read" are different facts, and only the
    first is true here (M13.19).
    """
    data = client.get(SUMMARY_URL).json()["data"]

    assert data["capture"]["data"]["running"] is False
    assert data["traffic"]["data"]["total_packets"] == 0
    assert data["devices"]["data"]["total"] == 0
    assert data["connections"]["data"]["tracked"] == 0
    assert data["alerts"]["data"]["total"] == 0
    assert data["incidents"]["data"]["total"] == 0
    assert data["detections"]["data"]["retained"] == 0
    assert data["detections"]["data"]["recent"] == []


def test_device_block_names_every_activity_state(client: TestClient) -> None:
    """``by_status`` always names each state, so a client needs no fallback."""
    by_status = client.get(SUMMARY_URL).json()["data"]["devices"]["data"]["by_status"]

    assert set(by_status) == {status.value for status in DeviceStatus}
    assert all(count == 0 for count in by_status.values())


def test_alert_block_names_every_severity(client: TestClient) -> None:
    """``by_severity`` always names the four severities (M13.19)."""
    by_severity = client.get(SUMMARY_URL).json()["data"]["alerts"]["data"]["by_severity"]

    assert set(by_severity) == set(SEVERITIES)


# ---------------------------------------------------------------------------
# Blocks reflect the owning service
# ---------------------------------------------------------------------------


def test_traffic_block_matches_the_statistics_manager(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """The traffic figures are the M6 snapshot, not a second aggregation."""
    statistics.record_packet(make_normalized_packet(length=100))
    statistics.record_packet(make_normalized_packet(length=60))

    traffic = client.get(SUMMARY_URL).json()["data"]["traffic"]["data"]
    snapshot = statistics.get_statistics()

    assert traffic["total_packets"] == snapshot.total_packets == 2
    assert traffic["total_bytes"] == snapshot.total_bytes == 160


def test_device_block_matches_the_registry(
    client: TestClient, devices: DeviceDiscoveryManager
) -> None:
    """The device counts come from the M8 registry's own views."""
    seed_device(devices)

    block = client.get(SUMMARY_URL).json()["data"]["devices"]["data"]

    assert block["total"] == len(devices.list_device_views()) == 1
    assert block["by_status"]["active"] == 1


def test_connection_block_matches_the_tracker(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The connection counters are the tracker's own, so they cannot drift."""
    tracker.process_packet(make_normalized_packet())

    block = client.get(SUMMARY_URL).json()["data"]["connections"]["data"]

    assert block["active"] == tracker.get_active_count() == 1
    assert block["tracked"] == tracker.get_tracked_count() == 1


def test_detections_block_carries_recent_findings(
    client: TestClient, detections: DetectionEngine
) -> None:
    """Recent findings are the M10 wire views, not a shape invented here."""
    assert detections.evaluate(make_context()) is not None

    block = client.get(SUMMARY_URL).json()["data"]["detections"]["data"]

    assert block["retained"] == 1
    assert len(block["recent"]) == 1
    assert block["recent"][0]["rule_id"] == "fixed"


def test_incident_block_matches_the_engine(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """The incident counts and worst score are the M12 engine's own (M12.13).

    The expected values are taken from the registry the engine holds rather than
    from a literal, because how many incidents two alerts form is M12's rule to
    apply, not this endpoint's.
    """
    correlations.correlate_alerts([make_alert(), make_alert(alert_id=2)])
    incidents = correlations.registry.incidents()

    block = client.get(SUMMARY_URL).json()["data"]["incidents"]["data"]

    assert block["total"] == correlations.count_incidents() == len(incidents)
    # Every lifecycle state is named, and the per-state counts add up to the
    # total, so the breakdown and the total cannot describe different sets.
    assert set(block["by_status"]) == {
        "open",
        "investigating",
        "resolved",
        "dismissed",
    }
    assert sum(block["by_status"].values()) == block["total"]


def test_recent_limit_bounds_the_findings(
    client: TestClient, detections: DetectionEngine
) -> None:
    """``recent_limit`` bounds what the summary carries (M13.24)."""
    for _ in range(4):
        detections.evaluate(make_context())

    data = client.get(SUMMARY_URL, params={"recent_limit": 2}).json()["data"]

    assert data["detections"]["data"]["retained"] == 4
    assert len(data["detections"]["data"]["recent"]) == 2


def test_recent_limit_is_validated(client: TestClient) -> None:
    """An out-of-range limit fails request validation, not the handler."""
    assert client.get(SUMMARY_URL, params={"recent_limit": -1}).status_code == 422
    assert client.get(SUMMARY_URL, params={"recent_limit": 500}).status_code == 422


def test_no_risk_or_severity_is_invented_for_devices(
    client: TestClient, devices: DeviceDiscoveryManager
) -> None:
    """M8 produces no risk score, so the device block carries none (M13.10)."""
    seed_device(devices)

    block = client.get(SUMMARY_URL).json()["data"]["devices"]["data"]

    assert "risk_score" not in block
    assert "severity" not in block


# ---------------------------------------------------------------------------
# Section isolation (M13.29)
# ---------------------------------------------------------------------------


def test_one_failing_section_leaves_the_rest_intact(
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    detections: DetectionEngine,
    correlations: CorrelationEngine,
) -> None:
    """A failing alerts section does not stop the other six being served."""
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_statistics_manager: lambda: statistics,
            get_device_manager: lambda: devices,
            get_connection_tracker: lambda: tracker,
            get_detection_engine: lambda: detections,
            get_correlation_engine: lambda: correlations,
            get_alert_queries: lambda: FailingAlertQueries(),
        }
    ) as failing_client:
        data = failing_client.get(SUMMARY_URL).json()["data"]

    assert data["alerts"]["available"] is False
    assert data["alerts"]["data"] is None
    assert data["unavailable_sections"] == ["alerts"]
    # Everything else is still there, with real values.
    assert data["devices"]["available"] is True
    assert data["detections"]["available"] is True


def test_a_failing_section_still_answers_200(
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    detections: DetectionEngine,
    correlations: CorrelationEngine,
) -> None:
    """A degraded summary is a payload, not a failed request (M13.19)."""
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_statistics_manager: lambda: statistics,
            get_device_manager: lambda: devices,
            get_connection_tracker: lambda: tracker,
            get_detection_engine: lambda: detections,
            get_correlation_engine: lambda: correlations,
            get_alert_queries: lambda: FailingAlertQueries(),
        }
    ) as failing_client:
        response = failing_client.get(SUMMARY_URL)

    assert response.status_code == 200
    assert response.json()["success"] is True


def test_a_failing_section_reports_no_internal_detail(
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    detections: DetectionEngine,
    correlations: CorrelationEngine,
) -> None:
    """The reason names the section and never the exception (M13.5/M13.30).

    A driver message can name a filesystem path or a host, and neither belongs
    in a response body.
    """
    with api_client(
        {
            get_capture_manager: capture_manager_override(),
            get_statistics_manager: lambda: statistics,
            get_device_manager: lambda: devices,
            get_connection_tracker: lambda: tracker,
            get_detection_engine: lambda: detections,
            get_correlation_engine: lambda: correlations,
            get_alert_queries: lambda: FailingAlertQueries(),
        }
    ) as failing_client:
        response = failing_client.get(SUMMARY_URL)

    text = response.text
    assert "simulated alert store outage" not in text
    assert "RuntimeError" not in text
    assert "Traceback" not in text
    assert "alerts" in response.json()["data"]["alerts"]["error"].lower()


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


def test_summary_is_read_only(client: TestClient) -> None:
    """The dashboard reports state; it never changes it."""
    assert client.post(SUMMARY_URL).status_code == 405
    assert client.put(SUMMARY_URL).status_code == 405
    assert client.delete(SUMMARY_URL).status_code == 405


def test_unknown_dashboard_route_is_404(client: TestClient) -> None:
    """An unknown dashboard sub-route answers in the standard envelope."""
    assert client.get("/api/v1/dashboard/nope").status_code == 404
