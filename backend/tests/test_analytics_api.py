"""API tests for the analytics endpoints (M13.18).

Analytics is a *derived* view over services that already exist, and the tests
are written to hold it to that. Rather than asserting literals, most of them
compare each figure against the value the owning service reports, so a route
that started recomputing — or re-aggregating — rather than reading would fail.

One comparison is deliberately about two *different* sources: ``traffic``
reports the live M6 packet total beside the count of rows actually in the packet
table. They are equal only by coincidence, and a test that seeds traffic but
persists nothing pins that down.
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
from app.database.session import get_db
from app.detection import DetectionEngine, get_detection_engine
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.risk.bands import BAND_RANGES
from app.schemas.device import DeviceStatus
from app.schemas.packet import PacketType
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager
from tests.correlation_fakes import make_alert, make_engine
from tests.detection_fakes import FixedRule, make_context
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet
from tests.m13_fakes import api_client, make_db_override

TRAFFIC_URL = "/api/v1/analytics/traffic"
PROTOCOLS_URL = "/api/v1/analytics/protocols"
DEVICES_URL = "/api/v1/analytics/devices"
CONNECTIONS_URL = "/api/v1/analytics/connections"
THREATS_URL = "/api/v1/analytics/threats"

MAC_A = "AA:BB:CC:DD:EE:FF"
IP_A = "192.168.1.10"


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
    db_engine,
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    detections: DetectionEngine,
    correlations: CorrelationEngine,
    session_factory: Callable[[], Session],
) -> Generator[TestClient, None, None]:
    """A client whose analytics collaborators are all overridden."""
    with api_client(
        {
            get_db: make_db_override(db_engine),
            get_statistics_manager: lambda: statistics,
            get_device_manager: lambda: devices,
            get_connection_tracker: lambda: tracker,
            get_detection_engine: lambda: detections,
            get_correlation_engine: lambda: correlations,
            get_alert_queries: lambda: AlertQueries(session_factory=session_factory),
        }
    ) as test_client:
        yield test_client


def seed_device(devices: DeviceDiscoveryManager, *, length: int = 100) -> None:
    """Track one device through the real M8 path."""
    devices.process_packet(
        make_normalized_packet(
            source_mac=MAC_A,
            source_ip=IP_A,
            destination_ip=None,
            length=length,
            timestamp=PACKET_BASE_TIME,
        )
    )


def seed_protocol(
    statistics: TrafficStatisticsManager,
    packet_type: PacketType,
    *,
    length: int,
    count: int = 1,
) -> None:
    """Record ``count`` packets of one M5 classification (M6.4).

    Both ``protocol`` and ``packet_type`` are set, because a real capture carries
    both and M5 keeps them consistent. The distinction matters here: M6 labels
    its counters with the *classification*, so DNS rides on UDP but is reported
    under its own name.
    """
    for _ in range(count):
        statistics.record_packet(
            make_normalized_packet(
                protocol=packet_type.value,
                packet_type=packet_type,
                length=length,
            )
        )


# ---------------------------------------------------------------------------
# /analytics/traffic
# ---------------------------------------------------------------------------


def test_traffic_carries_the_expected_blocks(client: TestClient) -> None:
    """The traffic view carries totals, derived ratios and rankings."""
    data = client.get(TRAFFIC_URL).json()["data"]

    assert set(data) >= {
        "total_packets",
        "total_bytes",
        "packets_per_second",
        "bytes_per_second",
        "bits_per_second",
        "average_packet_bytes",
        "stored_packet_count",
        "protocol_count",
        "directions",
        "protocols",
        "top_sources",
        "top_destinations",
        "top_ports",
    }


def test_traffic_reports_the_live_totals(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """The totals are the M6 snapshot, not a second aggregation."""
    statistics.record_packet(make_normalized_packet(length=100))
    statistics.record_packet(make_normalized_packet(length=60))

    data = client.get(TRAFFIC_URL).json()["data"]
    snapshot = statistics.get_statistics()

    assert data["total_packets"] == snapshot.total_packets == 2
    assert data["total_bytes"] == snapshot.total_bytes == 160


def test_traffic_average_is_derived_from_the_snapshot(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """The mean packet size is the snapshot's own ratio, computed once."""
    statistics.record_packet(make_normalized_packet(length=100))
    statistics.record_packet(make_normalized_packet(length=50))

    data = client.get(TRAFFIC_URL).json()["data"]

    assert data["average_packet_bytes"] == 75.0


def test_traffic_empty_state_reports_zeroes(client: TestClient) -> None:
    """With nothing observed the answer is zero, never an invented series."""
    data = client.get(TRAFFIC_URL).json()["data"]

    assert data["total_packets"] == 0
    assert data["average_packet_bytes"] == 0.0
    assert data["protocols"] == []
    assert data["top_sources"] == []


def test_traffic_separates_live_from_stored(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """Live traffic and persisted traffic are two different figures (M13.18).

    Traffic is recorded on the live side and nothing is persisted, so the two
    numbers must disagree — which is what proves the endpoint reports the packet
    table rather than echoing the manager.
    """
    statistics.record_packet(make_normalized_packet(length=100))

    data = client.get(TRAFFIC_URL).json()["data"]

    assert data["total_packets"] == 1
    assert data["stored_packet_count"] == 0


def test_traffic_ranks_the_leading_talkers(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """Top sources, destinations and ports come from the M6 manager."""
    statistics.record_packet(
        make_normalized_packet(
            source_ip="192.168.1.10", destination_ip="8.8.8.8", destination_port=443
        )
    )

    data = client.get(TRAFFIC_URL).json()["data"]

    assert {entry["key"] for entry in data["top_sources"]} == {"192.168.1.10"}
    assert {entry["key"] for entry in data["top_destinations"]} == {"8.8.8.8"}


def test_traffic_accepts_a_supported_window(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """A supported rate window is accepted and does not change the totals."""
    statistics.record_packet(make_normalized_packet(length=100))

    data = client.get(TRAFFIC_URL, params={"window": "10s"}).json()["data"]

    assert data["total_packets"] == 1


def test_traffic_rejects_an_unsupported_window(client: TestClient) -> None:
    """An unknown window label fails request validation."""
    assert client.get(TRAFFIC_URL, params={"window": "5m"}).status_code == 422


def test_traffic_limit_and_metric_are_validated(client: TestClient) -> None:
    """Out-of-range limits and unknown metrics fail request validation."""
    assert client.get(TRAFFIC_URL, params={"limit": 0}).status_code == 422
    assert client.get(TRAFFIC_URL, params={"limit": 5000}).status_code == 422
    assert client.get(TRAFFIC_URL, params={"by": "magic"}).status_code == 422


# ---------------------------------------------------------------------------
# /analytics/protocols
# ---------------------------------------------------------------------------


def test_protocols_empty_state(client: TestClient) -> None:
    """No protocol has been seen, so the breakdown is empty."""
    data = client.get(PROTOCOLS_URL).json()["data"]

    assert data["count"] == 0
    assert data["protocols"] == []
    assert data["total_packets"] == 0


def test_protocols_reports_each_protocol_with_its_totals(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """Entries carry packet and byte totals, and the sum matches the view."""
    seed_protocol(statistics, PacketType.TCP, length=100)
    seed_protocol(statistics, PacketType.UDP, length=40)

    data = client.get(PROTOCOLS_URL).json()["data"]
    by_name = {entry["protocol"]: entry for entry in data["protocols"]}

    assert data["count"] == 2
    assert by_name["TCP"]["packets"] == 1
    assert by_name["UDP"]["bytes"] == 40
    assert data["total_packets"] == sum(e["packets"] for e in data["protocols"])
    assert data["total_bytes"] == 140


def test_protocol_name_is_the_packet_classification(  # noqa: D401
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """DNS is reported as DNS, not folded into the UDP it rides on (M6.4).

    The classification M5 assigns is what M6 counts, so the endpoint must not
    re-derive a protocol name from the transport field.
    """
    seed_protocol(statistics, PacketType.DNS, length=90)

    names = [entry["protocol"] for entry in client.get(PROTOCOLS_URL).json()["data"].get("protocols")]

    assert names == ["DNS"]


def test_protocols_are_ordered_by_the_requested_metric(
    client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """``by=bytes`` orders on bytes; the default orders on packets (M13.18)."""
    seed_protocol(statistics, PacketType.TCP, length=1000)
    seed_protocol(statistics, PacketType.UDP, length=10, count=3)

    by_packets = client.get(PROTOCOLS_URL).json()["data"]
    by_bytes = client.get(PROTOCOLS_URL, params={"by": "bytes"}).json()["data"]

    assert [e["protocol"] for e in by_packets["protocols"]][0] == "UDP"
    assert [e["protocol"] for e in by_bytes["protocols"]][0] == "TCP"
    assert by_bytes["rank_by"] == "bytes"


def test_protocols_reject_an_unknown_metric(client: TestClient) -> None:
    """An unsupported ranking metric fails request validation."""
    assert client.get(PROTOCOLS_URL, params={"by": "magic"}).status_code == 422


# ---------------------------------------------------------------------------
# /analytics/devices
# ---------------------------------------------------------------------------


def test_devices_empty_state(client: TestClient) -> None:
    """An empty registry names every state at zero and ranks nothing."""
    data = client.get(DEVICES_URL).json()["data"]

    assert data["total"] == 0
    assert data["top"] == []
    assert set(data["by_status"]) == {status.value for status in DeviceStatus}


def test_devices_ranking_matches_the_registry(
    client: TestClient, devices: DeviceDiscoveryManager
) -> None:
    """The total and the ranking come from the M8 registry's own views."""
    seed_device(devices)

    data = client.get(DEVICES_URL).json()["data"]

    assert data["total"] == len(devices.list_device_views()) == 1
    assert data["by_status"]["active"] == 1
    assert data["top"][0]["device_id"] == f"mac:{MAC_A}"


def test_devices_ranking_carries_identity(
    client: TestClient, devices: DeviceDiscoveryManager
) -> None:
    """A ranked device carries its own identity, so no second request is needed."""
    seed_device(devices, length=250)

    entry = client.get(DEVICES_URL).json()["data"]["top"][0]

    assert entry["mac_address"] == MAC_A
    assert entry["ip_addresses"] == [IP_A]
    assert entry["packets"] == 1
    assert entry["bytes"] == 250
    assert entry["status"] == "active"


def test_devices_ranking_carries_no_risk(
    client: TestClient, devices: DeviceDiscoveryManager
) -> None:
    """M8 scores no risk, so the ranking invents none (M13.10)."""
    seed_device(devices)

    entry = client.get(DEVICES_URL).json()["data"]["top"][0]

    assert "risk_score" not in entry


def test_devices_limit_is_validated(client: TestClient) -> None:
    """An out-of-range limit fails request validation."""
    assert client.get(DEVICES_URL, params={"limit": 0}).status_code == 422
    assert client.get(DEVICES_URL, params={"limit": 5000}).status_code == 422


# ---------------------------------------------------------------------------
# /analytics/connections
# ---------------------------------------------------------------------------


def test_connections_empty_state(client: TestClient) -> None:
    """An empty tracker reports zero counters and no conversations."""
    data = client.get(CONNECTIONS_URL).json()["data"]

    assert data["active"] == 0
    assert data["historical"] == 0
    assert data["tracked"] == 0
    assert data["top"] == []


def test_connections_counters_match_the_tracker(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The counters are the tracker's own, so they cannot drift."""
    tracker.process_packet(make_normalized_packet())

    data = client.get(CONNECTIONS_URL).json()["data"]

    assert data["active"] == tracker.get_active_count() == 1
    assert data["tracked"] == tracker.get_tracked_count() == 1
    assert data["top"][0]["protocol"] == "TCP"
    assert data["top"][0]["source_port"] is not None


def test_connections_include_retired_conversations(
    client: TestClient, tracker: ConnectionTracker
) -> None:
    """The ranking spans every tracked conversation, not only live ones (M13.18).

    The busiest conversation of a session is often one that has already closed.
    """
    tracker.process_packet(make_normalized_packet())
    tracker.expire_connections(now=PACKET_BASE_TIME + 100_000)

    data = client.get(CONNECTIONS_URL).json()["data"]

    assert data["active"] == 0
    assert data["tracked"] == 1
    assert len(data["top"]) == 1


def test_connections_limit_is_validated(client: TestClient) -> None:
    """An out-of-range limit fails request validation."""
    assert client.get(CONNECTIONS_URL, params={"limit": 0}).status_code == 422
    assert client.get(CONNECTIONS_URL, params={"limit": 5000}).status_code == 422


# ---------------------------------------------------------------------------
# /analytics/threats
# ---------------------------------------------------------------------------


def test_threats_empty_state_reports_zeroes(client: TestClient) -> None:
    """Nothing observed means zeros, with every vocabulary still named."""
    data = client.get(THREATS_URL).json()["data"]

    assert data["alerts_total"] == 0
    assert data["incidents_total"] == 0
    assert data["detections_findings"] == 0
    assert set(data["alerts_by_severity"]) == {
        "critical",
        "high",
        "medium",
        "low",
    }


def test_threats_bands_always_name_every_band(client: TestClient) -> None:
    """The risk-band breakdown names each band, so a client needs no fallback."""
    band_counts = client.get(THREATS_URL).json()["data"]["incidents_by_risk_band"]

    assert set(band_counts) == {band.value for band, _low, _high in BAND_RANGES}


def test_threats_reports_finding_counters(
    client: TestClient, detections: DetectionEngine
) -> None:
    """The finding counters are the M10 engine's own diagnostics."""
    detections.evaluate(make_context())

    data = client.get(THREATS_URL).json()["data"]
    diagnostics = detections.get_diagnostics()

    assert data["findings_retained"] == diagnostics.retained_findings == 1
    assert data["detections_findings"] == diagnostics.findings == 1


def test_threats_lists_each_detector(
    client: TestClient, detections: DetectionEngine
) -> None:
    """Every registered detector appears, with its own counters."""
    rules = client.get(THREATS_URL).json()["data"]["rules"]

    assert [rule["rule_id"] for rule in rules] == ["fixed"]
    assert rules[0]["rule_name"] == "Fixed Rule"
    assert rules[0]["enabled"] is True


def test_threats_incident_breakdown_matches_the_engine(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """Incident counts and bands come from the M12 engine, not a re-scoring."""
    correlations.correlate_alerts([make_alert(), make_alert(alert_id=2)])

    data = client.get(THREATS_URL).json()["data"]

    assert data["incidents_total"] == correlations.count_incidents()
    assert sum(data["incidents_by_risk_band"].values()) == data["incidents_total"]
    assert sum(data["incidents_by_status"].values()) == data["incidents_total"]


def test_threats_keeps_the_three_notions_of_severity_apart(
    client: TestClient, detections: DetectionEngine
) -> None:
    """Findings, alert severity and risk bands stay distinct fields (M12.16).

    A finding carries no severity at all, so the alert severity scale and the
    incident risk scale must not be collapsed into one "threat" number.
    """
    detections.evaluate(make_context())

    data = client.get(THREATS_URL).json()["data"]

    assert "alerts_by_severity" in data
    assert "incidents_by_risk_band" in data
    assert data["alerts_total"] == 0
    assert data["detections_findings"] == 1


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url", [TRAFFIC_URL, PROTOCOLS_URL, DEVICES_URL, CONNECTIONS_URL, THREATS_URL]
)
def test_analytics_is_read_only(client: TestClient, url: str) -> None:
    """Analytics reports; it never changes anything."""
    assert client.post(url).status_code == 405
    assert client.put(url).status_code == 405
    assert client.delete(url).status_code == 405
