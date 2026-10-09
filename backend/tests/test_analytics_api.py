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
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.alerts.queries import AlertQueries
from app.analytics.metrics import MAX_GROUPS
from app.analytics.sections import UNAVAILABLE_MESSAGE
from app.analytics.window import (
    BUCKET_SIZES,
    MAX_BUCKETS,
    MAX_WINDOW_SECONDS,
)
from app.api.common.errors import ErrorCode
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
from tests.analytics_fakes import seed_alert, seed_connection, seed_packet, utc
from tests.correlation_fakes import make_alert, make_engine
from tests.detection_fakes import FixedRule, make_context
from tests.fakes import PACKET_BASE_TIME, FakeClock, make_normalized_packet
from tests.m13_fakes import (
    api_client,
    make_db_override,
    make_unreadable_db_override,
)

TRAFFIC_URL = "/api/v1/analytics/traffic"
PROTOCOLS_URL = "/api/v1/analytics/protocols"
DEVICES_URL = "/api/v1/analytics/devices"
CONNECTIONS_URL = "/api/v1/analytics/connections"
THREATS_URL = "/api/v1/analytics/threats"

MAC_A = "AA:BB:CC:DD:EE:FF"
IP_A = "192.168.1.10"

#: The window the M16 tests read over when they seed their own rows. The default
#: window ends at *now*, so a seeded row at ``PACKET_BASE_TIME`` would fall well
#: outside it; every test that asserts on stored content therefore names its
#: bounds. Ten minutes, which is long enough to hold several instants and short
#: enough that the chosen bucket stays small.
WINDOW_SINCE = PACKET_BASE_TIME
WINDOW_UNTIL = PACKET_BASE_TIME + 600.0
#: The bucket size those bounds resolve to when a request names none: ten seconds
#: is the smallest documented size whose ten-minute series fits the cap.
WINDOW_CHOSEN_BUCKET = 10


def iso(epoch: float) -> str:
    """Render epoch seconds the way the API's own bounds are written (M13.26)."""
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()


def window_params(**extra: object) -> dict[str, object]:
    """Return the query parameters naming the window these tests read over."""
    return {"since": iso(WINDOW_SINCE), "until": iso(WINDOW_UNTIL), **extra}


def section_of(data: dict, name: str) -> dict:
    """Return one availability section from a response payload."""
    section = data[name]
    assert isinstance(section, dict)
    return section


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


# ---------------------------------------------------------------------------
# the window every route resolves and reports (M16.7)
# ---------------------------------------------------------------------------


def test_analytics_keeps_the_m13_envelope(client: TestClient) -> None:
    """The M16 additions ride inside the envelope M13 already defined (M16.11)."""
    body = client.get(TRAFFIC_URL).json()

    assert body["success"] is True
    assert isinstance(body["message"], str)
    assert body["message"]
    assert isinstance(body["data"], dict)


@pytest.mark.parametrize(
    "url", [TRAFFIC_URL, PROTOCOLS_URL, DEVICES_URL, CONNECTIONS_URL, THREATS_URL]
)
def test_every_route_reports_the_window_it_read_over(
    client: TestClient, url: str
) -> None:
    """A request naming no bounds gets the default hour and is told so (M16.7)."""
    period = client.get(url).json()["data"]["period"]

    assert set(period) == {
        "since",
        "until",
        "seconds",
        "bucket_seconds",
        "buckets",
        "max_buckets",
        "defaulted",
    }
    assert period["defaulted"] is True
    assert abs(period["seconds"] - 3600.0) < 1e-3
    assert period["max_buckets"] == MAX_BUCKETS
    assert period["bucket_seconds"] in BUCKET_SIZES
    assert 0 < period["buckets"] <= MAX_BUCKETS


@pytest.mark.parametrize(
    "url", [TRAFFIC_URL, PROTOCOLS_URL, DEVICES_URL, CONNECTIONS_URL, THREATS_URL]
)
def test_a_named_window_is_echoed_verbatim(client: TestClient, url: str) -> None:
    """The bounds are read as given, not adjusted into a different question."""
    period = client.get(url, params=window_params()).json()["data"]["period"]

    assert period["since"] == iso(WINDOW_SINCE)
    assert period["until"] == iso(WINDOW_UNTIL)
    assert period["seconds"] == 600.0
    assert period["defaulted"] is False


def test_the_bucket_is_chosen_when_the_request_names_none(
    client: TestClient,
) -> None:
    """The smallest documented bucket whose series fits the cap is used (M16.7)."""
    period = client.get(TRAFFIC_URL, params=window_params()).json()["data"]["period"]

    assert period["bucket_seconds"] == WINDOW_CHOSEN_BUCKET
    assert period["buckets"] == 60
    assert period["buckets"] <= MAX_BUCKETS


def test_a_named_bucket_is_honoured_and_bounds_the_series(client: TestClient) -> None:
    """Ten minutes at a minute a point is eleven points, not an open-ended trend."""
    data = client.get(TRAFFIC_URL, params=window_params(bucket_seconds=60)).json()[
        "data"
    ]

    assert data["period"]["bucket_seconds"] == 60
    assert data["period"]["buckets"] == 11
    assert len(data["stored"]["data"]["series"]) == 11


def test_naming_only_one_bound_leaves_the_other_defaulted(client: TestClient) -> None:
    """``defaulted`` describes the pair, not either half of it (M16.7).

    Only ``since`` is sent, so ``until`` is now and the window was not wholly
    defaulted — which is what tells a client the bounds it is looking at are
    partly its own. The instant is a whole second so the echoed bound compares
    exactly rather than within a microsecond.
    """
    since = int(datetime.now(tz=timezone.utc).timestamp()) - 600

    period = client.get(TRAFFIC_URL, params={"since": iso(since)}).json()["data"][
        "period"
    ]

    assert period["defaulted"] is False
    assert period["since"] == iso(since)
    assert period["until"] > period["since"]


def test_a_window_that_cannot_be_honoured_is_refused_not_adjusted(
    client: TestClient,
) -> None:
    """An unacceptable window is a 400 naming the field, never a silent rewrite."""
    params = {
        "since": iso(WINDOW_UNTIL),
        "until": iso(WINDOW_SINCE),
    }

    response = client.get(TRAFFIC_URL, params=params)
    body = response.json()

    assert response.status_code == 400
    assert body["success"] is False
    assert body["errors"][0]["field"] == "window"
    assert body["errors"][0]["code"] == ErrorCode.INVALID_FILTER
    assert "since" in body["message"].lower()


# ---------------------------------------------------------------------------
# windows a request may not ask for (M16.7)
# ---------------------------------------------------------------------------

#: Windows a request may not ask for, paired with the word the refusal must name
#: so a caller can tell which bound was the problem. Each is a request that
#: cannot be honoured; none of them may be silently adjusted into an answer.
REFUSED_WINDOWS = [
    pytest.param({"since": "not-a-date"}, "since", id="unparsable-since"),
    pytest.param(
        {"until": "2023-13-45T00:00:00+00:00"}, "until", id="unparsable-until"
    ),
    pytest.param({"since": "   "}, "since", id="blank-since"),
    pytest.param(
        {"since": iso(WINDOW_UNTIL), "until": iso(WINDOW_SINCE)},
        "since",
        id="inverted",
    ),
    pytest.param(
        {"since": iso(WINDOW_SINCE), "until": iso(WINDOW_SINCE)},
        "window",
        id="empty",
    ),
    pytest.param(
        {"since": iso(0.0), "until": iso(MAX_WINDOW_SECONDS + 60.0)},
        "window",
        id="longer-than-the-ceiling",
    ),
    pytest.param(window_params(bucket_seconds=45), "bucket", id="unknown-bucket"),
    pytest.param(
        {
            "since": iso(0.0),
            "until": iso(MAX_WINDOW_SECONDS),
            "bucket_seconds": BUCKET_SIZES[0],
        },
        "bucket",
        id="bucket-too-fine-for-the-range",
    ),
]


@pytest.mark.parametrize("params,keyword", REFUSED_WINDOWS)
def test_a_window_that_cannot_be_honoured_is_refused(
    client: TestClient, params: dict, keyword: str
) -> None:
    """Every unusable window is a 400 that says which rule it broke (M16.7)."""
    response = client.get(TRAFFIC_URL, params=params)
    body = response.json()

    assert response.status_code == 400
    assert body["success"] is False
    assert body["errors"][0]["field"] == "window"
    assert body["errors"][0]["code"] == ErrorCode.INVALID_FILTER
    assert keyword in body["message"].lower()


@pytest.mark.parametrize(
    "url", [TRAFFIC_URL, PROTOCOLS_URL, DEVICES_URL, CONNECTIONS_URL, THREATS_URL]
)
def test_every_route_refuses_the_same_windows(client: TestClient, url: str) -> None:
    """The window rules are the analytics layer's, not one route's (M16.7)."""
    inverted = {"since": iso(WINDOW_UNTIL), "until": iso(WINDOW_SINCE)}
    unknown_bucket = window_params(bucket_seconds=45)

    assert client.get(url, params=inverted).status_code == 400
    assert client.get(url, params=unknown_bucket).status_code == 400


def test_a_refusal_never_names_an_internal(
    client: TestClient,
) -> None:
    """A rejected window explains itself without leaking the implementation."""
    body = client.get(TRAFFIC_URL, params=window_params(bucket_seconds=45)).json()

    message = body["message"]
    assert message
    for internal in ("Traceback", "File \"", "sqlalchemy", "app.", "site-packages"):
        assert internal not in message


def test_since_is_inclusive_and_until_is_exclusive(
    client: TestClient, db_session: Session
) -> None:
    """A packet exactly on ``until`` belongs to the next window (M13.26/M16.7).

    Three packets are stored one second apart across the closing bound: one on
    ``since``, one just before ``until``, and one exactly on ``until``. The first
    two are in the window and the third is not, which is what pins the half-open
    convention rather than merely asserting it.
    """
    seed_packet(db_session, offset=0.0, length=100)
    seed_packet(db_session, offset=599.0, length=100)
    seed_packet(db_session, offset=600.0, length=100)

    data = client.get(TRAFFIC_URL, params=window_params()).json()["data"]

    assert data["stored"]["available"] is True
    assert data["stored"]["data"]["total_packets"] == 2
    assert data["stored"]["data"]["total_bytes"] == 200
    # The third row is still in the table, and the M13 count says so.
    assert data["stored_packet_count"] == 3


# ---------------------------------------------------------------------------
# the persisted blocks each route now serves (M16.2–M16.6)
# ---------------------------------------------------------------------------

#: The block each route serves as an availability section, by window key.
SECTION_BY_URL = {
    TRAFFIC_URL: "stored",
    PROTOCOLS_URL: "stored",
    DEVICES_URL: "windowed",
    CONNECTIONS_URL: "stored",
    THREATS_URL: "stored",
}

#: The subset of those blocks read from SQLite, and so able to fail alone (M16.8).
#: ``devices`` is deliberately absent: its windowed block re-filters the M8
#: registry's in-process views and touches no table, so there is nothing for it
#: to fail on — a difference asserted below rather than assumed away.
STORED_SECTION_BY_URL = {
    TRAFFIC_URL: "stored",
    PROTOCOLS_URL: "stored",
    CONNECTIONS_URL: "stored",
    THREATS_URL: "stored",
}


@pytest.mark.parametrize("url,section_name", sorted(SECTION_BY_URL.items()))
def test_every_route_serves_an_available_section(
    client: TestClient, url: str, section_name: str
) -> None:
    """A readable store answers with ``available`` and no error (M16.8)."""
    section = section_of(client.get(url).json()["data"], section_name)

    assert section["available"] is True
    assert section["error"] is None
    assert isinstance(section["data"], dict)


def test_traffic_stored_block_is_the_window_and_not_the_live_view(
    client: TestClient, db_session: Session, statistics: TrafficStatisticsManager
) -> None:
    """The stored totals describe the packet table over the period (M16.2).

    Three packets are persisted and one is recorded live, so neither half can be
    the other: the stored block counts the two inside the window, the M13 count
    reports all three rows, and the live total reports the one observation.
    """
    seed_packet(db_session, offset=10.0, length=100)
    seed_packet(db_session, offset=20.0, length=300)
    seed_packet(db_session, offset=10_000.0, length=100)
    statistics.record_packet(make_normalized_packet(length=100))

    data = client.get(TRAFFIC_URL, params=window_params()).json()["data"]
    stored = data["stored"]["data"]

    assert data["total_packets"] == 1
    assert data["stored_packet_count"] == 3
    assert stored["total_packets"] == 2
    assert stored["total_bytes"] == 400
    assert stored["packets_per_second"] == 2 / 600.0
    assert stored["bytes_per_second"] == 400 / 600.0
    assert stored["average_packet_bytes"] == 200.0
    assert set(stored) == {
        "total_packets",
        "total_bytes",
        "packets_per_second",
        "bytes_per_second",
        "average_packet_bytes",
        "first_timestamp",
        "last_timestamp",
        "distinct_protocols",
        "packets_without_source_port",
        "packets_without_destination_port",
        "stored_packet_count",
        "series",
        "top_sources",
        "top_destinations",
        "top_ports",
        "protocols",
    }


def test_traffic_stored_series_covers_the_whole_window(
    client: TestClient, db_session: Session
) -> None:
    """One row on a bucket boundary leaves the other buckets zero, not absent."""
    seed_packet(db_session, offset=0.0, length=100)

    data = client.get(TRAFFIC_URL, params=window_params(bucket_seconds=60)).json()[
        "data"
    ]
    series = data["stored"]["data"]["series"]

    assert len(series) == data["period"]["buckets"] == 11
    assert sum(point["packets"] for point in series) == 1
    assert [point["packets"] for point in series].count(0) == 10


def test_traffic_stored_block_reports_absent_instants_as_null(
    client: TestClient,
) -> None:
    """An empty window has no first or last packet, and says ``null`` (M16.8)."""
    stored = client.get(TRAFFIC_URL, params=window_params()).json()["data"]["stored"][
        "data"
    ]

    assert stored["total_packets"] == 0
    assert stored["average_packet_bytes"] is None
    assert stored["first_timestamp"] is None
    assert stored["last_timestamp"] is None


def test_protocols_stored_shares_are_taken_against_the_window(
    client: TestClient, db_session: Session
) -> None:
    """Percentages describe the window's population, so they sum to 100 (M16.3)."""
    for _ in range(3):
        seed_packet(db_session, offset=0.0, packet_type=PacketType.UDP)
    seed_packet(db_session, offset=0.0, packet_type=PacketType.TCP)

    data = client.get(PROTOCOLS_URL, params=window_params()).json()["data"]
    stored = data["stored"]["data"]

    assert stored["total_packets"] == 4
    assert stored["count"] == 2
    assert stored["truncated"] is False
    assert set(stored) == {
        "count",
        "distinct_protocols",
        "truncated",
        "total_packets",
        "total_bytes",
        "rank_by",
        "protocols",
    }

    shares = {entry["protocol"]: entry["percentage"] for entry in stored["protocols"]}
    assert shares["UDP"] == 75.0
    assert shares["TCP"] == 25.0
    assert round(sum(shares.values()), 6) == 100.0


def test_protocols_stored_block_reports_no_share_for_an_empty_window(
    client: TestClient,
) -> None:
    """With nothing stored there are no shares — and none of them is a zero row."""
    stored = client.get(PROTOCOLS_URL, params=window_params()).json()["data"]["stored"][
        "data"
    ]

    assert stored["count"] == 0
    assert stored["total_packets"] == 0
    assert stored["protocols"] == []


def test_devices_windowed_block_is_the_registry_restricted_to_the_period(
    client: TestClient, devices: DeviceDiscoveryManager
) -> None:
    """A device M8 last saw inside the period is listed; one it did not is not."""
    seed_device(devices)
    later = {
        "since": iso(WINDOW_UNTIL + 3600.0),
        "until": iso(WINDOW_UNTIL + 7200.0),
    }

    inside = client.get(DEVICES_URL, params=window_params()).json()["data"]
    outside = client.get(DEVICES_URL, params=later).json()["data"]

    assert inside["total"] == 1
    assert inside["windowed"]["data"]["total"] == 1
    assert inside["windowed"]["data"]["top"][0]["device_id"] == f"mac:{MAC_A}"
    assert set(inside["windowed"]["data"]) == {"total", "by_status", "rank_by", "top"}

    # The registry still holds it, but M8 did not observe it in that period.
    assert outside["total"] == 1
    assert outside["windowed"]["data"]["total"] == 0


def test_connections_stored_block_is_the_beginning_of_the_period(
    client: TestClient, db_session: Session
) -> None:
    """Stored conversations are selected on ``start_time``, M9's own rule (M16.5)."""
    seed_connection(db_session, offset=0.0, protocol="TCP", status="active")
    seed_connection(
        db_session,
        offset=10.0,
        protocol="UDP",
        status="completed",
        end_time=utc(PACKET_BASE_TIME + 40.0),
    )

    stored = client.get(CONNECTIONS_URL, params=window_params()).json()["data"][
        "stored"
    ]["data"]

    assert stored["total"] == 2
    assert stored["active"] == 1
    assert stored["by_protocol"] == {"TCP": 1, "UDP": 1}
    assert set(stored["by_status"]) == {"active", "completed", "timeout"}
    assert stored["by_status"]["completed"] == 1
    # Only the conversation that ended has a lifetime to describe.
    assert stored["duration"]["samples"] == 1
    assert stored["duration"]["mean_seconds"] == 30.0
    assert set(stored) == {
        "total",
        "active",
        "first_timestamp",
        "last_timestamp",
        "by_protocol",
        "by_status",
        "duration",
        "series",
        "top_sources",
        "top_destinations",
    }


def test_connections_stored_duration_is_null_when_nothing_ended(
    client: TestClient, db_session: Session
) -> None:
    """A conversation still running has no lifetime, so it is excluded (M16.5)."""
    seed_connection(db_session, offset=0.0)

    duration = client.get(CONNECTIONS_URL, params=window_params()).json()["data"][
        "stored"
    ]["data"]["duration"]

    assert duration["samples"] == 0
    assert duration["min_seconds"] is None
    assert duration["mean_seconds"] is None
    assert duration["max_seconds"] is None


def test_threats_stored_block_keeps_the_three_notions_apart(
    client: TestClient, db_session: Session
) -> None:
    """Severity, belief and risk stay three fields over the window too (M16.6)."""
    seed_alert(
        db_session,
        offset=0.0,
        severity="critical",
        confidence=90,
        status="open",
        risk_score=80,
    )
    seed_alert(
        db_session, offset=10.0, severity="low", confidence=20, status="resolved"
    )

    stored = client.get(THREATS_URL, params=window_params()).json()["data"]["stored"][
        "data"
    ]

    assert stored["total"] == 2
    assert stored["by_severity"]["critical"] == 1
    assert stored["by_status"]["open"] == 1
    assert sum(stored["by_confidence_range"].values()) == 2
    # The second alert was never correlated, so its stored score is still zero.
    assert stored["by_risk_band"]["minimal"] == 1
    assert stored["by_risk_band"]["high"] == 1
    assert set(stored) == {
        "total",
        "without_rule_key",
        "first_timestamp",
        "last_timestamp",
        "by_severity",
        "by_status",
        "by_risk_band",
        "by_confidence_range",
        "rules",
        "series",
    }


def test_threats_stored_block_ranks_the_detectors_that_raised(
    client: TestClient, db_session: Session
) -> None:
    """The stored rule ranking reads M11's correlation key, not M10's counters."""
    seed_alert(db_session, offset=0.0, correlation_key="port_scan|a|b")
    seed_alert(db_session, offset=1.0, correlation_key="port_scan|a|c")
    seed_alert(db_session, offset=2.0, correlation_key="syn_flood|a|b")

    stored = client.get(THREATS_URL, params=window_params()).json()["data"]["stored"][
        "data"
    ]
    counts = {entry["rule_key"]: entry["alerts"] for entry in stored["rules"]}

    assert counts == {"port_scan": 2, "syn_flood": 1}


def test_threats_stored_block_bounds_its_series(
    client: TestClient, db_session: Session
) -> None:
    """The alert series is zero-filled over the window's own buckets (M16.6)."""
    seed_alert(db_session, offset=30.0)

    data = client.get(THREATS_URL, params=window_params(bucket_seconds=60)).json()[
        "data"
    ]
    series = data["stored"]["data"]["series"]

    assert len(series) == data["period"]["buckets"] == 11
    assert sum(point["alerts"] for point in series) == 1


def test_threats_findings_summary_matches_the_engine(
    client: TestClient, detections: DetectionEngine
) -> None:
    """The windowed findings are the M10 engine's retained observations (M16.6)."""
    detections.evaluate(make_context())

    findings = client.get(THREATS_URL, params=window_params()).json()["data"][
        "findings"
    ]
    diagnostics = detections.get_diagnostics()

    assert findings["retained"] == diagnostics.retained_findings == 1
    assert findings["in_window"] == 1
    assert findings["mean_confidence"] is not None
    assert [entry["rule_id"] for entry in findings["by_rule"]] == ["fixed"]


def test_threats_incident_links_report_the_references_m12_holds(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """The link block counts distinct alerts across incidents, not links (M16.6)."""
    correlations.correlate_alerts([make_alert(), make_alert(alert_id=2)])

    links = client.get(THREATS_URL, params=window_params()).json()["data"][
        "incident_links"
    ]

    assert links["incidents_total"] == correlations.count_incidents()
    assert links["incidents_with_alerts"] == links["incidents_total"]
    assert links["alerts_in_incidents"] == 2


def test_threats_scoring_survives_the_window(
    client: TestClient, db_session: Session, correlations: CorrelationEngine
) -> None:
    """No endpoint computes a band of its own; both read M12's table (M16.6).

    The comparison is against the engine rather than against a literal, because
    M12 scores an incident itself: the ``risk_score`` handed to ``make_alert`` is
    the *alert's* value, and the engine's own is the one the API must report.
    """
    correlations.correlate_alerts([make_alert(risk_score=90), make_alert(alert_id=2)])
    seed_alert(db_session, offset=0.0, risk_score=95)

    data = client.get(THREATS_URL, params=window_params()).json()["data"]
    engine_scores = [
        incident.risk_score for incident in correlations.registry.incidents()
    ]

    assert data["highest_risk_score"] == max(engine_scores)
    assert sum(data["incidents_by_risk_band"].values()) == data["incidents_total"]
    # The stored band is the seeded alert's own score, banded by M12's table.
    assert data["stored"]["data"]["by_risk_band"]["high"] == 1


# ---------------------------------------------------------------------------
# the ranking ceiling the M16 routes publish (M16.2)
# ---------------------------------------------------------------------------


def test_the_ranking_ceiling_is_the_analytics_layers_own(
    client: TestClient,
) -> None:
    """The largest accepted ``limit`` is the layer's group cap, not a second one."""
    assert client.get(TRAFFIC_URL, params={"limit": MAX_GROUPS}).status_code == 200
    assert (
        client.get(TRAFFIC_URL, params={"limit": MAX_GROUPS + 1}).status_code == 422
    )


# ---------------------------------------------------------------------------
# an unreadable store is reported, never guessed at (M16.8)
# ---------------------------------------------------------------------------


@pytest.fixture
def unreadable_client(
    statistics: TrafficStatisticsManager,
    devices: DeviceDiscoveryManager,
    tracker: ConnectionTracker,
    detections: DetectionEngine,
    correlations: CorrelationEngine,
    session_factory: Callable[[], Session],
) -> Generator[TestClient, None, None]:
    """A client whose request session cannot read the analytics tables (M16.8).

    The request-scoped session is pointed at an engine no fixture ever created
    the schema on, so every database-derived block fails the way an unreadable
    store does. The collaborators that open their own connections are pointed at
    the healthy store, which is what isolates the failure to the sections: the
    M13 fields a client already renders are plain integers and must stay
    answerable, and only the blocks M16 added are representable as unavailable.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        with api_client(
            {
                get_db: make_unreadable_db_override(engine),
                get_statistics_manager: lambda: statistics,
                get_device_manager: lambda: devices,
                get_connection_tracker: lambda: tracker,
                get_detection_engine: lambda: detections,
                get_correlation_engine: lambda: correlations,
                get_alert_queries: lambda: AlertQueries(
                    session_factory=session_factory
                ),
            }
        ) as test_client:
            yield test_client
    finally:
        engine.dispose()


@pytest.mark.parametrize("url,section_name", sorted(STORED_SECTION_BY_URL.items()))
def test_an_unreadable_store_is_reported_by_every_section(
    unreadable_client: TestClient, url: str, section_name: str
) -> None:
    """A block that could not be read says so; it is never reported as zero."""
    response = unreadable_client.get(url, params=window_params())
    section = section_of(response.json()["data"], section_name)

    assert response.status_code == 200
    assert section["available"] is False
    assert section["error"] == UNAVAILABLE_MESSAGE
    assert section["data"] is None


def test_a_section_with_no_table_to_read_is_never_unavailable(
    unreadable_client: TestClient,
) -> None:
    """``devices.windowed`` filters the M8 registry in memory, not a table.

    It is a section so that a future registry failure would be reportable, but
    today it reads no database and therefore cannot be made unavailable by one.
    Worth pinning down, since the four blocks beside it all can be.
    """
    section = section_of(
        unreadable_client.get(DEVICES_URL, params=window_params()).json()["data"],
        "windowed",
    )

    assert section["available"] is True
    assert section["error"] is None
    assert section["data"]["total"] == 0


def test_an_unreadable_store_leaves_the_live_half_intact(
    unreadable_client: TestClient, statistics: TrafficStatisticsManager
) -> None:
    """The M13 figures are still answered, so only the new block degrades."""
    statistics.record_packet(make_normalized_packet(length=100))

    data = unreadable_client.get(TRAFFIC_URL, params=window_params()).json()["data"]

    assert data["total_packets"] == 1
    assert data["stored_packet_count"] == 0
    assert data["stored"]["available"] is False


def test_an_unreadable_store_still_names_every_vocabulary(
    unreadable_client: TestClient,
) -> None:
    """A client renders fixed rows whether the store answered or not (M16.8)."""
    data = unreadable_client.get(THREATS_URL, params=window_params()).json()["data"]

    assert set(data["alerts_by_severity"]) == {
        "critical",
        "high",
        "medium",
        "low",
    }
    assert set(data["incidents_by_risk_band"]) == {
        band.value for band, _low, _high in BAND_RANGES
    }
    assert data["incident_links"]["incidents_total"] == 0


def test_an_unreadable_store_never_leaks_its_cause(unreadable_client: TestClient) -> None:
    """The response names no table, query, path or exception text (M13.30)."""
    body = unreadable_client.get(TRAFFIC_URL, params=window_params()).text

    for internal in (
        "no such table",
        "Traceback",
        "OperationalError",
        "sqlalchemy",
        "site-packages",
    ):
        assert internal not in body


def test_one_unreadable_block_does_not_take_the_next_one_with_it(
    unreadable_client: TestClient,
) -> None:
    """Each section is read on its own, so one fault is reported once (M16.8).

    Both sections are asked of the same broken session in one request, and both
    are reported. If the first failure had left the session unusable, the second
    block would be reported unavailable for a reason that is not its own — which
    is the outcome the rollback in ``read_section`` exists to prevent.
    """
    traffic = unreadable_client.get(TRAFFIC_URL, params=window_params()).json()[
        "data"
    ]
    protocols = unreadable_client.get(PROTOCOLS_URL, params=window_params()).json()[
        "data"
    ]

    assert traffic["stored"]["available"] is False
    assert protocols["stored"]["available"] is False
    # The live halves still resolved, which they could not if the session had
    # been left poisoned by the previous request's failure.
    assert protocols["count"] == 0
