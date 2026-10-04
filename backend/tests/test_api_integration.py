"""Integration test: capture → processing → data layers → alert → incident → API (M13.35).

This is the only test that drives the *whole* application and then reads the result
back over HTTP. Everything between the wire and the JSON is the production object:

    CaptureManager (real, over a fake sniffer)
          ↓
    PacketPipeline (real)
          ↓
    PacketProcessor → Statistics / Devices / Connections / Persistence
          ↓
    DetectionEngine (real M10 rules)
          ↓
    AlertEngine → alerts table (isolated SQLite)
          ↓
    CorrelationEngine (real M12 rules) → RiskScoringEngine
          ↓
    FastAPI /api/v1 (real routes)
          ↓
    HTTP response

Two things are substituted, and only two:

* the **sniffer**, because a test may not put a real NIC in promiscuous mode —
  ``FakeCaptureSniffer`` implements the same ``PacketSink`` contract, so the
  packets still travel the real capture → pipeline path;
* the **database**, because a test may not write to the developer's
  ``netwatch.db`` — ``session_factory`` points at a fresh in-memory engine, and
  the API reads that same engine through the ``get_db`` override.

The API assertions are made against *that* engine and *those* runtime registries:
each dependency is overridden with the very object the pipeline fed, so a response
can only be correct if the pipeline really wrote what the route is reading. That is
the property M13.35 asks for — "verify complete HTTP flows" — and it is why these
tests would fail if a router read a different store from the one capture fills,
which a unit test over a mocked service cannot show.

``docs/17_M13_REST_API_Design.md`` §9 records what each assertion is evidence of.
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from sqlalchemy.orm import Session

from app.alerts import get_alert_engine
from app.alerts.engine import AlertEngine
from app.alerts.queries import AlertQueries
from app.api.v1.deps import get_alert_queries
from app.connections.manager import ConnectionTracker, get_connection_tracker
from app.connections.persistence import ConnectionPersistence
from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.correlation.persistence import IncidentRiskWriter
from app.database.session import get_db
from app.detection import DetectionEngine, get_detection_engine
from app.detection.rules.internal_scan import InternalScanRule
from app.detection.rules.port_scan import PortScanRule
from app.devices.manager import DeviceDiscoveryManager, get_device_manager
from app.persistence.manager import PacketPersistence
from app.services.capture_manager import CaptureManager, get_capture_manager
from app.services.interface_manager import InterfaceManager, get_interface_manager
from app.services.packet_pipeline import PacketPipeline
from app.statistics.manager import TrafficStatisticsManager, get_statistics_manager
from tests.alert_fakes import ALERT_BASE_TIME, SOURCE_IP, make_service
from tests.correlation_fakes import FixedClock, make_engine
from tests.fakes import FakeCaptureSniffer, make_interface_manager, make_sniffer_factory
from tests.m13_fakes import api_client, make_db_override

#: Low thresholds, so a handful of packets exercises the real rules quickly.
PORT_SCAN_THRESHOLD = 5
INTERNAL_SCAN_THRESHOLD = 5

#: A public destination, so the internal-scan detector cannot claim it.
PUBLIC_DESTINATION = "8.8.8.8"

#: The interface the capture manager is told to use, and the one the fake sniffer
#: is created for. It comes from ``tests.fakes.SAMPLE_INTERFACES``.
CAPTURE_INTERFACE = "Wi-Fi"

#: The alert service's clock and the correlation engine's clock are pinned to the
#: same instant, so lifecycle stamping, retention and the recency term are all
#: deterministic and the two layers cannot disagree about "now".
ENGINE_NOW = ALERT_BASE_TIME + 60.0

#: The versioned base every route below is asserted against (M13.3).
API = "/api/v1"


@dataclass
class _Stack:
    """The live application, wired end to end over an isolated database.

    Holding the collaborators rather than re-deriving them is what lets each test
    hand the *same* object to the API that the pipeline fed, so a route and the
    pipeline cannot be looking at different state.
    """

    pipeline: PacketPipeline
    manager: CaptureManager
    interfaces: InterfaceManager
    sniffer_registry: list[FakeCaptureSniffer]
    statistics: TrafficStatisticsManager
    devices: DeviceDiscoveryManager
    connections: ConnectionTracker
    detection: DetectionEngine
    alerts: AlertEngine
    correlation: CorrelationEngine
    risk_writer: IncidentRiskWriter

    def drive(self, packets: Sequence[Any]) -> None:
        """Feed raw packets straight to the pipeline's capture seam.

        This is exactly what the sniffer's callback does, with the timestamp
        supplied explicitly so a test's times are deterministic.
        """
        for index, packet in enumerate(packets):
            self.pipeline.process(packet, ALERT_BASE_TIME + index)
        self.flush()

    def capture(self, packets: Sequence[Any]) -> None:
        """Feed packets through the real :class:`CaptureManager`, not the pipeline.

        Used where the test is specifically about the capture stage: the manager
        must be started, must create the sniffer through the injected factory, and
        must hand it the pipeline.

        The interface is chosen on the M4 :class:`InterfaceManager`, which is where
        selection lives — the capture manager reads the choice from it rather than
        holding one of its own, so this is the same two-step the ``PUT
        /capture/interface`` route plus ``POST /capture/start`` performs (M13.7).
        """
        self.interfaces.select_interface(CAPTURE_INTERFACE)
        self.manager.start()
        sniffer = self.sniffer_registry[-1]
        for packet in packets:
            sniffer.emit_packet(packet)
        self.manager.stop()
        self.flush()

    def flush(self) -> None:
        """Write whatever the pipeline is still buffering (M7.7/M9.17).

        Capture-stop does this in production; a test that drives the pipeline
        directly has to ask, or a route would read an empty table and the
        assertion would be about the test's own omission rather than the code.
        """
        self.pipeline.flush_persistence()
        self.pipeline.flush_connections()


def _port_scan_packets(count: int, *, source_ip: str = SOURCE_IP) -> list[Any]:
    """Return ``count`` raw SYNs from one source across distinct ports (M10.8)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=source_ip, dst=PUBLIC_DESTINATION)
        / TCP(sport=52000, dport=4000 + index, flags="S")
        for index in range(count)
    ]


def _internal_sweep_packets(count: int, *, source_ip: str = SOURCE_IP) -> list[Any]:
    """Return ``count`` raw UDP attempts to distinct private hosts (M10.9)."""
    return [
        Ether(src="AA:BB:CC:DD:EE:FF", dst="22:33:44:55:66:77")
        / IP(src=source_ip, dst=f"192.168.1.{20 + index}")
        / UDP(sport=53000, dport=53)
        for index in range(count)
    ]


def _build_stack(session_factory: Callable[[], Session]) -> _Stack:
    """Wire the production pipeline over an isolated database.

    Every layer is the real one. The only non-production objects are the sniffer
    (created per test by the factory) and the session factory itself.
    """
    detection = DetectionEngine(
        [
            PortScanRule(
                unique_port_threshold=PORT_SCAN_THRESHOLD, window_seconds=60.0
            ),
            InternalScanRule(
                unique_destination_threshold=INTERNAL_SCAN_THRESHOLD,
                window_seconds=60.0,
            ),
        ]
    )
    alerts = AlertEngine(make_service(session_factory, clock=lambda: ENGINE_NOW))
    devices = DeviceDiscoveryManager()
    connections = ConnectionTracker(
        device_registry=devices.registry,
        persistence=ConnectionPersistence(session_factory=session_factory),
        autostart_cleanup=False,
    )
    persistence = PacketPersistence(session_factory=session_factory, autostart=False)
    risk_writer = IncidentRiskWriter(session_factory)
    correlation = make_engine(
        risk_persistence=risk_writer, clock=FixedClock(ENGINE_NOW)
    )
    pipeline = PacketPipeline(
        persistence=persistence,
        devices=devices,
        connections=connections,
        detection=detection,
        alerts=alerts,
        correlation=correlation,
    )
    registry: list[FakeCaptureSniffer] = []
    interfaces = make_interface_manager()
    manager = CaptureManager(
        interface_manager=interfaces,
        sniffer_factory=make_sniffer_factory(registry=registry),
        pipeline=pipeline,
    )
    return _Stack(
        pipeline=pipeline,
        manager=manager,
        interfaces=interfaces,
        sniffer_registry=registry,
        statistics=pipeline.statistics,
        devices=devices,
        connections=connections,
        detection=detection,
        alerts=alerts,
        correlation=correlation,
        risk_writer=risk_writer,
    )


@pytest.fixture
def stack(session_factory: Callable[[], Session]) -> _Stack:
    """A fully wired application over a fresh in-memory database."""
    return _build_stack(session_factory)


@contextmanager
def _api(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> Generator[TestClient, None, None]:
    """Yield a client whose every collaborator is the stack's own (M13.28).

    Each override is keyed by the *dependency function* the route declares, so the
    route still resolves its collaborator through FastAPI and the wiring is the
    application's rather than the test's.
    """
    overrides = {
        get_db: make_db_override(db_engine),
        get_statistics_manager: lambda: stack.statistics,
        get_device_manager: lambda: stack.devices,
        get_connection_tracker: lambda: stack.connections,
        get_detection_engine: lambda: stack.detection,
        get_correlation_engine: lambda: stack.correlation,
        get_capture_manager: lambda: stack.manager,
        get_interface_manager: lambda: stack.interfaces,
        # The lifecycle *write* path needs the engine the pipeline wrote through,
        # not the process-wide one. Without this override the routes would reach
        # the developer's real database and answer 404 for an alert the pipeline
        # plainly stored (M13.28).
        get_alert_engine: lambda: stack.alerts,
        # The alert read service needs a *factory*, not a session, so it is built
        # against the same isolated engine (M13.28).
        get_alert_queries: lambda: AlertQueries(session_factory=session_factory),
    }
    with api_client(overrides) as client:
        yield client


def _get_data(client: TestClient, url: str, **params: Any) -> dict:
    """GET a route, assert the envelope, and return its ``data`` block (M13.4)."""
    response = client.get(url, params=params or None)
    assert response.status_code == 200, f"{url} -> {response.status_code}"
    body = response.json()
    assert body["success"] is True
    return body["data"]
# ---------------------------------------------------------------------------
# The whole chain: capture → every consumer → every route (M13.35)
# ---------------------------------------------------------------------------


def test_capture_feeds_every_layer_and_the_api_serves_the_result(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """A capture session drives the whole chain, and HTTP reports it (M13.35).

    This is the end-to-end flow the milestone names, started at its real
    beginning: the :class:`CaptureManager` is started, creates a sniffer through
    the injected factory, and the packets are emitted through that sniffer's sink
    callback. Every layer downstream is then read back over HTTP, so a failure
    anywhere between the wire and the JSON shows up here.
    """
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.capture(packets)

    # Capture itself: the session is real, so it counted and stopped cleanly.
    assert stack.pipeline.get_processed_count() == len(packets)
    assert stack.pipeline.get_statistics_error_count() == 0
    assert stack.pipeline.get_persistence_error_count() == 0
    assert stack.pipeline.get_connection_error_count() == 0
    assert stack.pipeline.get_detection_error_count() == 0
    assert stack.pipeline.get_alert_error_count() == 0
    assert stack.pipeline.get_correlation_error_count() == 0

    with _api(stack, session_factory, db_engine) as client:
        # Traffic: the snapshot the M6 manager accumulated.
        traffic = _get_data(client, f"{API}/statistics/traffic")
        assert traffic["total_packets"] == len(packets)

        # Devices: the two endpoints of the traffic were attributed.
        devices = _get_data(client, f"{API}/devices")
        observed = {
            address
            for device in devices["devices"]
            for address in device["ip_addresses"]
        }
        assert SOURCE_IP in observed

        # Connections: the SYNs became conversations.
        connections = _get_data(client, f"{API}/connections")
        assert any(
            row["source_ip"] == SOURCE_IP and row["protocol"] == "TCP"
            for row in connections["connections"]
        )

        # Packets: persisted, and pageable.
        stored = _get_data(client, f"{API}/packets")
        assert stored["count"] == len(packets)
        assert stored["total"] == len(packets)

        # Detection: the engine retained the finding its rule observed.
        findings = _get_data(client, f"{API}/detections")
        assert [row["rule_id"] for row in findings["findings"]] == ["port_scan"]

        # Alerting: the finding became a stored alert.
        alerts = _get_data(client, f"{API}/alerts")
        assert alerts["total"] == 1
        assert alerts["alerts"][0]["title"] == "Port Scan"

        # Correlation: the alert became a scored incident.
        incidents = _get_data(client, f"{API}/incidents")
        assert incidents["total"] == 1
        assert incidents["incidents"][0]["risk_score"] > 0


def test_the_dashboard_summary_aggregates_every_section(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """One dashboard request reports the whole chain from the same objects (M13.19).

    Every section is read from its own service, so this is also the check that the
    aggregate agrees with the individual routes it summarises.
    """
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.capture(packets)

    with _api(stack, session_factory, db_engine) as client:
        summary = _get_data(client, f"{API}/dashboard/summary")

    # No section failed: the aggregate is complete rather than partly unavailable.
    assert summary["unavailable_sections"] == []
    assert summary["generated_at"].endswith("+00:00")

    assert summary["capture"]["available"] is True
    assert summary["capture"]["data"]["packet_count"] == len(packets)
    assert summary["traffic"]["data"]["total_packets"] == len(packets)
    # Devices, alerts and incidents come straight from their own stores.
    assert summary["devices"]["data"]["total"] >= 1
    assert summary["alerts"]["data"]["total"] == 1
    assert summary["alerts"]["data"]["open"] == 1
    assert summary["incidents"]["data"]["total"] == 1
    assert summary["incidents"]["data"]["highest_risk_score"] > 0
    # Detection reports the retained finding and can show it directly.
    assert summary["detections"]["data"]["retained"] >= 1
    assert (
        summary["detections"]["data"]["recent"][0]["rule_id"] == "port_scan"
    )


# ---------------------------------------------------------------------------
# Each data route against the data its own layer produced
# ---------------------------------------------------------------------------


def test_the_statistics_api_reports_the_captured_traffic(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """The M6 aggregates reached over HTTP are the ones capture produced (M13.9)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        protocols = _get_data(client, f"{API}/statistics/protocols")
        talkers = _get_data(client, f"{API}/statistics/top-talkers")
        traffic = _get_data(client, f"{API}/statistics/traffic")

    # Every packet was TCP, so TCP holds all of them and nothing else appears.
    assert [row["protocol"] for row in protocols] == ["TCP"]
    assert protocols[0]["packets"] == len(packets)
    assert protocols[0]["percentage"] == pytest.approx(100.0)
    assert traffic["total_packets"] == len(packets)
    # The ranking endpoints report the source the traffic came from.
    assert talkers["sources"][0]["key"] == SOURCE_IP
    assert talkers["sources"][0]["packets"] == len(packets)


def test_the_device_api_reports_both_endpoints_of_the_traffic(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """M8 tracked the endpoints, and the API projects them unchanged (M13.10)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        data = _get_data(client, f"{API}/devices")
        filtered = _get_data(client, f"{API}/devices", ip=SOURCE_IP)

    source_devices = [
        device
        for device in data["devices"]
        if SOURCE_IP in device["ip_addresses"]
    ]
    assert len(source_devices) == 1
    device = source_devices[0]
    # The counts are M8's own, and they add up: sent + received == total.
    assert device["packet_count"] == len(packets)
    assert device["packets_sent"] == len(packets)
    assert device["packet_count"] == (
        device["packets_sent"] + device["packets_received"]
    )
    # The single-device filter returns the same device, not a different one.
    assert [row["device_id"] for row in filtered["devices"]] == [
        device["device_id"]
    ]


def test_the_connection_api_reports_the_conversations(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """M9 grouped the SYNs into conversations the API can list (M13.11)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        data = _get_data(client, f"{API}/connections")
        by_protocol = _get_data(client, f"{API}/connections", protocol="TCP")

    # Each SYN went to a distinct port, so each is its own conversation.
    assert data["count"] == len(packets)
    assert by_protocol["count"] == len(packets)
    connection = data["connections"][0]
    assert connection["protocol"] == "TCP"
    assert connection["source_ip"] == SOURCE_IP
    assert connection["packet_count"] == 1
    assert connection["active"] is True


def test_the_packet_api_serves_the_stored_packets_and_filters_them(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """M7 persisted the packets, and the API reads them back with filters (M13.8)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        data = _get_data(client, f"{API}/packets")
        filtered = _get_data(client, f"{API}/packets", protocol="TCP")
        unmatched = _get_data(client, f"{API}/packets", protocol="UDP")
        first = data["packets"][0]
        one = _get_data(client, f"{API}/packets/{first['id']}")

    assert data["count"] == len(packets)
    assert data["total"] == len(packets)
    # The page window the endpoint was given is echoed back (M13.24).
    assert data["limit"] == 100
    assert data["offset"] == 0
    assert data["has_more"] is False
    assert filtered["total"] == len(packets)
    assert unmatched["total"] == 0
    # A packet carries no payload: M7 never stored one (M7.5/M13.8).
    assert "payload" not in first
    assert one["id"] == first["id"]


def test_the_packet_api_pages_without_repeating_a_row(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """Paging is stable: two pages of one query are disjoint (M13.24)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        page_one = _get_data(client, f"{API}/packets", limit=3, offset=0)
        page_two = _get_data(client, f"{API}/packets", limit=3, offset=3)

    first_ids = {row["id"] for row in page_one["packets"]}
    second_ids = {row["id"] for row in page_two["packets"]}
    assert len(first_ids) == 3
    assert len(second_ids) == 3
    assert first_ids.isdisjoint(second_ids)
    # A full page reports that more may follow; the offsets are echoed.
    assert page_one["has_more"] is True
    assert page_one["offset"] == 0
    assert page_two["offset"] == 3


# ---------------------------------------------------------------------------
# Detection → alert → evidence (M13.12/M13.13/M13.14)
# ---------------------------------------------------------------------------


def test_the_detection_api_reports_the_finding_the_engine_observed(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """The M10 finding a route returns is the one the real rule produced (M13.12)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        data = _get_data(client, f"{API}/detections")
        filtered = _get_data(client, f"{API}/detections", rule_id="port_scan")
        unmatched = _get_data(client, f"{API}/detections", rule_id="syn_flood")
        rules = _get_data(client, f"{API}/detections/rules")
        finding = _get_data(
            client, f"{API}/detections/{data['findings'][0]['finding_id']}"
        )

    assert data["total"] == 1
    assert filtered["total"] == 1
    assert unmatched["total"] == 0
    # A finding is an observation: no severity and no risk anywhere on it.
    row = data["findings"][0]
    assert row["rule_id"] == "port_scan"
    assert row["source_ip"] == SOURCE_IP
    assert "severity" not in row
    assert "risk_score" not in row
    # The detail route returns the very finding the listing named.
    assert finding["finding_id"] == row["finding_id"]
    # Both registered detectors are listed, whether or not they fired.
    assert {entry["rule_id"] for entry in rules["rules"]} == {
        "port_scan",
        "internal_scan",
    }


def test_the_alert_api_reports_the_stored_alert_with_its_evidence(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """M11 stored the alert and its evidence, and both are readable (M13.13/M13.14)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        data = _get_data(client, f"{API}/alerts")
        alert = data["alerts"][0]
        evidence = _get_data(client, f"{API}/alerts/{alert['alert_id']}/evidence")

    assert data["total"] == 1
    assert alert["rule_id"] == "port_scan"
    assert alert["title"] == "Port Scan"
    assert alert["severity"] == "high"
    assert alert["status"] == "open"
    assert alert["source_ip"] == SOURCE_IP
    # Confidence is a 0..1 float on the wire, never the stored percentage (M11.5).
    assert 0.0 < alert["confidence"] <= 1.0
    # The two always-present evidence records, per M11.11.
    assert evidence["alert_id"] == alert["alert_id"]
    assert sorted(row["evidence_type"] for row in evidence["evidence"]) == [
        "behavioral",
        "rule",
    ]
    assert alert["evidence_count"] == evidence["count"]


def test_a_finding_with_no_alert_leaves_the_alert_api_empty(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """Traffic below every threshold produces no alert, and the API says so (M11.8).

    The negative case matters as much as the positive one: an endpoint that
    invented an alert from a quiet capture would pass every test above.
    """
    stack.drive(_port_scan_packets(PORT_SCAN_THRESHOLD - 1))

    with _api(stack, session_factory, db_engine) as client:
        alerts = _get_data(client, f"{API}/alerts")
        incidents = _get_data(client, f"{API}/incidents")
        detections = _get_data(client, f"{API}/detections")

    assert alerts["total"] == 0
    assert alerts["alerts"] == []
    assert incidents["total"] == 0
    assert detections["total"] == 0


# ---------------------------------------------------------------------------
# Correlation → incident (M13.15/M13.16)
# ---------------------------------------------------------------------------


def test_the_incident_api_exposes_the_scored_incident_and_its_membership(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """The M12 incident is served with its score, reasons and members (M13.15).

    The score is read from the incident rather than recomputed, so the listing and
    the detail view must agree on it exactly.
    """
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        listing = _get_data(client, f"{API}/incidents")
        summary = listing["incidents"][0]
        detail = _get_data(client, f"{API}/incidents/{summary['incident_id']}")
        open_only = _get_data(client, f"{API}/incidents/open")
        alerts = _get_data(client, f"{API}/alerts")

    assert listing["total"] == 1
    assert summary["title"] == "Port Scan"
    assert summary["status"] == "open"
    assert summary["risk_score"] > 0
    assert summary["risk_band"] != "minimal"

    # The detail view carries the members and the risk, consistently.
    assert detail["incident_id"] == summary["incident_id"]
    assert detail["risk_score"] == summary["risk_score"]
    assert detail["risk_band"] == summary["risk_band"]
    assert detail["alert_ids"] == [alerts["alerts"][0]["alert_id"]]
    assert detail["finding_ids"]  # the M10 observation behind the alert
    assert "port_scan" in detail["rule_ids"]
    # Three confidences stay distinct: a lone alert correlates with nothing, so
    # the correlation confidence is zero while the alert's own is not (M12.16).
    assert detail["correlation_confidence"] == 0.0
    assert detail["alert_confidence"] > 0.0
    # Timestamps are epoch seconds *and* ISO-8601 UTC with an offset (M13.26).
    assert detail["start_time_iso"].endswith("+00:00")
    assert detail["last_seen_iso"].endswith("+00:00")
    # The open listing is the same incident, since it is still open.
    assert [row["incident_id"] for row in open_only["incidents"]] == [
        summary["incident_id"]
    ]


def test_two_related_alerts_arrive_as_one_incident_over_http(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """Correlation groups two alerts, and the API reports both members (M13.15).

    A port scan followed by an internal sweep from one source matches the
    ``scan_sequence`` rule, so the two alerts are one incident — and both alerts
    remain individually readable, which is the property M12.10 requires.
    """
    stack.drive(_port_scan_packets(PORT_SCAN_THRESHOLD + 2))
    stack.drive(_internal_sweep_packets(INTERNAL_SCAN_THRESHOLD + 2))

    with _api(stack, session_factory, db_engine) as client:
        alerts = _get_data(client, f"{API}/alerts")
        incidents = _get_data(client, f"{API}/incidents")
        detail = _get_data(
            client, f"{API}/incidents/{incidents['incidents'][0]['incident_id']}"
        )

    # Two detectors, two alerts...
    assert alerts["total"] == 2
    assert {row["title"] for row in alerts["alerts"]} == {
        "Port Scan",
        "Internal Scan",
    }
    # ...grouped into one incident, with both alerts as members.
    assert incidents["total"] == 1
    assert sorted(detail["alert_ids"]) == sorted(
        row["alert_id"] for row in alerts["alerts"]
    )
    assert {"port_scan", "internal_scan"} <= set(detail["rule_ids"])
    # The reason trail names the rule that grouped them and the shared value.
    assert any(
        reason.startswith("matched:") for reason in detail["correlation_reasons"]
    )
    assert any(
        "same_source" in reason for reason in detail["correlation_reasons"]
    )


def test_the_incident_score_equals_the_score_written_onto_the_alerts(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """M12's score reaches the alert rows and the incident agrees with them.

    The alerts API has no risk field of its own — risk is M12's (M11.18) — so the
    agreement is checked against the stored rows the risk writer stamped.
    """
    stack.drive(_port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    with _api(stack, session_factory, db_engine) as client:
        incidents = _get_data(client, f"{API}/incidents")

    incident = incidents["incidents"][0]
    assert stack.risk_writer.stats()["rows_written"] >= 1

    session = session_factory()
    try:
        from app.models.alert import Alert as AlertRow

        rows = session.query(AlertRow).all()
        assert len(rows) == 1
        # M11 stores 0 because only M12 can produce a meaningful score; after the
        # pipeline has run the row carries the incident's own number (M12.24).
        assert rows[0].risk_score == incident["risk_score"]
        assert rows[0].risk_score > 0
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Lifecycle changes through the API (M13.13/M13.16)
# ---------------------------------------------------------------------------


def test_acknowledging_an_alert_through_the_api_persists(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """A lifecycle move made over HTTP is the one the store records (M13.13).

    The route must reach the same M11 service the pipeline wrote through, so the
    change is visible on the next read rather than held in the router.
    """
    stack.drive(_port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    with _api(stack, session_factory, db_engine) as client:
        before = _get_data(client, f"{API}/alerts")["alerts"][0]
        response = client.post(
            f"{API}/alerts/{before['alert_id']}/acknowledge"
        )
        after = _get_data(client, f"{API}/alerts")["alerts"][0]

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert before["status"] == "open"
    assert after["status"] == "acknowledged"


def test_an_incident_moved_to_investigating_is_listed_as_such(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """An incident transition over HTTP persists and is reflected in reads (M13.16)."""
    stack.drive(_port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    with _api(stack, session_factory, db_engine) as client:
        incident_id = _get_data(client, f"{API}/incidents")["incidents"][0][
            "incident_id"
        ]
        response = client.post(f"{API}/incidents/{incident_id}/investigate")
        listing = _get_data(client, f"{API}/incidents")
        open_only = _get_data(client, f"{API}/incidents/open")

    assert response.status_code == 200
    assert listing["incidents"][0]["status"] == "investigating"
    # "Investigating" is still an active state, so it stays in the open view.
    assert [row["incident_id"] for row in open_only["incidents"]] == [incident_id]


def test_an_incident_that_cannot_move_is_a_controlled_conflict(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """An impossible transition is a 409 in the standard envelope (M13.16/M13.6).

    ``resolved`` is terminal, so moving it *back* to ``investigating`` must be
    refused by the M12 transition table rather than by a second copy of the rule
    inside the route.

    The move is chosen deliberately. Re-resolving would not be refused: M12
    treats a move to the state an incident is already in as an explicit no-op
    (M12.9), because re-marking a conclusion changes nothing. So the test has to
    make a move the table genuinely forbids, or it would be asserting a rule the
    milestone does not hold.
    """
    stack.drive(_port_scan_packets(PORT_SCAN_THRESHOLD + 2))

    with _api(stack, session_factory, db_engine) as client:
        incident_id = _get_data(client, f"{API}/incidents")["incidents"][0][
            "incident_id"
        ]
        resolved = client.post(f"{API}/incidents/{incident_id}/resolve")
        reopened = client.post(f"{API}/incidents/{incident_id}/investigate")
        listing = _get_data(client, f"{API}/incidents")

    assert resolved.status_code == 200
    assert reopened.status_code == 409
    body = reopened.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "INVALID_TRANSITION"
    # The refused move changed nothing: the incident is still exactly where the
    # successful move left it, which is what "the route has no rule of its own"
    # means in practice.
    assert listing["incidents"][0]["status"] == "resolved"


# ---------------------------------------------------------------------------
# Analytics and system, over the same live state (M13.18/M13.22)
# ---------------------------------------------------------------------------


def test_analytics_reports_the_live_chain(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """The analytics routes expose what the services hold, not a recomputation (M13.18)."""
    packets = _port_scan_packets(PORT_SCAN_THRESHOLD + 2)
    stack.drive(packets)

    with _api(stack, session_factory, db_engine) as client:
        traffic = _get_data(client, f"{API}/analytics/traffic")
        protocols = _get_data(client, f"{API}/analytics/protocols")
        devices = _get_data(client, f"{API}/analytics/devices")
        threats = _get_data(client, f"{API}/analytics/threats")

    assert traffic["total_packets"] == len(packets)
    # ``/analytics/protocols`` is a block, not a bare list: the entries sit under
    # ``protocols`` beside the totals their shares are relative to (M13.18).
    assert [row["protocol"] for row in protocols["protocols"]] == ["TCP"]
    assert protocols["total_packets"] == len(packets)
    assert devices["total"] >= 1
    # The threat view counts what M10–M12 actually produced.
    assert threats["alerts_total"] == 1
    assert threats["incidents_total"] == 1
    assert threats["findings_retained"] >= 1


def test_the_system_api_reports_a_live_application(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """The system routes answer for the running app, with no secrets (M13.22)."""
    with _api(stack, session_factory, db_engine) as client:
        status = _get_data(client, f"{API}/system/status")
        health = _get_data(client, f"{API}/system/health")
        info = _get_data(client, f"{API}/system/info")

    # Health is a verdict per probe with an aggregate word on top, not a bare
    # mapping of dependency to status (M13.22). Capture being idle is *not* a
    # failure — capture is opt-in — so a freshly started application is healthy.
    assert health["status"] == "healthy"
    probes = {check["name"]: check for check in health["checks"]}
    assert probes["database"]["ok"] is True
    assert probes["capture"]["ok"] is True
    # The consolidated status carries the same reachability verdict.
    assert status["database"]["reachable"] is True
    assert status["capture"]["status"] in {"stopped", "running"}
    # No credential-shaped field is exposed anywhere in the payload.
    flattened = str(info).lower()
    for forbidden in ("password", "secret", "token", "api_key"):
        assert forbidden not in flattened
    # The database is described by dialect, never by the URL behind it (M13.30).
    assert "database_url" not in flattened
    assert "://" not in flattened


def test_the_api_reports_empty_collections_before_any_capture(
    stack: _Stack,
    session_factory: Callable[[], Session],
    db_engine: Any,
) -> None:
    """With nothing captured, every collection is empty rather than invented.

    The baseline the other tests are read against: these routes answer for the
    state they are in, so an empty application produces empty pages and not a
    placeholder row (M13.4/M13.29).
    """
    with _api(stack, session_factory, db_engine) as client:
        packets = _get_data(client, f"{API}/packets")
        devices = _get_data(client, f"{API}/devices")
        connections = _get_data(client, f"{API}/connections")
        detections = _get_data(client, f"{API}/detections")
        alerts = _get_data(client, f"{API}/alerts")
        incidents = _get_data(client, f"{API}/incidents")
        dashboard = _get_data(client, f"{API}/dashboard/summary")

    for page in (packets, devices, connections, detections, alerts, incidents):
        assert page["count"] == 0
        assert page["total"] == 0
        assert page["has_more"] is False
    assert packets["packets"] == []
    assert alerts["alerts"] == []
    assert incidents["incidents"] == []
    # The dashboard still renders every section, all reporting zero.
    assert dashboard["unavailable_sections"] == []
    assert dashboard["traffic"]["data"]["total_packets"] == 0
    assert dashboard["alerts"]["data"]["total"] == 0
    assert dashboard["incidents"]["data"]["total"] == 0
