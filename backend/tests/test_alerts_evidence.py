"""Tests for alert evidence (M11.29).

Evidence is the answer to "why was this alert created". These tests pin what an
alert carries — the detector record, the measured behaviour, the devices, the
conversations and the packets — and, just as importantly, what it does *not*:
packet payloads are never copied into an alert, and the bounded cap is enforced
rather than quietly exceeded.
"""

from __future__ import annotations

import json

from app.alerts.queries import AlertQueries
from tests.alert_fakes import (
    DESTINATION_DEVICE_ID,
    SOURCE_DEVICE_ID,
    FakeConnection,
    FakeConnectionSource,
    FakePacket,
    FakePacketSource,
    insert_packet,
    make_finding,
    make_resolvers,
    make_service,
)


def _detail(session_factory, alert_id: int):
    """Return the stored alert detail, failing loudly if it is missing."""
    detail = AlertQueries(session_factory=session_factory).get_detail(alert_id)
    assert detail is not None
    return detail


def _records_of(detail, evidence_type: str) -> list:
    """Return the evidence rows of one type."""
    return [
        record for record in detail.evidence if record.evidence_type == evidence_type
    ]


def _data(record) -> dict:
    """Parse one evidence row's JSON document."""
    return json.loads(record.evidence_data)


# -- the always-present evidence (M11.11) -----------------------------------


def test_an_alert_always_carries_rule_and_behavioural_evidence(
    session_factory,
) -> None:
    """Even with no resolvers, the alert explains itself (M11.7/M11.11)."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    types = [record.evidence_type for record in detail.evidence]
    assert "rule" in types
    assert "behavioral" in types
    assert len(_records_of(detail, "rule")) == 1
    assert len(_records_of(detail, "behavioral")) == 1


def test_rule_evidence_names_the_detector_and_finding(session_factory) -> None:
    """The rule record keeps the finding and severity identifiable (M11.7/M11.8)."""
    service = make_service(session_factory)
    finding = make_finding(confidence=0.7)
    outcome = service.process_finding(finding)
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    rule = _data(_records_of(detail, "rule")[0])

    assert rule["finding_id"] == finding.finding_id
    assert rule["rule_id"] == "port_scan"
    assert rule["rule_name"] == "Port Scan"
    assert rule["severity"] == "high"


def test_behavioural_evidence_carries_the_measured_numbers(session_factory) -> None:
    """The detector's own measurements are preserved verbatim (M11.11)."""
    service = make_service(session_factory)
    outcome = service.process_finding(
        make_finding(evidence={"unique_destination_ports": 37, "threshold": 20})
    )
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    behavioural = _data(_records_of(detail, "behavioral")[0])

    assert behavioural["measured"] == {
        "unique_destination_ports": 37,
        "threshold": 20,
    }


# -- device evidence (M11.15) -----------------------------------------------


def test_resolved_devices_become_evidence(session_factory) -> None:
    """Each resolved device is recorded, with its role (M11.15)."""
    service = make_service(session_factory)
    outcome = service.process_finding(
        make_finding(
            source_device_id=SOURCE_DEVICE_ID,
            destination_device_id=DESTINATION_DEVICE_ID,
        )
    )
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    devices = _records_of(detail, "device")

    assert len(devices) == 2
    roles = {_data(record)["role"] for record in devices}
    assert roles == {"source", "destination"}


def test_unresolved_device_produces_no_device_evidence(session_factory) -> None:
    """No device identity means no device record, not a placeholder (M11.15)."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    assert _records_of(detail, "device") == []


# -- connection evidence (M11.14) -------------------------------------------


def test_related_connections_become_evidence(session_factory) -> None:
    """Each conversation the resolver returns is recorded (M11.14)."""
    resolvers = make_resolvers(
        connection_source=FakeConnectionSource(
            [FakeConnection("conn-1"), FakeConnection("conn-2")]
        )
    )
    service = make_service(session_factory, resolvers=resolvers)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    connections = _records_of(detail, "connection")

    assert len(connections) == 2
    ids = {_data(record)["connection_id"] for record in connections}
    assert ids == {"conn-1", "conn-2"}


def test_connection_evidence_does_not_create_a_connection_store(
    session_factory,
) -> None:
    """The record references the M9 conversation by id, not a stored copy."""
    resolvers = make_resolvers(
        connection_source=FakeConnectionSource([FakeConnection("conn-7")])
    )
    service = make_service(session_factory, resolvers=resolvers)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    record = _records_of(detail, "connection")[0]

    assert _data(record)["connection_id"] == "conn-7"


# -- packet evidence (M11.13) -----------------------------------------------


def test_packet_evidence_references_a_real_packet(session_factory) -> None:
    """A resolved packet is referenced by its primary key (M11.13)."""
    packet_id = insert_packet(session_factory)
    resolvers = make_resolvers(
        packet_source=FakePacketSource([FakePacket(packet_id)])
    )
    service = make_service(session_factory, resolvers=resolvers)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    packets = _records_of(detail, "packet")

    assert len(packets) == 1
    assert packets[0].packet_id == packet_id


def test_packet_evidence_never_copies_the_payload(session_factory) -> None:
    """Evidence holds a readable digest, never the packet's own fields (M11.13)."""
    packet_id = insert_packet(session_factory)
    resolvers = make_resolvers(
        packet_source=FakePacketSource([FakePacket(packet_id)])
    )
    service = make_service(session_factory, resolvers=resolvers)
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)
    digest = _data(_records_of(detail, "packet")[0])

    assert "payload" not in digest
    assert digest["packet_id"] == packet_id
    # Only a small, legible digest travels with the reference.
    assert set(digest) == {
        "role",
        "packet_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "length",
    }


def test_packet_evidence_can_be_disabled(session_factory) -> None:
    """The packet switch (M11.13) suppresses packet records only."""
    packet_id = insert_packet(session_factory)
    resolvers = make_resolvers(
        packet_source=FakePacketSource([FakePacket(packet_id)])
    )
    service = make_service(
        session_factory, resolvers=resolvers, packet_evidence_enabled=False
    )
    outcome = service.process_finding(make_finding())
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    assert _records_of(detail, "packet") == []
    assert _records_of(detail, "rule")  # the justification is still present


# -- the bounded evidence set (M11.12) --------------------------------------


def test_evidence_count_is_reported_on_the_alert(session_factory) -> None:
    """The alert's ``evidence_count`` matches the rows actually stored (M11.3)."""
    service = make_service(session_factory)
    outcome = service.process_finding(
        make_finding(
            source_device_id=SOURCE_DEVICE_ID,
            destination_device_id=DESTINATION_DEVICE_ID,
        )
    )
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    assert outcome.alert.evidence_count == len(detail.evidence)
    assert detail.alert.evidence_count == len(detail.evidence)


def test_evidence_is_bounded_by_the_cap(session_factory) -> None:
    """The cap bites, and it drops the least important evidence first (M11.12)."""
    service = make_service(session_factory, max_evidence=3)
    outcome = service.process_finding(
        make_finding(
            source_device_id=SOURCE_DEVICE_ID,
            destination_device_id=DESTINATION_DEVICE_ID,
        )
    )
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    assert len(detail.evidence) == 3
    # Rule and behavioural evidence are never the ones dropped.
    types = [record.evidence_type for record in detail.evidence]
    assert types[0] == "rule"
    assert types[1] == "behavioral"


def test_evidence_count_by_type_is_reported(session_factory) -> None:
    """The detail groups evidence by type, so an alert is describeable."""
    service = make_service(session_factory)
    outcome = service.process_finding(make_finding(source_device_id=SOURCE_DEVICE_ID))
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    assert detail.evidence_by_type["rule"] == 1
    assert detail.evidence_by_type["behavioral"] == 1
    assert detail.evidence_by_type["device"] == 1


def test_evidence_created_at_matches_the_observation(session_factory) -> None:
    """Evidence is dated to the observation, not the write (M11.11)."""
    from app.alerts.timestamps import to_utc_datetime

    service = make_service(session_factory)
    outcome = service.process_finding(make_finding(timestamp=1_767_268_800.0))
    assert outcome.alert is not None and outcome.alert.alert_id is not None

    detail = _detail(session_factory, outcome.alert.alert_id)

    for record in detail.evidence:
        assert record.created_at == to_utc_datetime(1_767_268_800.0)
