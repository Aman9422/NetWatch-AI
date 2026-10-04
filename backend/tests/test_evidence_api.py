"""API tests for the evidence endpoints (M13.14).

Evidence is a *reference*, and these tests hold the surface to that. M11.13
stores the id of the packet, conversation or device an alert rests on — never a
copy of it — and the read path must not undo that decision by inlining the
referenced resource. So the tests assert the shape of the payload (a type, a
reference, the record's own document) and that no packet or connection content
appears beside it.

Rows are written through the same in-memory engine the application reads
through, so the API exercises the real repositories and the real
``AlertEvidenceView`` projection rather than a stub of either.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.alerts.queries import AlertQueries
from app.api.v1.deps import get_alert_queries
from app.models.alert import Alert
from app.models.alert_evidence import AlertEvidence

from tests.m13_fakes import api_client

ALERTS_URL = "/api/v1/alerts"
EVIDENCE_URL = "/api/v1/evidence"

#: A pipe-delimited M11 dedup key. Component 0 is the detector's string rule id
#: and component 3 the protocol, which is how ``Alert.from_record`` recovers
#: them — so a seeded row has to carry a well-formed key.
DEDUP_KEY = "port_scan|192.168.1.10|8.8.8.8|TCP|-|-|-"

#: A fixed attach time, so the ISO rendering is asserted exactly.
ATTACHED_AT = datetime(2024, 1, 1, 8, 0, 0)


@pytest.fixture
def client(session_factory: Callable[[], Session]) -> Generator[TestClient, None, None]:
    """A client whose alert queries read the isolated in-memory database."""
    with api_client(
        {get_alert_queries: lambda: AlertQueries(session_factory=session_factory)}
    ) as test_client:
        yield test_client


def store_alert(
    session: Session,
    *,
    title: str = "Port Scan",
    severity: str = "high",
    status: str = "open",
    correlation_key: str | None = DEDUP_KEY,
) -> Alert:
    """Write one alert row, the foreign key every evidence row needs."""
    row = Alert(
        title=title,
        description="Possible port scan detected",
        severity=severity,
        risk_score=40,
        confidence=80,
        status=status,
        correlation_key=correlation_key,
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
    )
    session.add(row)
    session.commit()
    return row


def store_evidence(
    session: Session,
    alert_id: int,
    *,
    evidence_type: str = "packet",
    evidence_data: str = '{"port": 443, "flags": "SYN"}',
    packet_id: int | None = None,
    created_at: datetime = ATTACHED_AT,
) -> AlertEvidence:
    """Write one evidence row attached to ``alert_id``."""
    row = AlertEvidence(
        alert_id=alert_id,
        packet_id=packet_id,
        evidence_type=evidence_type,
        evidence_data=evidence_data,
        created_at=created_at,
    )
    session.add(row)
    session.commit()
    return row


def iso(value: datetime) -> str:
    """Render a naive UTC datetime the way the API documents it (M13.26)."""
    return value.replace(tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# GET /alerts/{alert_id}/evidence
# ---------------------------------------------------------------------------


def test_an_alert_with_no_evidence_lists_nothing(
    client: TestClient, db_session: Session
) -> None:
    """An alert with no supporting rows answers with an empty list, not a 404."""
    alert = store_alert(db_session)

    body = client.get(f"{ALERTS_URL}/{alert.id}/evidence").json()

    assert body["success"] is True
    assert body["data"]["alert_id"] == alert.id
    assert body["data"]["count"] == 0
    assert body["data"]["evidence"] == []


def test_listing_returns_each_record(
    client: TestClient, db_session: Session
) -> None:
    """Each record carries its type, its reference and its parsed document."""
    alert = store_alert(db_session)
    store_evidence(db_session, alert.id, evidence_type="rule", evidence_data='{"threshold": 100}')

    body = client.get(f"{ALERTS_URL}/{alert.id}/evidence").json()

    assert body["data"]["count"] == 1
    record = body["data"]["evidence"][0]
    assert record["evidence_type"] == "rule"
    assert record["data"] == {"threshold": 100}
    assert record["created_at"] == iso(ATTACHED_AT)


def test_the_document_is_parsed_not_returned_as_text(
    client: TestClient, db_session: Session
) -> None:
    """``data`` is an object, so a client reads fields rather than JSON text."""
    alert = store_alert(db_session)
    store_evidence(db_session, alert.id, evidence_data='{"port": 443}')

    record = client.get(f"{ALERTS_URL}/{alert.id}/evidence").json()["data"]["evidence"][0]

    assert isinstance(record["data"], dict)
    assert record["data"]["port"] == 443


def test_a_record_references_its_packet_rather_than_inlining_it(
    client: TestClient, db_session: Session
) -> None:
    """The packet is a reference, so no packet content crosses the boundary.

    M11.13 kept the write path from copying the packet; the read path keeps that
    decision rather than undoing it (M13.14). The payload therefore has exactly
    four fields, and none of them is a packet.
    """
    alert = store_alert(db_session)
    store_evidence(db_session, alert.id)

    record = client.get(f"{ALERTS_URL}/{alert.id}/evidence").json()["data"]["evidence"][0]

    assert set(record) == {"evidence_type", "packet_id", "created_at", "data"}
    assert record["packet_id"] is None


def test_evidence_is_filtered_by_type(
    client: TestClient, db_session: Session
) -> None:
    """``evidence_type`` keeps only that kind of support."""
    alert = store_alert(db_session)
    store_evidence(db_session, alert.id, evidence_type="packet")
    store_evidence(db_session, alert.id, evidence_type="connection")

    data = client.get(
        f"{ALERTS_URL}/{alert.id}/evidence", params={"evidence_type": "connection"}
    ).json()["data"]

    assert data["count"] == 1
    assert data["evidence"][0]["evidence_type"] == "connection"


def test_an_unknown_evidence_type_is_a_400(
    client: TestClient, db_session: Session
) -> None:
    """An unknown kind is a controlled error, never a silently wider result."""
    alert = store_alert(db_session)

    response = client.get(
        f"{ALERTS_URL}/{alert.id}/evidence", params={"evidence_type": "telemetry"}
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "evidence_type"


def test_evidence_for_an_unknown_alert_is_404(client: TestClient) -> None:
    """A missing alert is a 404, not an empty list (M13.14).

    "This alert has no evidence" and "there is no such alert" are different
    answers, and only one of them is true here.
    """
    response = client.get(f"{ALERTS_URL}/424242/evidence")

    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "ALERT_NOT_FOUND"


def test_a_malformed_document_does_not_hide_its_row(
    client: TestClient, db_session: Session
) -> None:
    """One unparsable document yields an empty object, not a failed request.

    Returning an error would hide the alert itself behind one bad row, which is
    a worse outcome than reporting a record whose document could not be read.
    """
    alert = store_alert(db_session)
    store_evidence(db_session, alert.id, evidence_data="{not json at all")

    body = client.get(f"{ALERTS_URL}/{alert.id}/evidence").json()

    assert body["data"]["count"] == 1
    assert body["data"]["evidence"][0]["data"] == {}


# ---------------------------------------------------------------------------
# GET /evidence/{evidence_id}
# ---------------------------------------------------------------------------


def test_a_record_is_readable_on_its_own(
    client: TestClient, db_session: Session
) -> None:
    """The standalone view carries the owning alert, so the reference navigates.

    An operator holding an evidence id needs to reach the alert it supports
    without searching every alert for it (M13.14).
    """
    alert = store_alert(db_session)
    row = store_evidence(db_session, alert.id, evidence_type="behavioral")

    body = client.get(f"{EVIDENCE_URL}/{row.id}").json()

    assert body["success"] is True
    assert body["data"]["evidence_id"] == row.id
    assert body["data"]["alert_id"] == alert.id
    assert body["data"]["evidence"]["evidence_type"] == "behavioral"


def test_the_standalone_view_keeps_the_same_shape(
    client: TestClient, db_session: Session
) -> None:
    """One record serialises identically whichever endpoint serves it."""
    alert = store_alert(db_session)
    row = store_evidence(db_session, alert.id)

    standalone = client.get(f"{EVIDENCE_URL}/{row.id}").json()["data"]["evidence"]

    assert set(standalone) == {"evidence_type", "packet_id", "created_at", "data"}


def test_unknown_evidence_is_404(client: TestClient) -> None:
    """An unknown (or pruned) reference is a 404, not an empty object."""
    response = client.get(f"{EVIDENCE_URL}/424242")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "evidence_id", "code": "EVIDENCE_NOT_FOUND"}]


def test_a_non_numeric_evidence_id_is_rejected(client: TestClient) -> None:
    """A non-numeric id fails request validation rather than the lookup."""
    assert client.get(f"{EVIDENCE_URL}/not-a-number").status_code == 422


def test_evidence_is_read_only(client: TestClient, db_session: Session) -> None:
    """Evidence is recorded by the alert engine; the API only reports it."""
    alert = store_alert(db_session)
    row = store_evidence(db_session, alert.id)

    assert client.post(f"{EVIDENCE_URL}/{row.id}").status_code == 405
    assert client.put(f"{EVIDENCE_URL}/{row.id}").status_code == 405
    assert client.delete(f"{EVIDENCE_URL}/{row.id}").status_code == 405
