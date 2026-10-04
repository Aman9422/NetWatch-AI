"""API tests for the incident endpoints (M13.15/M13.16).

Incidents are seeded the way the application makes them — by correlating alerts
through the real M12 engine — so the tests exercise the stored object rather than
a hand-built stand-in, and a change in how correlation groups events shows up
here rather than being masked by a fixture.

Two boundaries get most of the attention, because they are the ones an API layer
is most likely to erode: no risk is recomputed here (it is read from the
incident, M12.13), and no lifecycle rule is written here (every move goes
through ``CorrelationEngine.set_status``). The second is checked by *parity*: for
every state pair, whether the API accepts the move must equal whether
``app.correlation.status`` allows it — not a second copy of the table that could
disagree with it.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.correlation import get_correlation_engine
from app.correlation.engine import CorrelationEngine
from app.correlation.registry import IncidentQuery
from app.correlation.status import STATUS_VALUES, is_valid_transition
from tests.correlation_fakes import (
    CORRELATION_BASE_TIME,
    DESTINATION_DEVICE_ID,
    DESTINATION_IP,
    SOURCE_DEVICE_ID,
    SOURCE_IP,
    make_alert,
    make_engine,
)
from tests.m13_fakes import api_client

INCIDENTS_URL = "/api/v1/incidents"
OPEN_URL = f"{INCIDENTS_URL}/open"

#: How each lifecycle state is reached from ``open`` by walking the API (M12.9).
DRIVE = {
    "open": None,
    "investigating": "investigate",
    "resolved": "resolve",
    "dismissed": "dismiss",
}


@pytest.fixture
def correlations() -> CorrelationEngine:
    """A correlation engine over deterministic collaborators."""
    return make_engine()


@pytest.fixture
def client(correlations: CorrelationEngine) -> Generator[TestClient, None, None]:
    """A client whose correlation engine is the one the test seeds."""
    with api_client({get_correlation_engine: lambda: correlations}) as test_client:
        yield test_client


def unrelated_identity(index: int) -> dict[str, Any]:
    """Return an identity tuple sharing nothing with any other ``index``.

    Correlation anchors on an identity overlap — a shared address or device — so
    two events with *no* shared dimension are two incidents. Varying all four at
    once is what keeps them separate rather than being folded together.
    """
    return {
        "source_ip": f"10.0.0.{index}",
        "source_device_id": f"mac:00:00:00:00:00:{index:02d}",
        "destination_ip": f"10.1.0.{index}",
        "destination_device_id": f"mac:11:11:11:11:11:{index:02d}",
    }


def seed_incident(
    engine: CorrelationEngine,
    *,
    alert_id: int,
    at: float = CORRELATION_BASE_TIME,
    rule_id: str = "port_scan",
    **identity: Any,
) -> str:
    """Correlate one alert and return the incident identifier it produced.

    Uses the engine's public ingestion path, so the incident under test is the
    one the application would have built. The timestamp is supplied explicitly so
    ordering tests control recency rather than depending on the wall clock.
    """
    outcome = engine.correlate_alert(
        make_alert(
            alert_id=alert_id,
            rule_id=rule_id,
            source_ip=identity.get("source_ip", SOURCE_IP),
            source_device_id=identity.get("source_device_id", SOURCE_DEVICE_ID),
            destination_ip=identity.get("destination_ip", DESTINATION_IP),
            destination_device_id=identity.get(
                "destination_device_id", DESTINATION_DEVICE_ID
            ),
        ),
        timestamp=at,
    )
    assert outcome.error is None, outcome.error
    assert outcome.incident_id is not None
    return outcome.incident_id


def seed_several(engine: CorrelationEngine, count: int) -> list[str]:
    """Seed ``count`` mutually unrelated incidents, each later than the last."""
    return [
        seed_incident(
            engine,
            alert_id=index,
            at=CORRELATION_BASE_TIME + index,
            **unrelated_identity(index),
        )
        for index in range(1, count + 1)
    ]


#: The state each lifecycle verb moves an incident into (M12.9).
STATUS_FOR_VERB = {
    "investigate": "investigating",
    "resolve": "resolved",
    "dismiss": "dismissed",
}


def drive_to(engine: CorrelationEngine, incident_id: str, state: str) -> None:
    """Move an incident into ``state`` by walking legal moves from ``open``.

    Used to place an incident in a known starting state for a transition test
    without reaching past the engine into the store.
    """
    verb = DRIVE[state]
    if verb is not None:
        engine.set_status(incident_id, STATUS_FOR_VERB[verb])


# ---------------------------------------------------------------------------
# GET /incidents
# ---------------------------------------------------------------------------


def test_empty_listing_is_well_formed(client: TestClient) -> None:
    """An empty store returns a well-formed, empty collection with a total."""
    body = client.get(INCIDENTS_URL).json()

    assert body["success"] is True
    data = body["data"]
    assert data["count"] == 0
    assert data["total"] == 0
    assert data["incidents"] == []
    assert data["has_more"] is False


def test_listing_matches_the_engine(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """The listing is the engine's own page, not a re-derived one."""
    seed_several(correlations, 3)

    data = client.get(INCIDENTS_URL).json()["data"]
    expected = correlations.get_incidents(IncidentQuery())

    assert data["count"] == len(expected) == 3
    assert data["total"] == correlations.count_incidents()
    assert [item["incident_id"] for item in data["incidents"]] == [
        incident.incident_id for incident in expected
    ]


def test_listing_is_newest_first(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """Ordering is by most recent activity, so a client reads the newest first."""
    seed_several(correlations, 3)

    incidents = client.get(INCIDENTS_URL).json()["data"]["incidents"]
    last_seen = [item["last_seen"] for item in incidents]

    assert last_seen == sorted(last_seen, reverse=True)


def test_listing_order_is_total(client: TestClient, correlations: CorrelationEngine) -> None:
    """Incidents sharing a timestamp still have one stable order (M13.24)."""
    for index in (1, 2, 3):
        seed_incident(
            correlations, alert_id=index, at=CORRELATION_BASE_TIME, **unrelated_identity(index)
        )

    first_pass = [i["incident_id"] for i in client.get(INCIDENTS_URL).json()["data"]["incidents"]]
    second_pass = [i["incident_id"] for i in client.get(INCIDENTS_URL).json()["data"]["incidents"]]

    assert first_pass == second_pass


def test_listing_row_carries_no_member_lists(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """A listing row is a summary; membership belongs to the detail view."""
    seed_incident(correlations, alert_id=1)

    row = client.get(INCIDENTS_URL).json()["data"]["incidents"][0]

    assert set(row).isdisjoint(
        {"alert_ids", "finding_ids", "connection_ids", "rule_ids", "correlation_reasons"}
    )
    assert row["alert_count"] == 1
    assert "risk_score" in row
    assert "risk_band" in row


def test_filter_by_status(client: TestClient, correlations: CorrelationEngine) -> None:
    """``status`` selects only incidents in that lifecycle state."""
    first = seed_incident(correlations, alert_id=1)
    seed_incident(correlations, alert_id=2, **unrelated_identity(2))
    correlations.set_status(first, "resolved")

    data = client.get(INCIDENTS_URL, params={"status": "resolved"}).json()["data"]

    assert data["count"] == 1
    assert data["incidents"][0]["incident_id"] == first


def test_unknown_status_is_rejected(client: TestClient) -> None:
    """An unknown state fails request validation, not the store (M13.25)."""
    assert client.get(INCIDENTS_URL, params={"status": "closed"}).status_code == 422


def test_active_only_excludes_resolved(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``active_only`` keeps what still needs attention (M12.9)."""
    first = seed_incident(correlations, alert_id=1)
    seed_incident(correlations, alert_id=2, **unrelated_identity(2))
    correlations.set_status(first, "resolved")

    data = client.get(INCIDENTS_URL, params={"active_only": True}).json()["data"]

    assert data["count"] == 1
    assert data["incidents"][0]["incident_id"] != first


def test_filter_by_source_and_device(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``source`` and ``device_id`` match the incident's own identity index."""
    seed_several(correlations, 3)

    by_source = client.get(
        INCIDENTS_URL, params={"source": unrelated_identity(2)["source_ip"]}
    ).json()["data"]
    by_device = client.get(
        INCIDENTS_URL, params={"device_id": unrelated_identity(3)["source_device_id"]}
    ).json()["data"]

    assert by_source["count"] == 1
    assert by_device["count"] == 1
    assert by_source["incidents"][0]["incident_id"] != by_device["incidents"][0]["incident_id"]


def test_filter_by_rule_id(client: TestClient, correlations: CorrelationEngine) -> None:
    """``rule_id`` matches a detector rule that contributed to the incident."""
    seed_incident(correlations, alert_id=1, rule_id="port_scan")
    other = seed_incident(
        correlations, alert_id=2, rule_id="syn_flood", **unrelated_identity(2)
    )

    data = client.get(INCIDENTS_URL, params={"rule_id": "syn_flood"}).json()["data"]

    assert data["count"] == 1
    assert data["incidents"][0]["incident_id"] == other


def test_risk_range_is_applied(client: TestClient, correlations: CorrelationEngine) -> None:
    """``min_risk_score``/``max_risk_score`` bound the stored score (M13.15)."""
    low = seed_incident(correlations, alert_id=1)
    high = seed_incident(correlations, alert_id=2, **unrelated_identity(2))
    # Written through the registry's documented backfill path (M12.13), so the
    # scores are exact rather than whatever the formula happens to produce.
    correlations.registry.apply_risk(low, score=10)
    correlations.registry.apply_risk(high, score=90)

    data = client.get(INCIDENTS_URL, params={"min_risk_score": 50}).json()["data"]

    assert data["count"] == 1
    assert data["incidents"][0]["incident_id"] == high


def test_risk_order_is_highest_first(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``order=risk`` ranks by score, not by recency (M12.26)."""
    low = seed_incident(correlations, alert_id=1)
    high = seed_incident(correlations, alert_id=2, **unrelated_identity(2))
    correlations.registry.apply_risk(low, score=10)
    correlations.registry.apply_risk(high, score=90)

    incidents = client.get(INCIDENTS_URL, params={"order": "risk"}).json()["data"]["incidents"]

    assert [item["incident_id"] for item in incidents] == [high, low]


def test_inverted_risk_range_is_a_400(client: TestClient) -> None:
    """A range that cannot match is rejected, not answered with an empty page."""
    response = client.get(
        INCIDENTS_URL, params={"min_risk_score": 80, "max_risk_score": 20}
    )

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["field"] == "min_risk_score"


def test_risk_bounds_are_validated(client: TestClient) -> None:
    """A score bound outside ``0..100`` fails request validation (M13.25)."""
    assert client.get(INCIDENTS_URL, params={"min_risk_score": 101}).status_code == 422
    assert client.get(INCIDENTS_URL, params={"max_risk_score": -1}).status_code == 422


def test_confidence_bound_is_validated(client: TestClient) -> None:
    """``min_confidence`` is a unit-interval number (M13.25)."""
    assert client.get(INCIDENTS_URL, params={"min_confidence": 1.5}).status_code == 422
    assert client.get(INCIDENTS_URL, params={"min_confidence": -0.1}).status_code == 422


def test_inverted_time_range_is_a_400(client: TestClient) -> None:
    """An inverted window is a controlled error, not an empty result."""
    response = client.get(
        INCIDENTS_URL,
        params={
            "since": "2024-06-01T00:00:00+00:00",
            "until": "2024-01-01T00:00:00+00:00",
        },
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "since"


@pytest.mark.parametrize("field", ["since", "until"])
def test_unparseable_time_is_a_400(client: TestClient, field: str) -> None:
    """A timestamp that cannot be read names the parameter that failed (M13.26).

    A typo must be a controlled 400, never an unhandled error: the parse raises a
    plain ``ValueError``, so a route that does not translate it would answer 500
    and make a client's mistake look like a server fault.
    """
    response = client.get(INCIDENTS_URL, params={field: "yesterday"})

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == field


def test_pagination_bounds_the_page_and_reports_the_total(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``limit``/``offset`` bound the page while ``total`` describes the match set."""
    seed_several(correlations, 5)

    first = client.get(INCIDENTS_URL, params={"limit": 2}).json()["data"]
    second = client.get(INCIDENTS_URL, params={"limit": 2, "offset": 2}).json()["data"]

    assert first["count"] == 2
    assert first["total"] == 5
    assert first["limit"] == 2
    assert first["offset"] == 0
    assert first["has_more"] is True
    assert {i["incident_id"] for i in first["incidents"]}.isdisjoint(
        {i["incident_id"] for i in second["incidents"]}
    )


def test_page_metadata_reflects_the_filter(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``total`` counts the matches, so a page and its total agree (M13.24)."""
    # A distinct alert id and identity, so this incident is its own rather than
    # a repeat of one the helper below is about to create.
    dismissed = seed_incident(correlations, alert_id=99, **unrelated_identity(99))
    seed_several(correlations, 3)
    correlations.set_status(dismissed, "dismissed")

    data = client.get(INCIDENTS_URL, params={"active_only": True}).json()["data"]

    assert data["count"] == data["total"] == 3


def test_limit_bounds_are_validated(client: TestClient) -> None:
    """An out-of-range limit fails request validation, never the store (M13.24)."""
    assert client.get(INCIDENTS_URL, params={"limit": 0}).status_code == 422
    assert client.get(INCIDENTS_URL, params={"limit": 100_000}).status_code == 422
    assert client.get(INCIDENTS_URL, params={"offset": -1}).status_code == 422


def test_unknown_order_is_rejected(client: TestClient) -> None:
    """An unknown ordering fails request validation rather than defaulting."""
    assert client.get(INCIDENTS_URL, params={"order": "alphabetical"}).status_code == 422


# ---------------------------------------------------------------------------
# GET /incidents/open
# ---------------------------------------------------------------------------


def test_open_listing_excludes_terminal_incidents(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``/open`` is the active set, using the store's own definition (M13.15)."""
    resolved = seed_incident(correlations, alert_id=1)
    investigating = seed_incident(correlations, alert_id=2, **unrelated_identity(2))
    correlations.set_status(resolved, "resolved")
    correlations.set_status(investigating, "investigating")

    data = client.get(OPEN_URL).json()["data"]

    assert data["count"] == 1
    assert data["incidents"][0]["incident_id"] == investigating
    assert data["incidents"][0]["status"] == "investigating"


def test_open_is_not_read_as_an_identifier(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``open`` resolves to the listing rather than to an incident lookup."""
    seed_incident(correlations, alert_id=1)

    response = client.get(OPEN_URL)

    assert response.status_code == 200
    assert "incidents" in response.json()["data"]


def test_open_orders_by_risk(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``/open`` answers "what needs attention first", so it ranks by risk."""
    low = seed_incident(correlations, alert_id=1)
    high = seed_incident(correlations, alert_id=2, **unrelated_identity(2))
    correlations.registry.apply_risk(low, score=10)
    correlations.registry.apply_risk(high, score=90)

    incidents = client.get(OPEN_URL).json()["data"]["incidents"]

    assert [i["incident_id"] for i in incidents] == [high, low]


# ---------------------------------------------------------------------------
# GET /incidents/{incident_id}
# ---------------------------------------------------------------------------


def test_detail_carries_the_full_membership(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """The detail view explains the grouping: members, reasons and score.

    The detail view carries what the listing omits — the member alert ids, the
    correlation reason trail and the rules that grouped it — so an operator can
    read *why* these events were judged to be one incident (M12.26).
    """
    incident_id = seed_incident(correlations, alert_id=1)

    body = client.get(f"{INCIDENTS_URL}/{incident_id}").json()

    assert body["success"] is True
    data = body["data"]
    assert data["incident_id"] == incident_id
    assert data["alert_ids"] == [1]
    assert data["event_count"] == 1
    assert data["rule_ids"] == ["port_scan"]
    assert data["status"] == "open"
    assert "risk_score" in data and "risk_band" in data
    assert data["start_time_iso"].endswith("+00:00")


def test_detail_reports_correlation_reasons_when_events_join(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """A grouped incident carries the reason trail that justified the grouping.

    The first event opens the incident, so its trail is empty; the second joins
    it and contributes the reasons. That asymmetry is the point — a reason trail
    is evidence of correlation, not decoration.
    """
    first = seed_incident(correlations, alert_id=1)
    joined = seed_incident(correlations, alert_id=2)
    assert joined == first

    data = client.get(f"{INCIDENTS_URL}/{first}").json()["data"]

    assert data["alert_ids"] == [1, 2]
    assert data["correlation_reasons"] != []
    assert data["correlation_rule_ids"] != []
    assert data["correlation_confidence"] > 0.0


def test_unknown_incident_is_404(client: TestClient) -> None:
    """An unknown id returns the standard not-found envelope (M13.15)."""
    response = client.get(f"{INCIDENTS_URL}/inc:does-not-exist")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [
        {"field": "incident_id", "code": "INCIDENT_NOT_FOUND"}
    ]


# ---------------------------------------------------------------------------
# Incident lifecycle (M13.16)
# ---------------------------------------------------------------------------


def test_investigate_moves_an_open_incident(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``investigate`` is accepted from ``open`` and is visible afterwards."""
    incident_id = seed_incident(correlations, alert_id=1)

    response = client.post(f"{INCIDENTS_URL}/{incident_id}/investigate")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "investigating"
    assert client.get(f"{INCIDENTS_URL}/{incident_id}").json()["data"]["status"] == "investigating"


def test_resolve_is_accepted_from_investigating(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``investigating`` may be resolved (M12.9)."""
    incident_id = seed_incident(correlations, alert_id=1)
    drive_to(correlations, incident_id, "investigating")

    response = client.post(f"{INCIDENTS_URL}/{incident_id}/resolve")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "resolved"


def test_dismiss_is_accepted_from_open(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """``open`` may be dismissed, which is terminal (M12.9)."""
    incident_id = seed_incident(correlations, alert_id=1)

    response = client.post(f"{INCIDENTS_URL}/{incident_id}/dismiss")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "dismissed"


def test_same_state_move_is_a_no_op_not_an_error(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """Re-marking an incident as investigating changes nothing and is allowed."""
    incident_id = seed_incident(correlations, alert_id=1)
    drive_to(correlations, incident_id, "investigating")

    response = client.post(f"{INCIDENTS_URL}/{incident_id}/investigate")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "investigating"


def test_a_terminal_incident_cannot_be_reopened(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """M12 offers no reopen, so a dismissed incident cannot be investigated."""
    incident_id = seed_incident(correlations, alert_id=1)
    drive_to(correlations, incident_id, "dismissed")

    response = client.post(f"{INCIDENTS_URL}/{incident_id}/investigate")

    assert response.status_code == 409
    assert response.json()["errors"] == [
        {"field": "status", "code": "INVALID_TRANSITION"}
    ]


def test_a_rejected_transition_leaves_the_incident_untouched(
    client: TestClient, correlations: CorrelationEngine
) -> None:
    """A refused move is not a partial write (M13.16)."""
    incident_id = seed_incident(correlations, alert_id=1)
    drive_to(correlations, incident_id, "resolved")

    client.post(f"{INCIDENTS_URL}/{incident_id}/investigate")

    assert client.get(f"{INCIDENTS_URL}/{incident_id}").json()["data"]["status"] == "resolved"


def test_unknown_incident_transition_is_404(client: TestClient) -> None:
    """A lifecycle move on an unknown incident is a not-found, not a conflict."""
    response = client.post(f"{INCIDENTS_URL}/inc:missing/resolve")

    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "INCIDENT_NOT_FOUND"


@pytest.mark.parametrize("current", STATUS_VALUES)
@pytest.mark.parametrize(
    "verb, target",
    [
        ("investigate", "investigating"),
        ("resolve", "resolved"),
        ("dismiss", "dismissed"),
    ],
)
def test_transition_reachability_matches_the_m12_table(
    client: TestClient,
    correlations: CorrelationEngine,
    current: str,
    verb: str,
    target: str,
) -> None:
    """The API's answer equals the M12 transition table's, for every pair.

    This is the parity check that makes M13.16's "do not duplicate lifecycle
    rules inside routes" verifiable rather than a claim: the expected verdict is
    computed from ``app.correlation.status`` — the one authority — so a route
    that grew its own rules would fail here.
    """
    incident_id = seed_incident(correlations, alert_id=1)
    drive_to(correlations, incident_id, current)

    response = client.post(f"{INCIDENTS_URL}/{incident_id}/{verb}")

    if current == target or is_valid_transition(current, target):
        assert response.status_code == 200
        assert response.json()["data"]["status"] == target
    else:
        assert response.status_code == 409
        assert response.json()["errors"][0]["code"] == "INVALID_TRANSITION"


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


def test_collection_rejects_unsupported_verbs(client: TestClient) -> None:
    """The collection is read-only; lifecycle moves are their own sub-resources."""
    assert client.post(INCIDENTS_URL).status_code == 405
    assert client.put(INCIDENTS_URL).status_code == 405
    assert client.delete(INCIDENTS_URL).status_code == 405
