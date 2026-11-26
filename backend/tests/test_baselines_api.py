"""API tests for the baseline endpoints (M21.10).

Before M21 this file asserted a deliberate ``501``: no baseline engine existed, and
serving the M2 development seed rows would have presented a placeholder as an
analysed profile. M21 implements the engine, so the tests now assert the real
surfaces — and, just as importantly, the things these routes still must *not* do.

The absences are asserted rather than assumed:

* no response carries a risk score, severity, confidence or any other judgement;
* no response carries a peer address or a port number — a profile reports *how
  many* distinct peers and ports, never which;
* a device that has produced no observation window has **no baseline**, and the
  detail route answers ``404`` rather than a fabricated empty profile.

Every test runs against an isolated in-memory database by overriding
``get_baseline_engine``, so nothing here can reach the developer's own
``netwatch.db``.
"""

from __future__ import annotations

from collections.abc import Callable, Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.baselines import get_baseline_engine
from app.baselines.aggregation import WindowAggregator
from app.baselines.engine import BaselineEngine
from app.baselines.store import BaselineStore
from app.schemas.baseline import BASELINE_DISCLAIMER
from tests.m13_fakes import api_client, baseline_engine_override

BASELINES_URL = "/api/v1/baselines"

#: The device the seeded windows belong to.
DEVICE_KEY = "mac:aa:bb:cc:dd:ee:01"

#: A window start that is a whole number of minutes, so flooring is exact.
WINDOW_START = 1_700_000_040.0


def seed_windows(
    engine: BaselineEngine,
    *,
    device_key: str = DEVICE_KEY,
    count: int = 6,
    packets: int = 10,
) -> None:
    """Feed ``count`` complete windows for one device into ``engine``.

    Each window carries a constant ``packets`` count so the resulting statistics
    are exactly predictable — a mean and median of ``packets`` and a MAD of zero —
    which lets a test assert a real figure rather than "some number".
    """
    from app.baselines.features import PacketObservation
    from app.schemas.packet import PacketType

    for index in range(count):
        at = WINDOW_START + index * 60.0
        for _ in range(packets):
            observation = PacketObservation(
                device_key=device_key,
                identity_kind="mac",
                mac_address="aa:bb:cc:dd:ee:01",
                ip_address="10.0.0.21",
                peer_ip="10.0.0.1",
                destination_port=443,
                length=100,
                protocol="TCP",
                packet_type=PacketType.TCP,
                is_syn=True,
            )
            engine.get_aggregator().observe_packet(observation, at=at)
    # Close every window and write it, exactly as the flush thread would.
    engine.flush_all()


@pytest.fixture
def engine(session_factory: Callable[[], Session]) -> BaselineEngine:
    """An engine over the isolated in-memory database, thread not started."""
    return BaselineEngine(
        store=BaselineStore(
            session_factory=session_factory,
            provisional_min_samples=3,
            established_min_samples=10,
        ),
        aggregator=WindowAggregator(window_seconds=60.0),
        autostart=False,
    )


@pytest.fixture
def client(engine: BaselineEngine) -> Generator[TestClient, None, None]:
    """A client whose baseline routes read the isolated engine."""
    with api_client({get_baseline_engine: lambda: engine}) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# The listing
# ---------------------------------------------------------------------------


def test_an_empty_listing_is_a_page_not_a_fabrication(
    client: TestClient,
) -> None:
    """With nothing learnt the listing is an empty page with a real total.

    A baseline is only described once observations exist, so an empty page is the
    honest answer rather than a profile of zeroes (M21.7).
    """
    response = client.get(BASELINES_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert data["baselines"] == []
    assert data["total"] == 0
    assert data["count"] == 0
    assert data["has_more"] is False


def test_a_listing_carries_the_learning_state_and_sample_count(
    client: TestClient, engine: BaselineEngine
) -> None:
    """A learnt baseline reports its state, sample count and window length."""
    seed_windows(engine, count=6)

    data = client.get(BASELINES_URL).json()["data"]

    assert data["total"] == 1
    baseline = data["baselines"][0]
    assert baseline["device_key"] == DEVICE_KEY
    assert baseline["identity_kind"] == "mac"
    assert baseline["sample_count"] == 6
    # 6 windows clears the provisional threshold of 3, not the established 10.
    assert baseline["learning_state"] == "provisional"
    assert baseline["window_seconds"] == 60.0


def test_a_learning_baseline_publishes_no_statistics(
    client: TestClient, engine: BaselineEngine
) -> None:
    """Below the minimum sample count no profile is published (M21.7)."""
    seed_windows(engine, count=2)

    baseline = client.get(BASELINES_URL).json()["data"]["baselines"][0]

    assert baseline["learning_state"] == "learning"
    assert baseline["sample_count"] == 2
    assert baseline["statistics"] == []


def test_an_established_baseline_publishes_a_real_profile(
    client: TestClient, engine: BaselineEngine
) -> None:
    """Enough windows produce an established profile with calculated figures."""
    seed_windows(engine, count=12, packets=10)

    baseline = client.get(BASELINES_URL).json()["data"]["baselines"][0]

    assert baseline["learning_state"] == "established"
    features = {entry["feature"]: entry for entry in baseline["statistics"]}
    packet_feature = features["packet_count"]
    # Twelve windows of exactly ten packets: every central figure is exactly 10.
    assert packet_feature["count"] == 12
    assert packet_feature["mean"] == 10.0
    assert packet_feature["median"] == 10.0
    assert packet_feature["mad"] == 0.0
    assert packet_feature["min"] == 10.0
    assert packet_feature["max"] == 10.0


def test_the_learning_state_filter_narrows_the_listing(
    client: TestClient, engine: BaselineEngine
) -> None:
    """``learning_state`` is a real filter, and an unknown one is a 422."""
    seed_windows(engine, count=6)

    provisional = client.get(
        BASELINES_URL, params={"learning_state": "provisional"}
    ).json()["data"]
    learning = client.get(
        BASELINES_URL, params={"learning_state": "learning"}
    ).json()["data"]

    assert provisional["total"] == 1
    assert learning["total"] == 0
    assert client.get(
        BASELINES_URL, params={"learning_state": "made-up"}
    ).status_code == 422


# ---------------------------------------------------------------------------
# The detail
# ---------------------------------------------------------------------------


def test_the_detail_carries_recent_windows_and_the_statistics(
    client: TestClient, engine: BaselineEngine
) -> None:
    """The detail exposes the samples the profile was calculated from."""
    seed_windows(engine, count=6, packets=4)

    response = client.get(f"{BASELINES_URL}/{DEVICE_KEY}")

    assert response.status_code == 200
    baseline = response.json()["data"]
    assert baseline["sample_count"] == 6
    assert len(baseline["recent_windows"]) == 6
    window = baseline["recent_windows"][0]
    assert window["packet_count"] == 4
    assert window["tcp_packets"] == 4
    assert window["unique_peers"] == 1
    assert window["unique_destination_ports"] == 1
    assert window["window_start"].endswith("+00:00")


def test_an_unknown_device_has_no_baseline_rather_than_an_empty_one(
    client: TestClient,
) -> None:
    """A device nothing was observed for is a ``404``, not a profile of zeroes."""
    response = client.get(f"{BASELINES_URL}/mac:00:00:00:00:00:99")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["field"] == "device_key"


def test_the_detail_states_what_a_baseline_is_and_is_not(
    client: TestClient, engine: BaselineEngine
) -> None:
    """Every profile carries the disclaimer M21.7 requires."""
    seed_windows(engine, count=6)

    baseline = client.get(f"{BASELINES_URL}/{DEVICE_KEY}").json()["data"]

    assert baseline["disclaimer"] == BASELINE_DISCLAIMER
    assert "not an anomaly verdict" in baseline["disclaimer"]
    assert baseline["state_description"]


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_a_reset_deletes_the_baseline_and_restarts_learning(
    client: TestClient, engine: BaselineEngine
) -> None:
    """The reset removes this device's windows and profile, and says so."""
    seed_windows(engine, count=6)

    response = client.post(f"{BASELINES_URL}/{DEVICE_KEY}/reset")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["device_key"] == DEVICE_KEY
    assert data["windows_deleted"] == 6
    assert data["profile_deleted"] is True
    assert data["learning_restarted"] is True

    # Learning genuinely restarted: the listing is empty again and a new packet
    # would begin a fresh window rather than resuming a partial one.
    assert client.get(BASELINES_URL).json()["data"]["total"] == 0
    assert client.get(f"{BASELINES_URL}/{DEVICE_KEY}").status_code == 404


def test_a_reset_of_an_unknown_device_is_still_successful(
    client: TestClient,
) -> None:
    """Resetting a device with no baseline leaves it with no baseline.

    A ``404`` here would force a caller to distinguish "already absent" from
    "reset failed" for an operation whose outcome is identical.
    """
    response = client.post(f"{BASELINES_URL}/mac:11:22:33:44:55:66/reset")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["windows_deleted"] == 0
    assert data["profile_deleted"] is False


def test_a_reset_does_not_touch_another_devices_baseline(
    client: TestClient, engine: BaselineEngine
) -> None:
    """Reset is scoped to one identity, never to the store."""
    other_key = "mac:aa:bb:cc:dd:ee:02"
    seed_windows(engine, device_key=DEVICE_KEY, count=6)
    seed_windows(engine, device_key=other_key, count=6)

    client.post(f"{BASELINES_URL}/{DEVICE_KEY}/reset")

    remaining = client.get(BASELINES_URL).json()["data"]
    assert remaining["total"] == 1
    assert remaining["baselines"][0]["device_key"] == other_key


# ---------------------------------------------------------------------------
# What the surface must never expose
# ---------------------------------------------------------------------------


def _field_names(value: object) -> set[str]:
    """Collect every object key anywhere in a decoded JSON document.

    The assertions below are about the *shape* of a response, not about prose. A
    disclaimer is free to say the word "verdict" — it says a baseline is not one
    — while a field named ``verdict`` would be the thing M21.2 forbids. Walking
    the keys keeps those two facts apart.
    """
    names: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            names.add(str(key).lower())
            names |= _field_names(child)
    elif isinstance(value, list):
        for child in value:
            names |= _field_names(child)
    return names


def test_no_response_carries_a_score_or_a_verdict(
    client: TestClient, engine: BaselineEngine
) -> None:
    """M21 learns and describes; it never scores or classifies (M21.2).

    Asserted on the field names the API publishes rather than on a model or on
    raw body text, because the guarantee is about what a client can read as data.
    Substring matching would be wrong here: the disclaimer says a baseline is
    "not an anomaly verdict", so the *word* legitimately appears while no field
    carries a judgement.
    """
    seed_windows(engine, count=12)
    body = [
        client.get(BASELINES_URL).json(),
        client.get(f"{BASELINES_URL}/{DEVICE_KEY}").json(),
    ]
    fields = set().union(*(_field_names(document) for document in body))

    for forbidden in (
        "risk_score",
        "anomaly_score",
        "severity",
        "confidence",
        "suspicious",
        "verdict",
        "score",
        "alert",
        "incident",
    ):
        assert forbidden not in fields, forbidden


def test_no_response_carries_a_peer_address_or_a_port(
    client: TestClient, engine: BaselineEngine
) -> None:
    """A profile reports cardinalities, never the addresses behind them (M21.8).

    The seeded packets all target ``10.0.0.1:443``, so either value appearing in
    a body would mean an address or a port had leaked into a response.
    """
    seed_windows(engine, count=6)
    text = client.get(f"{BASELINES_URL}/{DEVICE_KEY}").text

    assert "10.0.0.1" not in text
    assert "443" not in text
