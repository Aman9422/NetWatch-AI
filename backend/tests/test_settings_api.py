"""API tests for the settings endpoints (M13.21).

The settings surface has to do three things at once, and each is checked here:
read stored values back *decoded* rather than as the raw text the column holds,
accept changes only for the keys it declares mutable, and never let an
internal-only key or its value cross the HTTP boundary (M13.21/M13.30).

The rows are written through the same in-memory engine the application reads
through, so a test exercises the real repository and the real policy rather than
a stub of either.
"""

from __future__ import annotations

from collections.abc import Generator, Mapping
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.v1.settings import MUTABLE_KEYS
from app.database.session import get_db
from app.models.setting import Setting
from tests.m13_fakes import api_client, make_db_override

SETTINGS_URL = "/api/v1/settings"

#: A value distinctive enough that finding it in a response is unambiguous.
SECRET_VALUE = "hunter2-not-for-export"

#: Keys that must never be listed or read, by the marker rule (M13.21).
SECRET_KEYS = ("db_password", "api_token", "encryption_key", "connection_dsn")


@pytest.fixture
def client(db_engine) -> Generator[TestClient, None, None]:
    """A client reading the isolated in-memory database, not the real one."""
    with api_client({get_db: make_db_override(db_engine)}) as test_client:
        yield test_client


def store(
    session: Session,
    key: str,
    value: str,
    data_type: str = "string",
) -> None:
    """Write one settings row as the application would read it."""
    session.add(
        Setting(setting_key=key, setting_value=value, data_type=data_type)
    )
    session.commit()


def only(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return the single setting in a listing, asserting there is exactly one."""
    assert data["count"] == 1, data
    return data["settings"][0]


# ---------------------------------------------------------------------------
# GET /settings
# ---------------------------------------------------------------------------


def test_empty_listing_is_well_formed(client: TestClient) -> None:
    """An empty table returns an empty collection and the mutable key list."""
    body = client.get(SETTINGS_URL).json()

    assert body["success"] is True
    data = body["data"]
    assert data["count"] == 0
    assert data["settings"] == []
    assert data["internal_key_count"] == 0
    assert data["mutable_keys"] == sorted(MUTABLE_KEYS)


def test_listing_uses_the_standard_envelope(client: TestClient) -> None:
    """The response carries the one success shape the API uses (M13.4)."""
    assert set(client.get(SETTINGS_URL).json()) == {"success", "message", "data"}


def test_listing_returns_readable_keys_in_order(
    client: TestClient, db_session: Session
) -> None:
    """Readable settings come back ordered by key, so the order is stable."""
    store(db_session, "zebra", "last")
    store(db_session, "alpha", "first")

    keys = [
        setting["key"]
        for setting in client.get(SETTINGS_URL).json()["data"]["settings"]
    ]

    assert keys == ["alpha", "zebra"]


def test_listing_decodes_each_value_by_its_type(
    client: TestClient, db_session: Session
) -> None:
    """A value is handed over decoded, not as the text the column holds.

    A client asking for ``packet_retention_days`` must receive ``30``, not
    ``"30"``: the column's text form is a storage detail (M13.21).
    """
    store(db_session, "packet_retention_days", "30", "int")
    store(db_session, "alert_threshold", "75", "int")
    store(db_session, "ai_enabled", "true", "bool")

    by_key = {
        setting["key"]: setting
        for setting in client.get(SETTINGS_URL).json()["data"]["settings"]
    }

    assert by_key["packet_retention_days"]["value"] == 30
    assert by_key["alert_threshold"]["value"] == 75
    assert by_key["ai_enabled"]["value"] is True
    assert by_key["packet_retention_days"]["data_type"] == "int"


def test_listing_marks_only_declared_keys_mutable(
    client: TestClient, db_session: Session
) -> None:
    """``mutable`` reflects the declaration, not the row's type (M13.21)."""
    store(db_session, "default_theme", "light")
    store(db_session, "some_internal_note", "x")

    by_key = {
        setting["key"]: setting
        for setting in client.get(SETTINGS_URL).json()["data"]["settings"]
    }

    assert by_key["default_theme"]["mutable"] is True
    assert by_key["some_internal_note"]["mutable"] is False


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_listing_withholds_internal_only_keys(
    client: TestClient, db_session: Session, key: str
) -> None:
    """A key matching the denylist is never listed, and is counted instead."""
    store(db_session, "default_theme", "light")
    store(db_session, key, SECRET_VALUE)

    body = client.get(SETTINGS_URL).json()
    data = body["data"]

    assert data["count"] == 1
    assert [setting["key"] for setting in data["settings"]] == ["default_theme"]
    assert data["internal_key_count"] == 1
    # The key's *name* is withheld too: naming it would confirm it is stored.
    assert key not in client.get(SETTINGS_URL).text
    assert SECRET_VALUE not in client.get(SETTINGS_URL).text


# ---------------------------------------------------------------------------
# GET /settings/{setting_key}
# ---------------------------------------------------------------------------


def test_single_read_returns_the_setting(
    client: TestClient, db_session: Session
) -> None:
    """A known key resolves to its decoded value and metadata."""
    store(db_session, "default_theme", "dark")

    body = client.get(f"{SETTINGS_URL}/default_theme").json()

    assert body["success"] is True
    assert body["data"]["key"] == "default_theme"
    assert body["data"]["value"] == "dark"
    assert body["data"]["mutable"] is True
    assert body["data"]["updated_at"].endswith("+00:00")


def test_unknown_key_is_404(client: TestClient) -> None:
    """An absent key returns the standard not-found envelope (M13.21)."""
    response = client.get(f"{SETTINGS_URL}/never_stored")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [
        {"field": "setting_key", "code": "SETTING_NOT_FOUND"}
    ]


@pytest.mark.parametrize("key", SECRET_KEYS)
def test_internal_only_key_reads_exactly_like_an_unknown_one(
    client: TestClient, db_session: Session, key: str
) -> None:
    """A secret key answers 404, not 403, so its existence is not confirmed.

    Distinguishing "stored but hidden" from "not stored" would tell a caller
    that a credential lives under that name, which is the leak this rule
    exists to prevent (M13.30).
    """
    store(db_session, key, SECRET_VALUE)

    response = client.get(f"{SETTINGS_URL}/{key}")

    assert response.status_code == 404
    assert response.json()["errors"][0]["code"] == "SETTING_NOT_FOUND"
    assert SECRET_VALUE not in response.text


# ---------------------------------------------------------------------------
# PUT /settings
# ---------------------------------------------------------------------------


def test_update_stores_and_echoes_the_change(client: TestClient) -> None:
    """A valid change is persisted and read back, not merely acknowledged."""
    response = client.put(
        SETTINGS_URL, json={"values": {"default_theme": "dark"}}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["restart_required"] is True
    updated = only({"count": len(body["data"]["updated"]), "settings": body["data"]["updated"]})
    assert updated["key"] == "default_theme"
    assert updated["value"] == "dark"
    # Read back through a second request, so the store really holds it.
    assert client.get(f"{SETTINGS_URL}/default_theme").json()["data"]["value"] == "dark"


def test_update_states_that_a_restart_is_required(client: TestClient) -> None:
    """Stored settings are applied at startup, and the payload says so (M13.21).

    A client that assumed the change took effect immediately would believe a
    running service had been reconfigured when it had not.
    """
    body = client.put(
        SETTINGS_URL, json={"values": {"default_theme": "light"}}
    ).json()

    assert body["data"]["restart_required"] is True


def test_update_stores_typed_values(client: TestClient) -> None:
    """Each key is stored the way its own declaration says (M13.21)."""
    client.put(
        SETTINGS_URL,
        json={
            "values": {
                "packet_retention_days": 30,
                "ai_enabled": False,
                "capture_interface": "Wi-Fi",
            }
        },
    )

    assert client.get(f"{SETTINGS_URL}/packet_retention_days").json()["data"]["value"] == 30
    assert client.get(f"{SETTINGS_URL}/ai_enabled").json()["data"]["value"] is False
    assert client.get(f"{SETTINGS_URL}/capture_interface").json()["data"]["value"] == "Wi-Fi"


def test_update_rejects_a_value_outside_its_constraint(client: TestClient) -> None:
    """A value that fails its declared constraint names the key that failed."""
    response = client.put(SETTINGS_URL, json={"values": {"default_theme": "neon"}})

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"field": "default_theme", "code": "INVALID_SETTING"}]


def test_update_rejects_a_wrongly_typed_value(client: TestClient) -> None:
    """Types are checked, so an integer key will not accept a word."""
    response = client.put(
        SETTINGS_URL, json={"values": {"packet_retention_days": "many"}}
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "packet_retention_days"


def test_update_rejects_a_bool_where_an_int_belongs(client: TestClient) -> None:
    """A boolean is not an integer here, despite Python's subclassing.

    ``True`` would otherwise satisfy an integer constraint as ``1``, which is
    exactly the silent coercion M13.25 forbids.
    """
    response = client.put(
        SETTINGS_URL, json={"values": {"packet_retention_days": True}}
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["field"] == "packet_retention_days"


def test_update_rejects_an_unknown_key(client: TestClient) -> None:
    """A key the application never heard of is a 400, not a silent skip."""
    response = client.put(
        SETTINGS_URL, json={"values": {"not_a_real_setting": "x"}}
    )

    assert response.status_code == 400
    assert response.json()["errors"] == [
        {"field": "not_a_real_setting", "code": "INVALID_SETTING"}
    ]


def test_update_rejects_a_read_only_stored_key(
    client: TestClient, db_session: Session
) -> None:
    """A stored but immutable key is a 409, not the 400 an unknown key gets.

    The two are different facts: one means "that key is real and I will not
    change it", the other "I have never heard of it" (M13.21/M13.25).
    """
    store(db_session, "app_name", "NetWatch AI")

    response = client.put(SETTINGS_URL, json={"values": {"app_name": "Other"}})

    assert response.status_code == 409
    assert response.json()["errors"] == [
        {"field": "app_name", "code": "IMMUTABLE_SETTING"}
    ]


def test_update_rejects_an_empty_request(client: TestClient) -> None:
    """A request naming nothing is a 400 rather than a no-op success."""
    response = client.put(SETTINGS_URL, json={"values": {}})

    assert response.status_code == 400
    assert response.json()["errors"] == [{"field": "values", "code": "INVALID_SETTING"}]


def test_update_applies_all_or_nothing(client: TestClient) -> None:
    """One bad key in a batch changes nothing, so no half-applied state exists.

    A partial write would leave the client unable to tell which half took
    effect (M13.21).
    """
    response = client.put(
        SETTINGS_URL,
        json={"values": {"default_theme": "dark", "packet_retention_days": "many"}},
    )

    assert response.status_code == 400
    assert client.get(f"{SETTINGS_URL}/default_theme").status_code == 404


def test_update_rejects_a_secret_named_key_without_echoing_a_value(
    client: TestClient,
) -> None:
    """A credential cannot be written through this API (M13.30).

    The failure is the same one an unknown key gets, so the response does not
    confirm that the name is special — and the submitted value is never echoed
    back.
    """
    response = client.put(
        SETTINGS_URL, json={"values": {"db_password": SECRET_VALUE}}
    )

    assert response.status_code == 400
    assert response.json()["errors"][0]["code"] == "INVALID_SETTING"
    assert SECRET_VALUE not in response.text


# ---------------------------------------------------------------------------
# Read-only surface
# ---------------------------------------------------------------------------


def test_collection_rejects_unsupported_verbs(client: TestClient) -> None:
    """Settings are read with GET and changed with PUT, and nothing else."""
    assert client.post(SETTINGS_URL).status_code == 405
    assert client.delete(SETTINGS_URL).status_code == 405
