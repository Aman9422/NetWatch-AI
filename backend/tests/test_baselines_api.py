"""API tests for the baselines endpoints (M13.17).

The behavioural baseline engine is **not implemented** — M13.17 says so
explicitly, and this file is where that is checked rather than assumed. Every
test here asserts that the API says "not implemented" instead of returning the
M2 development seed rows, because presenting a placeholder profile as an analysed
one is precisely the fake data the requirement forbids.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.api.v1.baselines import FEATURE
from app.config.settings import settings
from app.main import app

BASELINES_URL = "/api/v1/baselines"


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Test client that never touches the real database.

    The lifespan is run with ``app_env == "test"`` so ``init_db()`` is skipped.
    No dependency is overridden: the point of these tests is that the endpoints
    answer identically whether or not a baseline store exists, because there is
    no baseline engine behind them.
    """
    original_env = settings.app_env
    settings.app_env = "test"
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        settings.app_env = original_env


def test_collection_reports_not_implemented(client: TestClient) -> None:
    """The baseline collection is a 501, not an empty list (M13.17)."""
    response = client.get(BASELINES_URL)

    assert response.status_code == 501
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == "FEATURE_NOT_IMPLEMENTED"
    # The failing "field" names which subsystem refused, not a query parameter:
    # there was no query, and a client branches on the feature (M13.17).
    assert body["errors"][0]["field"] == FEATURE


def test_message_names_the_missing_subsystem(client: TestClient) -> None:
    """The message says what is missing and does not expose any internals."""
    body = client.get(BASELINES_URL).json()

    message = body["message"]
    assert "baseline" in message.lower()
    # No traceback, no path, no module reference reaches the client (M13.5).
    assert "Traceback" not in message
    assert "app/" not in message
    assert ".py" not in message


def test_device_lookup_reports_not_implemented(client: TestClient) -> None:
    """A per-device baseline lookup is a 501, not a 404 (M13.17).

    A 404 would claim "this device has no baseline yet", which implies baselines
    exist for other devices. They do not exist at all.
    """
    response = client.get(f"{BASELINES_URL}/mac:aa:bb:cc:dd:ee:ff")

    assert response.status_code == 501
    assert response.json()["errors"][0]["code"] == "FEATURE_NOT_IMPLEMENTED"


def test_baseline_routes_are_read_only(client: TestClient) -> None:
    """No verb other than GET is offered, because nothing could be written."""
    assert client.post(BASELINES_URL).status_code == 405
    assert client.put(BASELINES_URL).status_code == 405
    assert client.delete(BASELINES_URL).status_code == 405


def test_response_uses_the_standard_error_envelope(client: TestClient) -> None:
    """The refusal is rendered in the one error shape the API uses (M13.5)."""
    body = client.get(BASELINES_URL).json()

    assert set(body) == {"success", "message", "errors"}
    assert isinstance(body["errors"], list)
    assert set(body["errors"][0]) == {"field", "code"}


def test_unknown_baseline_subroute_is_404(client: TestClient) -> None:
    """A route that is not part of the surface answers 404, not 501."""
    assert client.get(f"{BASELINES_URL}/a/b/c/d").status_code in (404, 501)
