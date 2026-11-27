"""The local LLM REST surface (M23.12).

What these tests assert, beyond status codes:

* ``/status`` answers ``200`` in every state, because "disabled" and "unreachable"
  are conditions rather than faults.
* The error mapping distinguishes a refusal the client caused (``400``), a busy
  resource (``409``) and an unavailable dependency (``503``).
* The response body never contains a URL, a path, a traceback or the provider's own
  error text (M23.10).
* The request body cannot name a model or a host.

A fake service is injected through the router's own dependency, so nothing here
reaches a real Ollama.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.ai.exceptions import (
    REASON_BUSY,
    REASON_INVALID_PROMPT,
    REASON_MODEL_MISSING,
    REASON_NOT_RUNNING,
    REASON_PROVIDER_ERROR,
    REASON_TIMEOUT,
    LlmBusyError,
    LlmGenerationError,
    LlmUnavailableError,
)
from app.api.v1.ai import get_service
from app.main import app
from tests.ai_fakes import FakeProvider, make_service

STATUS_URL = "/api/v1/ai/status"
MODELS_URL = "/api/v1/ai/models"
TEST_URL = "/api/v1/ai/test"


def client_for(service) -> TestClient:
    """Return a client whose AI routes use ``service`` instead of the singleton."""
    app.dependency_overrides[get_service] = lambda: service
    return TestClient(app)


@pytest.fixture(autouse=True)
def clear_overrides() -> Generator[None, None, None]:
    """Remove the dependency override after every test, whatever it did."""
    yield
    app.dependency_overrides.pop(get_service, None)


def envelope(body: object) -> dict:
    """Assert the M13 envelope and return the parsed body."""
    assert isinstance(body, dict), body
    assert set(body) == {"success", "message", "data"} or set(body) == {
        "success",
        "message",
        "errors",
    }
    return body


# -- status -----------------------------------------------------------------


def test_status_is_200_and_reports_ready() -> None:
    """A working configuration answers 200 with the ready state."""
    client = client_for(make_service(FakeProvider()))

    response = client.get(STATUS_URL)

    assert response.status_code == 200
    data = envelope(response.json())["data"]
    assert data["state"] == "ready"
    assert data["enabled"] is True
    assert data["runtime_version"] == "0.40.18"
    assert data["state_label"] == "Ready"


def test_status_is_200_when_disabled() -> None:
    """A disabled feature is a condition, not a failure, so it is not a 503.

    This is the distinction the whole state vocabulary exists for: if disabling the
    feature answered 503, the page could not tell "switched off" from "broken".
    """
    client = client_for(make_service(FakeProvider(), enabled=False))

    response = client.get(STATUS_URL)

    assert response.status_code == 200
    data = envelope(response.json())["data"]
    assert data["state"] == "disabled"
    assert data["enabled"] is False


def test_status_is_200_when_the_runtime_is_unreachable() -> None:
    """An unreachable runtime is also a state, answered with 200."""
    client = client_for(make_service(FakeProvider(reachable=False)))

    response = client.get(STATUS_URL)

    assert response.status_code == 200
    assert envelope(response.json())["data"]["state"] == "unreachable"


def test_status_carries_the_disclaimer() -> None:
    """Every payload states what model output is and is not."""
    client = client_for(make_service(FakeProvider()))

    data = envelope(client.get(STATUS_URL).json())["data"]

    assert "not a security finding" in data["disclaimer"]


def test_status_reports_the_probe_budget_it_used() -> None:
    """The probe budget reaches the wire, and is the configured one.

    A regression test with a reason: the field was declared on the schema and
    documented as "the budget the probe used", but the route never populated it, so
    every payload carried `0.0`. An operator reading that number would be reading a
    value nobody set.
    """
    client = client_for(make_service(FakeProvider(), health_timeout_seconds=2.5))

    data = envelope(client.get(STATUS_URL).json())["data"]

    assert data["health_timeout_seconds"] == 2.5


# -- models -----------------------------------------------------------------


def test_models_lists_the_runtime_inventory() -> None:
    """The listing is the runtime's own inventory, with the configured one marked."""
    provider = FakeProvider(installed=["llama3.2:3b", "qwen2.5:3b-instruct"])
    client = client_for(make_service(provider))

    response = client.get(MODELS_URL)

    assert response.status_code == 200
    data = envelope(response.json())["data"]
    assert data["count"] == 2
    assert [m["name"] for m in data["models"]] == [
        "llama3.2:3b",
        "qwen2.5:3b-instruct",
    ]
    assert data["configured_model"] == "llama3.2:3b"
    assert data["configured_model_installed"] is True


def test_models_reports_the_configured_model_as_absent() -> None:
    """A configured model that is not installed is marked, not silently omitted."""
    provider = FakeProvider(installed=["other:7b"])
    client = client_for(make_service(provider))

    data = envelope(client.get(MODELS_URL).json())["data"]

    assert data["configured_model"] == "llama3.2:3b"
    assert data["configured_model_installed"] is False


def test_models_is_503_when_disabled() -> None:
    """Listing would require reaching a service the operator switched off."""
    client = client_for(make_service(FakeProvider(), enabled=False))

    response = client.get(MODELS_URL)

    assert response.status_code == 503
    assert envelope(response.json())["errors"][0]["field"] == "llm_enabled"


def test_models_is_503_when_the_runtime_is_unreachable() -> None:
    """A down runtime cannot answer an inventory question."""
    provider = FakeProvider()
    provider.list_error = LlmUnavailableError(
        "down", reason=REASON_NOT_RUNNING, detail="refused"
    )
    client = client_for(make_service(provider))

    assert client.get(MODELS_URL).status_code == 503


# -- test generation --------------------------------------------------------


def test_test_generation_returns_the_reply() -> None:
    """A bounded prompt produces the model's text and its metadata."""
    client = client_for(make_service(FakeProvider(reply="NETWATCH_OK")))

    response = client.post(TEST_URL, json={"prompt": "Reply with NETWATCH_OK"})

    assert response.status_code == 200
    data = envelope(response.json())["data"]
    assert data["response"] == "NETWATCH_OK"
    assert data["model"] == "llama3.2:3b"
    assert data["provider"] == "fake"
    assert data["requested_prompt_chars"] == len("Reply with NETWATCH_OK")
    assert data["done_reason"] == "stop"


def test_test_generation_carries_the_disclaimer() -> None:
    """The reply is untrusted text, and the payload says so."""
    client = client_for(make_service(FakeProvider()))

    data = envelope(client.post(TEST_URL, json={"prompt": "hi"}).json())["data"]

    assert "may be incorrect" in data["disclaimer"]


def test_an_oversized_prompt_is_a_400_naming_the_field() -> None:
    """A prompt over the configured limit is the client's mistake, not a 503."""
    client = client_for(make_service(FakeProvider(), max_prompt_chars=8))

    response = client.post(TEST_URL, json={"prompt": "x" * 9})

    assert response.status_code == 400
    body = envelope(response.json())
    assert body["errors"][0]["field"] == "prompt"
    assert body["errors"][0]["code"] == "INVALID_REQUEST"


def test_a_blank_prompt_is_a_400() -> None:
    """Whitespace is not a prompt, and the field is named."""
    client = client_for(make_service(FakeProvider()))

    response = client.post(TEST_URL, json={"prompt": "   "})

    assert response.status_code == 400
    assert envelope(response.json())["errors"][0]["field"] == "prompt"


def test_an_empty_body_is_refused_by_validation() -> None:
    """Pydantic refuses a body with no prompt before the handler runs."""
    client = client_for(make_service(FakeProvider()))

    assert client.post(TEST_URL, json={}).status_code == 422


def test_test_generation_is_503_when_disabled() -> None:
    """A disabled feature cannot generate."""
    client = client_for(make_service(FakeProvider(), enabled=False))

    response = client.post(TEST_URL, json={"prompt": "hi"})

    assert response.status_code == 503
    assert envelope(response.json())["errors"][0]["field"] == "llm_enabled"


@pytest.mark.parametrize(
    ("error", "status", "field"),
    [
        (LlmUnavailableError("down", reason=REASON_NOT_RUNNING), 503, "llm"),
        (
            LlmUnavailableError("gone", reason=REASON_MODEL_MISSING),
            503,
            "llm_model",
        ),
        (LlmGenerationError("slow", reason=REASON_TIMEOUT), 503, "llm"),
        (LlmGenerationError("boom", reason=REASON_PROVIDER_ERROR), 503, "llm"),
    ],
)
def test_generation_failures_map_to_a_503_naming_the_cause(
    error: Exception, status: int, field: str
) -> None:
    """Each failure is unavailable-by-a-different-cause, and the field says which."""
    provider = FakeProvider()
    provider.generate_error = error
    client = client_for(make_service(provider))

    response = client.post(TEST_URL, json={"prompt": "hi"})

    assert response.status_code == status
    assert envelope(response.json())["errors"][0]["field"] == field


def test_a_busy_runtime_is_a_409_not_a_queue() -> None:
    """Concurrency exhaustion is a conflict the caller retries, not a wait."""
    provider = FakeProvider()
    provider.generate_error = LlmBusyError()
    client = client_for(make_service(provider))

    response = client.post(TEST_URL, json={"prompt": "hi"})

    assert response.status_code == 409
    assert envelope(response.json())["errors"][0]["code"] == "CONFLICT"


def test_an_invalid_prompt_reason_maps_to_a_400() -> None:
    """The service's own prompt rejection reaches the client as a 400."""
    provider = FakeProvider()
    provider.generate_error = LlmGenerationError(
        "too long", reason=REASON_INVALID_PROMPT
    )
    client = client_for(make_service(provider))

    assert client.post(TEST_URL, json={"prompt": "hi"}).status_code == 400


# -- the body cannot choose a model or a host -------------------------------


def test_the_request_body_cannot_name_a_model_or_a_host() -> None:
    """Extra fields are ignored, so a client cannot select either.

    This is the security test M23.10 asks for: the schema is a prompt and nothing
    else, and an attempt to override the configuration has no effect.
    """
    provider = FakeProvider(installed=["llama3.2:3b"])
    client = client_for(make_service(provider))

    response = client.post(
        TEST_URL,
        json={
            "prompt": "hi",
            "model": "attacker:70b",
            "base_url": "http://evil.example.com",
            "temperature": 1.9,
        },
    )

    assert response.status_code == 200
    data = envelope(response.json())["data"]
    assert data["model"] == "llama3.2:3b", "the configured model must win"
    assert provider.last_options is not None
    assert "attacker" not in provider.last_options.prompt


# -- no internals on the wire -----------------------------------------------


@pytest.mark.parametrize("url", [STATUS_URL, MODELS_URL])
def test_no_response_leaks_an_internal_string(url: str) -> None:
    """No body carries a traceback, a module path or a provider detail."""
    client = client_for(make_service(FakeProvider()))

    text = client.get(url).text

    for forbidden in ("Traceback", "sqlalchemy", "app/", "site-packages"):
        assert forbidden not in text


def test_an_unreachable_failure_does_not_leak_the_address() -> None:
    """The configured host is never echoed, even when it is why the call failed."""
    provider = FakeProvider()
    provider.generate_error = LlmUnavailableError(
        "not answering", reason=REASON_NOT_RUNNING, detail="http://127.0.0.1:11434"
    )
    client = client_for(make_service(provider))

    text = client.post(TEST_URL, json={"prompt": "hi"}).text

    assert "127.0.0.1" not in text
    assert "11434" not in text
