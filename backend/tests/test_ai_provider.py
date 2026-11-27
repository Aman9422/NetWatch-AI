"""The Ollama adapter, exercised without a running Ollama (M23.12).

These tests drive ``OllamaProvider`` against a stubbed ``httpx`` transport. What
they prove is the adapter's *translation*: a 404 becomes ``model_missing``, a
timeout becomes ``unreachable``, a malformed body becomes ``invalid_response``, and
the request it builds carries the pinned options rather than anything a caller
supplied.

What they do **not** prove is that a real Ollama answers this way. That is
``test_ai_live.py``, and M23.13 is explicit that one may not stand in for the other.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.ai.exceptions import (
    REASON_INVALID_RESPONSE,
    REASON_MODEL_MISSING,
    REASON_NOT_RUNNING,
    REASON_PROVIDER_ERROR,
    LlmGenerationError,
    LlmUnavailableError,
)
from app.ai.providers.base import GenerationOptions
from app.ai.providers.ollama import OllamaProvider

BASE_URL = "http://127.0.0.1:11434"


def provider_with(handler) -> OllamaProvider:
    """Return an adapter whose HTTP layer is ``handler``.

    The client is replaced rather than mocked at the method level, so these tests
    exercise the adapter's own request construction, status handling and error
    translation — the code that would actually break.
    """
    provider = OllamaProvider(
        base_url=BASE_URL, model="llama3.2:3b", num_ctx=4096, keep_alive="5m"
    )
    provider._client = httpx.Client(  # noqa: SLF001 - the seam under test
        base_url=BASE_URL, transport=httpx.MockTransport(handler)
    )
    return provider


def json_response(payload: object, status: int = 200) -> httpx.Response:
    """Return a JSON ``httpx.Response``."""
    return httpx.Response(
        status,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


# -- health -----------------------------------------------------------------


def test_health_reports_reachable_with_version_and_count() -> None:
    """A live runtime reports its version and how many models it has."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return json_response({"version": "0.40.18"})
        return json_response({"models": [{"name": "llama3.2:3b"}, {"name": "x:1b"}]})

    health = provider_with(handler).check_health(timeout_seconds=3.0)

    assert health.reachable is True
    assert health.version == "0.40.18"
    assert health.model_count == 2


def test_health_never_raises_when_the_host_is_down() -> None:
    """A down runtime is a state, not an exception — the interface requires it."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    assert provider_with(handler).check_health(timeout_seconds=3.0).reachable is False


def test_health_stays_reachable_when_only_the_inventory_fails() -> None:
    """A service answering one endpoint and refusing another is still up."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return json_response({"version": "0.40.18"})
        return httpx.Response(500, content=b"nope")

    health = provider_with(handler).check_health(timeout_seconds=3.0)

    assert health.reachable is True
    assert health.version == "0.40.18"
    assert health.model_count == 0


# -- models -----------------------------------------------------------------


def test_list_models_projects_the_runtime_inventory() -> None:
    """The inventory is reported as the runtime describes it, nothing curated."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            {
                "models": [
                    {
                        "name": "llama3.2:3b",
                        "size": 2_019_393_189,
                        "details": {
                            "parameter_size": "3.2B",
                            "quantization_level": "Q4_K_M",
                            "family": "llama",
                        },
                    }
                ]
            }
        )

    models = provider_with(handler).list_models(timeout_seconds=3.0)

    assert len(models) == 1
    assert models[0].name == "llama3.2:3b"
    assert models[0].parameter_size == "3.2B"
    assert models[0].quantization == "Q4_K_M"
    assert models[0].size_bytes == 2_019_393_189


def test_list_models_tolerates_a_missing_details_block() -> None:
    """A runtime that omits a detail field must not make the inventory unreadable."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"models": [{"name": "bare:1b"}]})

    models = provider_with(handler).list_models(timeout_seconds=3.0)

    assert [model.name for model in models] == ["bare:1b"]
    assert models[0].parameter_size == ""


def test_list_models_skips_an_entry_without_a_name() -> None:
    """A malformed entry is dropped rather than failing the whole listing."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"models": [{"name": "ok:1b"}, {"size": 10}]})

    listed = provider_with(handler).list_models(timeout_seconds=3.0)
    assert [m.name for m in listed] == ["ok:1b"]


def test_list_models_treats_a_connection_failure_as_unreachable() -> None:
    """No answer means unreachable, which is what an operator acts on."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(LlmUnavailableError) as caught:
        provider_with(handler).list_models(timeout_seconds=3.0)

    assert caught.value.reason == REASON_NOT_RUNNING


def test_list_models_treats_a_non_json_body_as_invalid() -> None:
    """A 200 carrying HTML is not a model list, and saying so is more useful."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not ollama</html>")

    with pytest.raises(LlmGenerationError) as caught:
        provider_with(handler).list_models(timeout_seconds=3.0)

    assert caught.value.reason == REASON_INVALID_RESPONSE


# -- model availability -----------------------------------------------------


def test_model_available_matches_a_tagless_request() -> None:
    """``llama3.2`` finds the installed ``llama3.2:3b``."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"models": [{"name": "llama3.2:3b"}]})

    assert provider_with(handler).model_available("llama3.2", timeout_seconds=3.0)


def test_model_available_is_false_for_an_absent_model() -> None:
    """An installed runtime without the model answers False, not an error."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"models": [{"name": "other:1b"}]})

    provider = provider_with(handler)
    assert not provider.model_available("llama3.2:3b", timeout_seconds=3.0)


def test_model_available_is_false_for_a_blank_name() -> None:
    """A blank model name cannot match anything, and is answered without a request."""
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return json_response({"models": []})

    assert not provider_with(handler).model_available("  ", timeout_seconds=3.0)
    assert asked == []
