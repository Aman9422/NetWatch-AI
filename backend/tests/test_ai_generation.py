"""Generation behaviour of the Ollama adapter (M23.12).

Split from ``test_ai_provider.py`` so one file covers the read surface and this one
covers the write. Both use a stubbed transport and neither claims to prove live
behaviour - ``test_ai_live.py`` does that.
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
    """Return an adapter whose HTTP layer is ``handler``."""
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


def options(prompt: str = "hi", max_output_tokens: int = 8) -> GenerationOptions:
    """Return generation options for a test."""
    return GenerationOptions(prompt=prompt, max_output_tokens=max_output_tokens)


def test_generate_returns_the_reply_and_its_metadata() -> None:
    """A completed generation carries the text and what the runtime measured."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            {
                "model": "llama3.2:3b",
                "response": "  NETWATCH_OK",
                "done_reason": "stop",
                "prompt_eval_count": 32,
                "eval_count": 4,
                "total_duration": 274_000_000,
            }
        )

    generation = provider_with(handler).generate(options(), timeout_seconds=60.0)

    assert generation.text == "  NETWATCH_OK"
    assert generation.model == "llama3.2:3b"
    assert generation.prompt_tokens == 32
    assert generation.output_tokens == 4
    assert generation.done_reason == "stop"
    assert generation.total_ms == pytest.approx(274.0)


def test_generate_pins_the_context_and_output_budget() -> None:
    """``num_ctx`` and ``num_predict`` are sent, not left to the runtime default.

    An unpinned context would size the KV cache from the model's advertised
    131,072 tokens, which exceeds 4 GB of VRAM.
    """
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return json_response({"model": "llama3.2:3b", "response": "ok"})

    provider_with(handler).generate(
        options(max_output_tokens=64), timeout_seconds=60.0
    )

    assert captured["model"] == "llama3.2:3b"
    assert captured["stream"] is False
    assert captured["keep_alive"] == "5m"
    sent = captured["options"]
    assert isinstance(sent, dict)
    assert sent["num_ctx"] == 4096
    assert sent["num_predict"] == 64


def test_generate_reports_a_missing_model_as_model_missing() -> None:
    """A 404 means the model is absent, a different fix from starting the service."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"error": "model 'nope:1b' not found"}, status=404)

    with pytest.raises(LlmUnavailableError) as caught:
        provider_with(handler).generate(options(), timeout_seconds=60.0)

    assert caught.value.reason == REASON_MODEL_MISSING


def test_generate_maps_a_server_error_to_a_provider_error() -> None:
    """A 500 is the runtime failing, not the model missing."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"boom")

    with pytest.raises(LlmGenerationError) as caught:
        provider_with(handler).generate(options(), timeout_seconds=60.0)

    assert caught.value.reason == REASON_PROVIDER_ERROR


def test_generate_maps_a_timeout_to_unreachable() -> None:
    """A host that never answers is unreachable, which is what a timeout means."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    with pytest.raises(LlmUnavailableError) as caught:
        provider_with(handler).generate(options(), timeout_seconds=1.0)

    assert caught.value.reason == REASON_NOT_RUNNING


def test_generate_treats_an_error_field_in_a_200_as_a_failure() -> None:
    """Ollama reports some failures as a 200 carrying ``error``; that is not success."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"error": "out of memory"})

    with pytest.raises(LlmGenerationError) as caught:
        provider_with(handler).generate(options(), timeout_seconds=60.0)

    assert caught.value.reason == REASON_PROVIDER_ERROR


def test_generate_rejects_a_body_without_text() -> None:
    """A 200 with no ``response`` field is an unusable answer, not an empty one."""

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"model": "llama3.2:3b"})

    with pytest.raises(LlmGenerationError) as caught:
        provider_with(handler).generate(options(), timeout_seconds=60.0)

    assert caught.value.reason == REASON_INVALID_RESPONSE


def test_generate_without_a_configured_model_is_refused_before_the_network() -> None:
    """A blank model is a configuration fault, caught without a request."""
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return json_response({"response": "should not happen"})

    provider = OllamaProvider(base_url=BASE_URL, model="")
    provider._client = httpx.Client(  # noqa: SLF001
        base_url=BASE_URL, transport=httpx.MockTransport(handler)
    )

    with pytest.raises(LlmUnavailableError) as caught:
        provider.generate(options(), timeout_seconds=60.0)

    assert caught.value.reason == REASON_MODEL_MISSING
    assert asked == []


def test_no_error_message_leaks_the_base_url_or_the_provider_body() -> None:
    """Every failure message is written here, never echoed by the runtime.

    The provider body is captured in ``detail`` for the log and must not appear in
    ``message``, which is the text that reaches a client.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return json_response({"error": "model 'secret-model' not found"}, status=404)

    with pytest.raises(LlmUnavailableError) as caught:
        provider_with(handler).generate(options(), timeout_seconds=60.0)

    assert BASE_URL not in caught.value.message
    assert "127.0.0.1" not in caught.value.message
    assert "secret-model" not in caught.value.message
