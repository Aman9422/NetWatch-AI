"""Shared fakes for the M23 local-LLM suite (M23.12).

The provider interface is small enough that a fake is a few dozen lines, which is
why every AI test drives one rather than reaching for a mocking library. A fake
that implements the real interface also fails to type-check when the interface
changes — an argument ``Mock`` never makes.

**What a fake proves, and what it does not.** It proves the *service* reacts
correctly to each runtime behaviour: a down runtime becomes ``unreachable``, a
missing model becomes ``model_missing``, a slow generation becomes a timeout. It
does **not** prove Ollama behaves that way; that is what ``test_ai_live.py`` is
for, and the two are never conflated (M23.13).
"""

from __future__ import annotations

from typing import Any

from app.ai.exceptions import (
    REASON_MODEL_MISSING,
    REASON_NOT_RUNNING,
    REASON_PROVIDER_ERROR,
    REASON_TIMEOUT,
    LlmGenerationError,
    LlmUnavailableError,
)
from app.ai.providers.base import (
    GenerationOptions,
    LlmProvider,
    ProviderGeneration,
    ProviderHealth,
    ProviderModel,
)


class FakeProvider(LlmProvider):
    """A provider whose every behaviour is decided by its attributes."""

    name = "fake"

    def __init__(
        self,
        *,
        reachable: bool = True,
        version: str = "0.40.18",
        installed: list[str] | None = None,
        reply: str = "NETWATCH_TEST_OK",
    ) -> None:
        self.reachable = reachable
        self.version = version
        self.installed = installed if installed is not None else ["llama3.2:3b"]
        self.reply = reply
        self.generate_error: Exception | None = None
        self.list_error: Exception | None = None
        self.health_calls = 0
        self.generate_calls = 0
        self.list_calls = 0
        self.last_options: GenerationOptions | None = None
        self.last_timeout: float | None = None

    def check_health(self, *, timeout_seconds: float) -> ProviderHealth:
        """Report reachability without raising, as the interface requires."""
        self.health_calls += 1
        if not self.reachable:
            return ProviderHealth(reachable=False)
        return ProviderHealth(
            reachable=True, version=self.version, model_count=len(self.installed)
        )

    def list_models(self, *, timeout_seconds: float) -> list[ProviderModel]:
        """Return the configured inventory, or raise the configured error."""
        self.list_calls += 1
        if self.list_error is not None:
            raise self.list_error
        return [
            ProviderModel(
                name=name,
                parameter_size="3.2B",
                quantization="Q4_K_M",
                size_bytes=2_019_393_189,
                family="llama",
            )
            for name in self.installed
        ]

    def generate(
        self, options: GenerationOptions, *, timeout_seconds: float
    ) -> ProviderGeneration:
        """Return the configured reply, or raise the configured error."""
        self.generate_calls += 1
        self.last_options = options
        self.last_timeout = timeout_seconds
        if not self.reachable:
            # A runtime that is not answering cannot return text. A fake that
            # replied anyway would let a test assert "no fallback exists" while
            # silently exercising the path a fallback would take, which is the
            # one thing this property must not be able to fake (M23.10).
            raise LlmUnavailableError(
                "The local model runtime is not answering.",
                reason=REASON_NOT_RUNNING,
                detail="fake provider is unreachable",
            )
        if self.generate_error is not None:
            raise self.generate_error
        return ProviderGeneration(
            text=self.reply,
            model=self.installed[0] if self.installed else "fake-model",
            prompt_tokens=12,
            output_tokens=4,
            total_ms=42.0,
            done_reason="stop",
        )

    def model_available(self, model: str, *, timeout_seconds: float) -> bool:
        """Report whether ``model`` is in the configured inventory."""
        wanted = model.strip()
        return any(
            name == wanted or (":" not in wanted and name.split(":", 1)[0] == wanted)
            for name in self.installed
        )


def make_service(
    provider: FakeProvider | None = None,
    *,
    enabled: bool = True,
    model: str = "llama3.2:3b",
    max_prompt_chars: int = 4000,
    max_output_tokens: int = 512,
    max_concurrent_requests: int = 1,
    health_timeout_seconds: float = 3.0,
) -> Any:
    """Build an ``AiService`` around a fake provider."""
    from app.ai.service import AiService

    return AiService(
        provider=provider or FakeProvider(),
        enabled=enabled,
        model=model,
        timeout_seconds=60.0,
        health_timeout_seconds=health_timeout_seconds,
        max_prompt_chars=max_prompt_chars,
        max_output_tokens=max_output_tokens,
        max_concurrent_requests=max_concurrent_requests,
    )


def unreachable_provider() -> FakeProvider:
    """Return a provider whose health probe fails."""
    return FakeProvider(reachable=False)


def empty_provider() -> FakeProvider:
    """Return a reachable provider with an empty inventory."""
    return FakeProvider(installed=[])


#: The controlled generation errors, for parametrised tests.
GENERATION_ERRORS: tuple[Exception, ...] = (
    LlmGenerationError("timed out", reason=REASON_TIMEOUT, detail="60s"),
    LlmGenerationError("provider failed", reason=REASON_PROVIDER_ERROR, detail="500"),
    LlmUnavailableError("model gone", reason=REASON_MODEL_MISSING, detail="404"),
)

__all__ = [
    "GENERATION_ERRORS",
    "FakeProvider",
    "empty_provider",
    "make_service",
    "unreachable_provider",
]
