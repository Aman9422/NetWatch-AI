"""The AI service: the one place limits, concurrency and state are enforced (M23.5).

This module is what the API and the frontend talk to. It owns exactly four things
and delegates everything else:

1. **The state.** Asked once per status request, it probes the runtime and the
   model with the short health budget, then reports one of four words from
   :mod:`app.ai.health`.
2. **The limits.** It refuses a blank or oversized prompt, and a request made while
   the feature is disabled — before any network call.
3. **The concurrency.** One generation at a time, enforced by a
   :class:`threading.BoundedSemaphore`, refused rather than queued (M23.7).
4. **The budget.** It passes the *generation* timeout to a generation and the
   *health* timeout to a probe, which are deliberately different numbers (M23.7).

**What it never does.** It never constructs a provider per request, never reads a
request body to choose a model or a host, never retries, and never runs anything on
a timer. There is no background thread here at all: M23 is request-driven, so no
code in this package can execute on the packet-capture thread (M23.6).

**Why the slot is acquired without blocking indefinitely.** A caller that waited
forever would turn "the model is busy" into "the page hangs". The acquire timeout
is short and a failure is an explicit ``LlmBusyError``, which the API renders as
``409`` — the same shape M22 uses for a training pass already running.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from app.ai.exceptions import (
    REASON_INVALID_PROMPT,
    LlmBusyError,
    LlmDisabledError,
    LlmError,
    LlmGenerationError,
)
from app.ai.health import LlmState, describe_state, is_usable, resolve_state
from app.ai.providers.base import (
    GenerationOptions,
    LlmProvider,
    ProviderGeneration,
    ProviderModel,
)

logger = logging.getLogger(__name__)

#: Seconds a request will wait for the generation slot before being refused.
#:
#: Short on purpose. A generation can legitimately take a minute, so waiting for
#: one is not useful: the honest answer to a second concurrent request is "busy,
#: retry when the first finishes", not a minute-long queue that looks like a hang
#: (M23.7).
SLOT_ACQUIRE_TIMEOUT_SECONDS = 0.05


@dataclass(frozen=True)
class AiStatus:
    """What one status probe found (M23.9).

    Attributes:
        enabled: Whether ``llm_enabled`` is true.
        provider: The configured runtime name.
        model: The configured model, blank when none is set.
        state: One of the four words from :mod:`app.ai.health`.
        state_description: One sentence explaining it.
        runtime_reachable: Whether the runtime answered.
        model_available: Whether the configured model is installed.
        runtime_version: The runtime's own version string, when reported.
        installed_model_count: How many models it reports, when reachable.
        message: A safe sentence for the page, never a provider error.
        health_timeout_seconds: The probe budget this answer was produced under.
            Reported because it explains the answer: an ``unreachable`` that
            arrived in three seconds and one that arrived in sixty are different
            facts about the configuration (M23.7).
    """

    enabled: bool
    provider: str
    model: str
    state: str
    state_description: str
    runtime_reachable: bool
    model_available: bool
    runtime_version: str = ""
    installed_model_count: int = 0
    message: str = ""
    health_timeout_seconds: float = 0.0


class AiService:
    """Orchestrate the local LLM behind one interface (M23.5).

    Args:
        provider: The runtime adapter. Required.
        enabled: The master switch.
        model: The configured model, echoed in the status payload.
        timeout_seconds: The generation budget.
        health_timeout_seconds: The probe budget. Must be the shorter of the two.
        max_prompt_chars: The longest prompt this service will accept.
        max_output_tokens: The reply cap handed to the provider.
        max_concurrent_requests: How many generations may run at once.

    Safe to share across threads: the only mutable state is the semaphore.
    """

    def __init__(
        self,
        *,
        provider: LlmProvider,
        enabled: bool,
        model: str,
        timeout_seconds: float,
        health_timeout_seconds: float,
        max_prompt_chars: int,
        max_output_tokens: int,
        max_concurrent_requests: int = 1,
    ) -> None:
        self._provider = provider
        self._enabled = bool(enabled)
        self._model = model.strip()
        self._timeout_seconds = float(timeout_seconds)
        self._health_timeout_seconds = float(health_timeout_seconds)
        self._max_prompt_chars = int(max_prompt_chars)
        self._max_output_tokens = int(max_output_tokens)
        # A BoundedSemaphore, not a Lock: releasing one time too many raises rather
        # than silently widening the budget, which is the failure that would show up
        # as two concurrent models on a card that fits one.
        self._slots = threading.BoundedSemaphore(max(1, int(max_concurrent_requests)))

    def close(self) -> None:
        """Release the provider's pooled HTTP client (M23.5)."""
        closer = getattr(self._provider, "close", None)
        if callable(closer):
            closer()

    # -- read surface ------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return whether the master switch is on."""
        return self._enabled

    @property
    def model(self) -> str:
        """Return the configured model name."""
        return self._model

    @property
    def provider_name(self) -> str:
        """Return the configured provider name."""
        return getattr(self._provider, "name", "unknown")

    @property
    def max_prompt_chars(self) -> int:
        """Return the longest prompt this service accepts, in characters."""
        return self._max_prompt_chars

    @property
    def max_output_tokens(self) -> int:
        """Return the reply token cap."""
        return self._max_output_tokens

    def status(self) -> AiStatus:
        """Probe the runtime and report one state (M23.9).

        **When disabled, nothing is probed.** A feature that is off has not asked
        whether its runtime is up, and spending a health timeout to find out would
        make the page wait three seconds for an answer it will not show.

        Never raises: every failure becomes a state, because the question this
        method answers is "what is going on", and an exception is not an answer.
        """
        if not self._enabled:
            return AiStatus(
                enabled=False,
                provider=self.provider_name,
                model=self._model,
                state=LlmState.DISABLED.value,
                state_description=describe_state(LlmState.DISABLED.value),
                runtime_reachable=False,
                model_available=False,
                message="Local AI is disabled by configuration.",
                health_timeout_seconds=self._health_timeout_seconds,
            )

        health = self._provider.check_health(
            timeout_seconds=self._health_timeout_seconds
        )
        if not health.reachable:
            return AiStatus(
                enabled=True,
                provider=self.provider_name,
                model=self._model,
                state=LlmState.UNREACHABLE.value,
                state_description=describe_state(LlmState.UNREACHABLE.value),
                runtime_reachable=False,
                model_available=False,
                message=(
                    "The local model runtime is not answering on the configured "
                    "address."
                ),
                health_timeout_seconds=self._health_timeout_seconds,
            )

        try:
            model_present = self._provider.model_available(
                self._model, timeout_seconds=self._health_timeout_seconds
            )
        except LlmError as exc:
            # Reachable a moment ago, unreachable now: report unreachable rather
            # than pretending either fact is certain.
            logger.info("Model availability check failed: %r", exc)
            return AiStatus(
                enabled=True,
                provider=self.provider_name,
                model=self._model,
                state=LlmState.UNREACHABLE.value,
                state_description=describe_state(LlmState.UNREACHABLE.value),
                runtime_reachable=False,
                model_available=False,
                message=(
                    "The local model runtime stopped answering while its models "
                    "were being checked."
                ),
                health_timeout_seconds=self._health_timeout_seconds,
            )

        state = resolve_state(
            enabled=True, reachable=True, model_present=model_present
        )
        return AiStatus(
            enabled=True,
            provider=self.provider_name,
            model=self._model,
            state=state.value,
            state_description=describe_state(state.value),
            runtime_reachable=True,
            model_available=model_present,
            runtime_version=health.version,
            installed_model_count=health.model_count,
            message=(
                "Ready to generate."
                if is_usable(state.value)
                else "The configured model is not installed in the runtime."
            ),
            health_timeout_seconds=self._health_timeout_seconds,
        )

    def list_models(self) -> list[ProviderModel]:
        """Return the models actually installed on the runtime (M23.8).

        Raises:
            LlmDisabledError: If the feature is switched off. Listing would require
                reaching a service the operator asked this application not to use.
            LlmError: If the runtime is unreachable or answers unusably.
        """
        if not self._enabled:
            raise LlmDisabledError()
        return self._provider.list_models(
            timeout_seconds=self._health_timeout_seconds
        )

    # -- generation --------------------------------------------------------

    def generate(self, prompt: str) -> ProviderGeneration:
        """Generate a reply to ``prompt`` with the configured model (M23.9).

        The order of checks is deliberate: everything decidable without touching
        the network is decided first, so a disabled feature, an oversized prompt or
        an exhausted slot never costs a timeout.

        Raises:
            LlmDisabledError: If the feature is switched off.
            LlmGenerationError: If the prompt is blank or over the limit.
            LlmBusyError: If another generation holds the only slot.
            LlmUnavailableError: If the runtime or model is unavailable.
            LlmGenerationError: On a timeout or provider failure.
        """
        if not self._enabled:
            raise LlmDisabledError()

        text = prompt if isinstance(prompt, str) else ""
        if not text.strip():
            raise LlmGenerationError(
                "The prompt is empty. Enter some text to send.",
                reason=REASON_INVALID_PROMPT,
            )
        if len(text) > self._max_prompt_chars:
            raise LlmGenerationError(
                f"The prompt is {len(text)} characters, which exceeds the "
                f"configured limit of {self._max_prompt_chars}. Shorten it and try "
                "again.",
                reason=REASON_INVALID_PROMPT,
            )

        if not self._slots.acquire(timeout=SLOT_ACQUIRE_TIMEOUT_SECONDS):
            raise LlmBusyError()
        try:
            options = GenerationOptions(
                prompt=text, max_output_tokens=self._max_output_tokens
            )
            generation = self._provider.generate(
                options, timeout_seconds=self._timeout_seconds
            )
            logger.info(
                "Local generation completed: %d output token(s) in %.0f ms",
                generation.output_tokens,
                generation.total_ms,
            )
            return generation
        finally:
            self._slots.release()


__all__ = ["AiService", "AiStatus", "SLOT_ACQUIRE_TIMEOUT_SECONDS"]
