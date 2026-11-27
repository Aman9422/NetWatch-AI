"""Local LLM integration (M23).

The infrastructure for talking to a model running on this machine, and nothing
beyond it. Each responsibility has its own module:

* :mod:`app.ai.health` — the four-state vocabulary and what each one means.
* :mod:`app.ai.exceptions` — the controlled failures, with reason codes a client
  can branch on and no provider text.
* :mod:`app.ai.providers.base` — the runtime-independent interface.
* :mod:`app.ai.providers.ollama` — the only adapter M23 ships.
* :mod:`app.ai.service` — state, limits, concurrency and budgets in one place.
* :mod:`app.ai.schemas` — the wire shapes and the disclaimer they all carry.

**What this package does not do.** No alert explanation, no incident
investigation, no sequence analysis, no risk score, no automatic action, no cloud
call, no model download. It establishes that the application can reach a local
model, list what is installed, and generate bounded text on explicit request. An
analyst layer is a later milestone (M23.16).

**M23 is request-driven, by design.** There is no background worker, no polling
thread, no scheduler and no lifespan hook in this package: nothing here can
execute on the packet-capture thread, and an unavailable runtime costs monitoring
nothing at all (M23.6). That property is structural rather than a matter of care,
which is why it is stated here where a future contributor will read it before
adding a timer.
"""

from __future__ import annotations

import logging
import threading

from app.ai.exceptions import (
    LLM_REASONS,
    REASON_BUSY,
    REASON_DISABLED,
    REASON_INVALID_PROMPT,
    REASON_INVALID_RESPONSE,
    REASON_MODEL_MISSING,
    REASON_NOT_RUNNING,
    REASON_PROVIDER_ERROR,
    REASON_TIMEOUT,
    LlmBusyError,
    LlmDisabledError,
    LlmError,
    LlmGenerationError,
    LlmUnavailableError,
)
from app.ai.health import (
    LLM_STATES,
    STATE_DISABLED,
    STATE_MODEL_MISSING,
    STATE_READY,
    STATE_UNREACHABLE,
    LlmState,
    describe_state,
    is_usable,
    resolve_state,
)
from app.ai.providers import (
    OLLAMA_PROVIDER_NAME,
    GenerationOptions,
    LlmProvider,
    OllamaProvider,
    ProviderGeneration,
    ProviderHealth,
    ProviderModel,
    build_provider,
)
from app.ai.schemas import (
    LLM_DISCLAIMER,
    STATE_LABELS,
    AiModelListData,
    AiModelView,
    AiStatusData,
    AiTestData,
    AiTestRequest,
)
from app.ai.service import AiService, AiStatus

logger = logging.getLogger(__name__)

__all__ = [
    "LLM_DISCLAIMER",
    "LLM_REASONS",
    "LLM_STATES",
    "OLLAMA_PROVIDER_NAME",
    "REASON_BUSY",
    "REASON_DISABLED",
    "REASON_INVALID_PROMPT",
    "REASON_INVALID_RESPONSE",
    "REASON_MODEL_MISSING",
    "REASON_NOT_RUNNING",
    "REASON_PROVIDER_ERROR",
    "REASON_TIMEOUT",
    "STATE_DISABLED",
    "STATE_LABELS",
    "STATE_MODEL_MISSING",
    "STATE_READY",
    "STATE_UNREACHABLE",
    "AiModelListData",
    "AiModelView",
    "AiService",
    "AiStatus",
    "AiStatusData",
    "AiTestData",
    "AiTestRequest",
    "GenerationOptions",
    "LlmBusyError",
    "LlmDisabledError",
    "LlmError",
    "LlmGenerationError",
    "LlmProvider",
    "LlmState",
    "LlmUnavailableError",
    "OllamaProvider",
    "ProviderGeneration",
    "ProviderHealth",
    "ProviderModel",
    "build_provider",
    "describe_state",
    "get_ai_service",
    "is_usable",
    "reset_ai_service",
    "resolve_state",
]

#: The shared service instance. Built once, on first use.
_ai_service: AiService | None = None
_service_lock = threading.Lock()


def _build_service() -> AiService:
    """Construct the process-wide service from application settings (M23.5).

    Reads configuration and builds a provider; it does **not** probe the runtime.
    An Ollama service that is down must never prevent this application from
    starting, so reachability is asked later, by a status or generation request
    (M23.4/M23.6).

    The settings import is local so importing this package never reads the
    environment as a side effect — the convention
    :func:`app.anomaly_detection.get_anomaly_engine` follows.
    """
    from app.config.settings import settings

    provider = build_provider(
        name=settings.llm_provider,
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        num_ctx=settings.llm_num_ctx,
        keep_alive=settings.llm_keep_alive,
    )
    return AiService(
        provider=provider,
        enabled=settings.llm_enabled,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
        health_timeout_seconds=settings.llm_health_timeout_seconds,
        max_prompt_chars=settings.llm_max_prompt_chars,
        max_output_tokens=settings.llm_max_output_tokens,
        max_concurrent_requests=settings.llm_max_concurrent_requests,
    )


def get_ai_service() -> AiService:
    """Return the process-wide AI service, building it once (M23.5).

    A factory rather than a module-level instance, so importing this package has no
    side effect and a test can call :func:`reset_ai_service` to get a service built
    from different settings.
    """
    global _ai_service
    with _service_lock:
        if _ai_service is None:
            _ai_service = _build_service()
        return _ai_service


def reset_ai_service() -> None:
    """Drop the cached service so the next call rebuilds it. For tests and reloads.

    There is no thread and no timer to stop — M23 owns neither (M23.6). The one
    resource that does need releasing is the adapter's pooled HTTP client, so it is
    closed here rather than left to the garbage collector: one open connection is
    cheap, but leaving one behind on every reset would accumulate over a test
    session.
    """
    global _ai_service
    with _service_lock:
        current = _ai_service
        _ai_service = None
    if current is None:
        return
    closer = getattr(current, "close", None)
    if callable(closer):
        try:
            closer()
        except Exception:  # noqa: BLE001 - a reset must never raise
            logger.exception("Failed to close the local LLM HTTP client")
