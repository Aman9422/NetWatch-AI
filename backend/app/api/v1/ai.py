"""Local LLM API (M23.9).

Three surfaces over the M23 service, and each exists for a distinct question:

* ``GET /ai/status`` — is the feature on, is the runtime up, is the model
  installed? Answered as a **state**, always ``200``.
* ``GET /ai/models`` — which models does the runtime actually have? A passthrough
  of its own inventory.
* ``POST /ai/test`` — send a bounded prompt and return what the model said.

**Why status answers ``200`` even when nothing works.** A disabled feature and a
stopped service are both normal conditions of a development machine. Reporting
either as a ``503`` would make the page render an error banner for a situation that
needs a sentence and a switch, and would make "disabled" indistinguishable from
"broken" — the one distinction an operator most needs. The ``state`` field carries
the answer; the status code carries whether the *request* was understood, and it
was (M23.9).

**What these routes cannot do.** There is no field for a model, a host, a timeout,
a context size or a temperature. The request body is a prompt and nothing else, so
"a client cannot choose which model runs or where it is reached" is a property of
the schema rather than a rule someone has to enforce twice (M23.10). Nothing here
reads packets, touches the database, executes model output or writes to a
detection, alert, incident or risk record.

**Every error is sanitised.** :func:`_to_api_error` maps a controlled
:class:`app.ai.exceptions.LlmError` onto the project envelope, and the provider's
own text stays in ``detail`` where only the log can see it — no URL, path, stack
trace or raw provider message reaches a client (M23.10/M13.30).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from app.ai import (
    LLM_DISCLAIMER,
    REASON_BUSY,
    REASON_DISABLED,
    REASON_INVALID_PROMPT,
    REASON_MODEL_MISSING,
    REASON_TIMEOUT,
    STATE_LABELS,
    AiModelListData,
    AiModelView,
    AiService,
    AiStatusData,
    AiTestData,
    AiTestRequest,
    LlmError,
    get_ai_service,
)
from app.api.common import (
    BadRequestError,
    ConflictError,
    ErrorCode,
    ServiceUnavailableError,
    success_payload,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def get_service() -> AiService:
    """Return the process-wide AI service as a FastAPI dependency (M23.9).

    A thin wrapper rather than passing ``get_ai_service`` itself, so a test can
    override this one dependency and hand a route a known service without patching
    a module global — the pattern M22's ``get_engine`` established.
    """
    return get_ai_service()


def _to_api_error(exc: LlmError) -> Exception:
    """Translate a controlled LLM failure into the project's error envelope.

    The status code is chosen from the *reason*, not from the exception class,
    because two failures of one class mean different things to an operator: a
    missing model is a misconfiguration they fix, and an unreachable runtime is a
    service they start. Both are ``503`` — the request cannot be served either way
    — but the code and message differ.

    Args:
        exc: The controlled failure. Its ``detail`` is logged and never returned.

    Returns:
        An :class:`app.api.common.ApiError` subclass instance, ready to raise.
    """
    logger.info("Local LLM request failed: %r — %s", exc, exc.detail or "no detail")

    if exc.reason == REASON_DISABLED:
        return ServiceUnavailableError(
            "Local AI is disabled. Set LLM_ENABLED=true and name an installed "
            "model in LLM_MODEL to use it.",
            code=ErrorCode.SERVICE_UNAVAILABLE,
            field="llm_enabled",
        )
    if exc.reason == REASON_BUSY:
        # 409, matching M22's "a training pass is already running": the request was
        # understood, the resource is occupied, and retrying later is the answer.
        return ConflictError(exc.message, code=ErrorCode.CONFLICT, field="llm")
    if exc.reason == REASON_INVALID_PROMPT:
        # A blank or oversized prompt is the client's mistake: 400 naming the field.
        return BadRequestError(
            exc.message, code=ErrorCode.INVALID_REQUEST, field="prompt"
        )
    if exc.reason == REASON_MODEL_MISSING:
        return ServiceUnavailableError(
            exc.message, code=ErrorCode.SERVICE_UNAVAILABLE, field="llm_model"
        )
    if exc.reason == REASON_TIMEOUT:
        return ServiceUnavailableError(
            exc.message, code=ErrorCode.SERVICE_UNAVAILABLE, field="llm"
        )
    # Any other controlled failure is still the LLM's rather than the API's, so a
    # 503 stays more honest than a 500 that would suggest the request was malformed.
    return ServiceUnavailableError(
        "The local model could not complete this request. Check the runtime and "
        "try again.",
        code=ErrorCode.SERVICE_UNAVAILABLE,
        field="llm",
    )


@router.get("/status", response_model=None)
def get_status(service: AiService = Depends(get_service)) -> dict:
    """Report whether local AI is usable, as one of four states (M23.9).

    Always ``200``. The payload states whether the feature is enabled, which
    provider and model are configured, whether the runtime answered, whether the
    model is installed, and one sentence explaining what to do about it.

    **The probe is short.** The runtime is checked with the configured *health*
    budget — three seconds by default — not the generation budget, because an
    unreachable host hangs rather than refusing and a status check that blocked for
    a minute would be indistinguishable from a broken page.

    **The probe is skipped entirely when disabled.** A feature that is off has not
    asked whether its runtime is up, and the answer would not be shown.
    """
    status = service.status()
    payload = AiStatusData(
        enabled=status.enabled,
        provider=status.provider,
        model=status.model,
        state=status.state,
        state_label=STATE_LABELS.get(status.state, status.state),
        state_description=status.state_description,
        runtime_reachable=status.runtime_reachable,
        model_available=status.model_available,
        runtime_version=status.runtime_version,
        installed_model_count=status.installed_model_count,
        message=status.message,
        health_timeout_seconds=status.health_timeout_seconds,
    )
    logger.info("Local AI status requested: state=%s", status.state)
    return success_payload(
        "Local AI status retrieved", payload.model_dump(mode="json")
    )


@router.get("/models", response_model=None)
def list_models(service: AiService = Depends(get_service)) -> dict:
    """Return the models the runtime actually has installed (M23.8).

    A passthrough of the runtime's inventory: nothing cached, nothing curated,
    nothing invented. If the runtime lists four models, four are returned, and the
    payload marks which of them is the configured one so a page need not compare
    strings itself.

    Raises:
        ServiceUnavailableError: If the feature is disabled, the runtime is
            unreachable, or it answers with something unusable.
    """
    try:
        installed = service.list_models()
    except LlmError as exc:
        raise _to_api_error(exc) from exc

    configured = service.model
    views = [
        AiModelView(
            name=entry.name,
            parameter_size=entry.parameter_size,
            quantization=entry.quantization,
            size_bytes=entry.size_bytes,
            family=entry.family,
        )
        for entry in installed
    ]
    payload = AiModelListData(
        count=len(views),
        configured_model=configured,
        configured_model_installed=any(
            entry.name == configured for entry in installed
        ),
        models=views,
    )
    logger.info("Returning %d installed local model(s) via API", payload.count)
    return success_payload(
        "Installed local models retrieved", payload.model_dump(mode="json")
    )


@router.post("/test", response_model=None)
def test_generation(
    body: AiTestRequest,
    service: AiService = Depends(get_service),
) -> dict:
    """Send a bounded prompt to the configured model (M23.9).

    The body carries a prompt and nothing else: no model, no host, no timeout, no
    options. Those are configuration, which is what stops a caller choosing which
    model runs or where it is reached.

    The reply is **untrusted text**: returned as a string, never executed, never
    parsed as a directive and never written to a detection, alert, incident or risk
    record. The payload says so in its ``disclaimer``.

    Raises:
        ServiceUnavailableError: If the feature is disabled, the runtime or model
            is unavailable, or the generation timed out.
        BadRequestError: If the prompt is blank or longer than the configured
            limit, naming ``prompt``.
        ConflictError: If another generation is already running — refused rather
            than queued, because on this hardware only one runs at a time.
    """
    try:
        generation = service.generate(body.prompt)
    except LlmError as exc:
        raise _to_api_error(exc) from exc

    payload = AiTestData(
        requested_prompt_chars=len(body.prompt),
        response=generation.text,
        model=generation.model or service.model,
        provider=service.provider_name,
        prompt_tokens=generation.prompt_tokens,
        output_tokens=generation.output_tokens,
        duration_ms=generation.total_ms,
        done_reason=generation.done_reason,
    )
    logger.info(
        "Local test generation completed via API: %d output token(s)",
        payload.output_tokens,
    )
    return success_payload(
        "Local model test generation completed", payload.model_dump(mode="json")
    )


__all__ = ["LLM_DISCLAIMER", "get_service", "router"]
