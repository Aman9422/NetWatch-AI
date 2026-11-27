"""The runtime-state vocabulary for the local LLM (M23.9).

Four states, and the point of naming them is that an operator fixes each one
differently:

===============  ==========================================================
State            What it means and what to do
===============  ==========================================================
disabled         ``llm_enabled`` is false. Nothing is wrong.
unreachable      Enabled, but the runtime is not answering. Start Ollama.
model_missing    The runtime answers but lacks ``llm_model``. Pull it.
ready            Enabled, reachable, installed. Generation will be attempted.
===============  ==========================================================

**Why a state and not an error.** A disabled feature and a stopped service are
both normal conditions of a development machine. Reporting either as a failure
would make the page render an error banner for a situation that needs a sentence
and a switch. The API answers ``200`` with one of these states and reserves a
non-2xx status for a generation request that genuinely could not be honoured
(M23.9).

This module holds no provider knowledge: it maps reachability and a model check
onto one word, and describes that word.
"""

from __future__ import annotations

from enum import Enum

#: The closed state vocabulary, mirrored by the frontend's ``AiState`` and the
#: ``Literal`` in :mod:`app.api.v1.ai`.
STATE_DISABLED = "disabled"
STATE_UNREACHABLE = "unreachable"
STATE_MODEL_MISSING = "model_missing"
STATE_READY = "ready"

#: Every state this layer can report.
LLM_STATES: tuple[str, ...] = (
    STATE_DISABLED,
    STATE_UNREACHABLE,
    STATE_MODEL_MISSING,
    STATE_READY,
)


class LlmState(str, Enum):
    """The four states a local LLM integration can be in (M23.9)."""

    DISABLED = STATE_DISABLED
    UNREACHABLE = STATE_UNREACHABLE
    MODEL_MISSING = STATE_MODEL_MISSING
    READY = STATE_READY


def resolve_state(*, enabled: bool, reachable: bool, model_present: bool) -> LlmState:
    """Return the state implied by three independent facts (M23.9).

    Ordered deliberately: ``disabled`` is decided first because an operator who
    switched the feature off has not asked whether the runtime is up, and probing
    it would spend a health timeout answering a question nobody asked.
    """
    if not enabled:
        return LlmState.DISABLED
    if not reachable:
        return LlmState.UNREACHABLE
    if not model_present:
        return LlmState.MODEL_MISSING
    return LlmState.READY


def describe_state(state: str) -> str:
    """Return one sentence explaining ``state`` and what it implies (M23.9).

    No state reads as an error unless it is one: ``disabled`` says the feature is
    off rather than that something failed, and ``ready`` says generation *will be
    attempted* rather than that any answer will be correct.

    An unrecognised state returns a neutral sentence rather than raising, so a
    value written by a later version is still renderable.
    """
    return {
        STATE_DISABLED: (
            "Local AI is switched off. No model is loaded and no generation is "
            "possible until LLM_ENABLED is set to true."
        ),
        STATE_UNREACHABLE: (
            "Local AI is enabled but the model runtime is not answering. Start "
            "Ollama; monitoring, detection and alerting are unaffected."
        ),
        STATE_MODEL_MISSING: (
            "The model runtime is running but the configured model is not "
            "installed. Install it, then reload this page."
        ),
        STATE_READY: (
            "The model runtime is reachable and the configured model is "
            "installed. A test generation will be attempted on request."
        ),
    }.get(
        str(state),
        f"The local AI state is {state!r}, which this version does not describe.",
    )


def is_usable(state: str) -> bool:
    """Return True when a generation may be attempted in ``state`` (M23.9).

    Only ``ready`` qualifies. Failing fast with the reason beats spending a
    generation timeout discovering that the runtime was down.
    """
    return str(state) == STATE_READY


__all__ = [
    "LLM_STATES",
    "STATE_DISABLED",
    "STATE_MODEL_MISSING",
    "STATE_READY",
    "STATE_UNREACHABLE",
    "LlmState",
    "describe_state",
    "is_usable",
    "resolve_state",
]
