"""Controlled errors for the local LLM layer (M23.5).

Every failure this layer can produce is one of the four below, and each exists
because a caller has to tell it apart from the others:

* :class:`LlmDisabledError` — the feature is switched off. Not a fault.
* :class:`LlmUnavailableError` — the runtime is not answering, or is answering
  without the configured model. Not a fault of the request.
* :class:`LlmBusyError` — another generation is already running. Refused, not
  queued.
* :class:`LlmGenerationError` — the runtime was reached and the generation failed,
  timed out or answered with something unusable.

**What these errors deliberately do not carry.** No URL, no filesystem path, no
provider payload and no exception text from the HTTP client. A provider error
string is useful in a log and is an information leak in a response, so each class
holds a stable machine-readable ``reason`` code and a short sentence written here
— never the text the runtime produced (M23.8/M23.10).

The hierarchy is deliberately *not* built on :class:`app.api.common.ApiError`:
this package must be importable by something that is not a FastAPI application,
and the API layer is what decides a status code. The mapping from these to HTTP
lives in :mod:`app.api.v1.ai`.
"""

from __future__ import annotations

#: Stable reason codes a caller may branch on. Closed vocabulary, so a client can
#: distinguish "the model is not installed" from "the runtime is down" instead of
#: parsing a sentence.
REASON_DISABLED = "disabled"
REASON_NOT_RUNNING = "runtime_unreachable"
REASON_MODEL_MISSING = "model_missing"
REASON_BUSY = "generation_in_progress"
REASON_TIMEOUT = "generation_timeout"
REASON_PROVIDER_ERROR = "provider_error"
REASON_INVALID_RESPONSE = "invalid_response"
REASON_INVALID_PROMPT = "invalid_prompt"

#: Every reason code this module can emit.
LLM_REASONS: tuple[str, ...] = (
    REASON_DISABLED,
    REASON_NOT_RUNNING,
    REASON_MODEL_MISSING,
    REASON_BUSY,
    REASON_TIMEOUT,
    REASON_PROVIDER_ERROR,
    REASON_INVALID_RESPONSE,
    REASON_INVALID_PROMPT,
)


class LlmError(Exception):
    """Base class for every controlled failure in this layer (M23.5).

    Args:
        message: A short sentence safe to return to a client. Must not contain a
            URL, a path, provider text or an exception repr.
        reason: One of :data:`LLM_REASONS`.
        detail: Optional developer-facing detail. **Never serialised** — it exists
            for a log line, and the API layer drops it.
    """

    def __init__(
        self, message: str, *, reason: str = REASON_PROVIDER_ERROR, detail: str = ""
    ) -> None:
        super().__init__(message)
        self.message = str(message)
        self.reason = str(reason)
        # Kept off the wire deliberately: see the module docstring.
        self.detail = str(detail)

    def __repr__(self) -> str:
        """Return a developer repr that includes the reason, not the client text."""
        return f"{type(self).__name__}(reason={self.reason!r})"


class LlmDisabledError(LlmError):
    """LLM functionality is switched off by configuration (M23.4).

    Not a fault: an operator who has not enabled the feature has not broken
    anything, and the API answers this as an explicit state rather than as an
    error where it can.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or (
                "Local AI is disabled. Set LLM_ENABLED=true and name an installed "
                "model in LLM_MODEL to use it."
            ),
            reason=REASON_DISABLED,
        )


class LlmUnavailableError(LlmError):
    """The local runtime is not reachable, or lacks the configured model (M23.4).

    Two causes share one class because they share one remedy from the operator's
    point of view — start the runtime or install the model — but they keep
    distinct reason codes so the page can say which.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str = REASON_NOT_RUNNING,
        detail: str = "",
    ) -> None:
        super().__init__(message, reason=reason, detail=detail)


class LlmBusyError(LlmError):
    """Another generation is already running, and this one was refused (M23.7).

    Refused rather than queued: on a card where the model alone occupies most of
    the VRAM, a queue would turn one slow request into a stalled page. The caller
    may retry when the running generation finishes.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or (
                "Another local generation is already running. Only one runs at a "
                "time on this hardware, so this request was refused rather than "
                "queued. Try again when it finishes."
            ),
            reason=REASON_BUSY,
        )


class LlmGenerationError(LlmError):
    """The runtime was reached and the generation did not produce usable text.

    Covers a timeout, a transport failure mid-request, a non-2xx answer and a
    response body that is not the documented shape. The ``reason`` field
    distinguishes them; the message never repeats what the provider said.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str = REASON_PROVIDER_ERROR,
        detail: str = "",
    ) -> None:
        super().__init__(message, reason=reason, detail=detail)


__all__ = [
    "LLM_REASONS",
    "REASON_BUSY",
    "REASON_DISABLED",
    "REASON_INVALID_PROMPT",
    "REASON_INVALID_RESPONSE",
    "REASON_MODEL_MISSING",
    "REASON_NOT_RUNNING",
    "REASON_PROVIDER_ERROR",
    "REASON_TIMEOUT",
    "LlmBusyError",
    "LlmDisabledError",
    "LlmError",
    "LlmGenerationError",
    "LlmUnavailableError",
]
