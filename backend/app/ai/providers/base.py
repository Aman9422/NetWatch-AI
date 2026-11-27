"""The inference-provider interface (M23.3).

Everything the application needs from a local model runtime is expressed here, in
terms that mention no runtime. :mod:`app.ai.providers.ollama` is the only
implementation M23 ships, and the reason this module exists is that a second one
must be addable without touching :mod:`app.ai.service`, :mod:`app.api.v1.ai` or
the frontend.

Four operations, and no more:

* :meth:`LlmProvider.check_health` — is the runtime answering, and what is it?
* :meth:`LlmProvider.list_models` — which models are actually installed?
* :meth:`LlmProvider.generate` — produce text for a prompt.
* :meth:`LlmProvider.model_available` — is this specific model installed?

**What this interface forbids by shape.** There is no parameter for a base URL, a
host, a model override or a context size: those are configuration, and leaving
them out of the signatures is what makes "a client cannot point this application
at another host" a property of the type rather than a rule someone has to remember
(M23.10). The two ``timeout_seconds`` arguments are the *caller's* budget, not a
client's.

**Every method raises only :class:`app.ai.exceptions.LlmError` subclasses.** A
provider is responsible for translating whatever its transport does — a refused
connection, a socket timeout, a 404 body naming a model — into one of those, so
nothing runtime-specific leaks past this boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderHealth:
    """The result of asking a runtime whether it is alive (M23.9).

    Attributes:
        reachable: True when the runtime answered at all. False means the host did
            not respond within the health budget, which is the ordinary case for a
            stopped service — a closed port hangs rather than refusing.
        version: The runtime's own version string, when it reports one. Shown to
            the operator because "Ollama 0.40.18" is the first thing a support
            question needs.
        model_count: How many models the runtime reports installed. Zero is a
            valid, healthy answer — it means nothing has been pulled.
    """

    reachable: bool
    version: str = ""
    model_count: int = 0


@dataclass(frozen=True)
class ProviderModel:
    """One installed model, as the runtime describes it (M23.8).

    Only what a page can display is kept. Ollama reports far more — a digest, a
    family list, an embedding length — and carrying it through would make the wire
    shape a mirror of one runtime's ``/api/tags`` rather than a small common
    vocabulary.

    Attributes:
        name: The identifier to pass back as ``model``, e.g. ``llama3.2:3b``.
        parameter_size: e.g. ``3.2B``, when reported.
        quantization: e.g. ``Q4_K_M``, when reported.
        size_bytes: On-disk size, when reported.
        family: e.g. ``llama``, when reported.
    """

    name: str
    parameter_size: str = ""
    quantization: str = ""
    size_bytes: int = 0
    family: str = ""


@dataclass(frozen=True)
class ProviderGeneration:
    """One completed generation (M23.9).

    Attributes:
        text: The model's reply. **Untrusted text** — the caller renders it and
            never executes, evaluates or stores it as a directive (M23.10).
        model: The model that produced it, echoed by the runtime.
        prompt_tokens: Tokens the runtime counted in the prompt, when reported.
        output_tokens: Tokens it counted in the reply, when reported.
        total_ms: Wall time the runtime spent, when reported.
        done_reason: Why it stopped — ``stop`` for a completed reply, ``length``
            when the output budget was exhausted. ``length`` is worth showing
            because it means the answer was cut off rather than finished.
    """

    text: str
    model: str = ""
    prompt_tokens: int = 0
    output_tokens: int = 0
    total_ms: float = 0.0
    done_reason: str = ""


@dataclass(frozen=True)
class GenerationOptions:
    """The bounded shape of one generation request (M23.7).

    Assembled by :mod:`app.ai.service` from configuration, **never** from a request
    body: a client supplies a prompt and nothing else. That is what stops a caller
    choosing a bigger model, a wider context or a longer reply than the operator
    configured (M23.10).

    Attributes:
        prompt: The text to complete. Already length-checked by the service.
        max_output_tokens: Hard cap on the reply.
        temperature: Sampling temperature, carried here so a provider need not
            hard-code one.
        stop: Optional stop sequences.
    """

    prompt: str
    max_output_tokens: int
    temperature: float = 0.2
    stop: tuple[str, ...] = field(default=())


class LlmProvider(ABC):
    """A local inference runtime this application can talk to (M23.3).

    Implementations are constructed from configuration and must be safe to share
    across threads: the service holds one instance and FastAPI serves requests from
    a thread pool, so no method may keep per-request mutable state on ``self``.
    """

    #: The provider's own name, matching the ``llm_provider`` setting.
    name: str

    @abstractmethod
    def check_health(self, *, timeout_seconds: float) -> ProviderHealth:
        """Return whether the runtime is answering (M23.9).

        Must not raise. A runtime that is down is a *state*, not an exception, and
        every caller of this method — including the status endpoint — wants the
        answer rather than a failure to handle.

        Args:
            timeout_seconds: The caller's short health budget. Never the generation
                budget: an unreachable host hangs until the timeout expires, so a
                probe using 60 seconds would freeze a page for a minute.
        """

    @abstractmethod
    def list_models(self, *, timeout_seconds: float) -> list[ProviderModel]:
        """Return the models actually installed on the runtime (M23.8).

        A passthrough of the runtime's own inventory. Nothing is cached, nothing is
        invented and nothing is filtered: if the runtime lists four models, four
        are returned, because a curated list would be a claim about what is
        installed and this method's only job is to report what is.

        Raises:
            LlmUnavailableError: If the runtime cannot be reached.
            LlmGenerationError: If it answers with something unusable.
        """

    @abstractmethod
    def generate(
        self, options: GenerationOptions, *, timeout_seconds: float
    ) -> ProviderGeneration:
        """Produce text for a prompt (M23.9).

        Args:
            options: The bounded request, built from configuration.
            timeout_seconds: The caller's generation budget.

        Raises:
            LlmUnavailableError: If the runtime cannot be reached, or reports that
                the configured model is not installed.
            LlmGenerationError: On a timeout, a non-2xx answer, a transport failure
                or a malformed body.
        """

    @abstractmethod
    def model_available(self, model: str, *, timeout_seconds: float) -> bool:
        """Return whether ``model`` is installed (M23.4).

        Used by the status endpoint to distinguish ``model_missing`` from
        ``unreachable`` — two states an operator fixes differently.

        Raises:
            LlmUnavailableError: If the runtime cannot be reached at all.
        """


__all__ = [
    "GenerationOptions",
    "LlmProvider",
    "ProviderGeneration",
    "ProviderHealth",
    "ProviderModel",
]
