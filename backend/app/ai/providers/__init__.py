"""The provider registry for the local LLM layer (M23.3).

A single factory, :func:`build_provider`, is the only place a runtime adapter is
constructed. Keeping it here rather than in :mod:`app.ai.service` is what makes the
word ``ollama`` appear in exactly one switch: adding a second runtime is a new
module plus one branch, and no caller changes.

**An unknown provider raises.** The setting that names a provider is validated at
startup (see ``Settings._validate_llm_configuration``), so reaching this factory
with an unsupported name means the service was assembled outside the normal path.
Raising there is better than silently falling back to Ollama, because a silent
fallback is precisely the "pretend it worked" behaviour M23.10 forbids.
"""

from __future__ import annotations

from app.ai.providers.base import (
    GenerationOptions,
    LlmProvider,
    ProviderGeneration,
    ProviderHealth,
    ProviderModel,
)
from app.ai.providers.ollama import PROVIDER_NAME as OLLAMA_PROVIDER_NAME
from app.ai.providers.ollama import OllamaProvider

#: The providers this package can construct, keyed by their setting value.
_PROVIDER_FACTORIES = {
    OLLAMA_PROVIDER_NAME: OllamaProvider,
}


def build_provider(
    *,
    name: str,
    base_url: str,
    model: str,
    num_ctx: int = 4096,
    keep_alive: str = "5m",
) -> LlmProvider:
    """Construct the provider named by configuration (M23.3).

    Args:
        name: The ``llm_provider`` setting. Matched case-insensitively.
        base_url: The runtime's address.
        model: The configured model. Required by every provider this project has,
            and never a client's choice.
        num_ctx: The context window to request.
        keep_alive: How long to ask the runtime to keep the model resident.

    Returns:
        A ready provider instance.

    Raises:
        ValueError: If ``name`` is not a provider this build can construct.
    """
    key = str(name).strip().lower()
    factory = _PROVIDER_FACTORIES.get(key)
    if factory is None:
        raise ValueError(
            f"Unknown LLM provider {name!r}; this build supports: "
            f"{', '.join(sorted(_PROVIDER_FACTORIES))}"
        )
    return factory(
        base_url=base_url, model=model, num_ctx=num_ctx, keep_alive=keep_alive
    )


__all__ = [
    "OLLAMA_PROVIDER_NAME",
    "GenerationOptions",
    "LlmProvider",
    "OllamaProvider",
    "ProviderGeneration",
    "ProviderHealth",
    "ProviderModel",
    "build_provider",
]
