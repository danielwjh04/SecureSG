"""Construct the OpenAI guard provider from settings.

The guard's semantic layer runs on OpenAI. A missing ``OPENAI_API_KEY`` is a loud
``ModelLoadError`` — never a silent degrade to an unguarded state. Running
deterministic-only is a separate, explicit choice (constructing the Enforcer
without a Screener in ``main``), not a fallback hidden here.
"""

from typing import cast

from secureSG.config.settings import Settings
from secureSG.exceptions import ModelLoadError
from secureSG.models.openai_provider import OpenAIChatClient, OpenAIGuardProvider
from secureSG.models.provider import ModelProvider


def load_guard_provider(settings: Settings) -> ModelProvider:
    """Build the OpenAI guard provider, failing loud without an API key.

    Raises:
        ModelLoadError: if ``OPENAI_API_KEY`` is not configured.

    Time complexity: O(1). Space complexity: O(1).
    """
    if settings.openai_api_key is None:
        raise ModelLoadError("OPENAI_API_KEY is not set; no guard model to load")
    return OpenAIGuardProvider(
        _build_client(settings),
        guard_model=settings.openai_guard_model,
        assess_max_tokens=settings.openai_assess_max_tokens,
        author_max_tokens=settings.openai_author_max_tokens,
    )


def _build_client(settings: Settings) -> OpenAIChatClient:
    """Construct the async OpenAI client (no network until first call). O(1)."""
    from openai import AsyncOpenAI

    return cast(
        OpenAIChatClient,
        AsyncOpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            timeout=settings.openai_request_timeout,
        ),
    )
