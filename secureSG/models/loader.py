"""One-time loader for the GuardFormer model.

Weights load once at startup (CLAUDE.md section 6: never reload per request). A
missing weights path, an absent file, or a missing native wheel is a loud
``ModelLoadError`` — never a silent degrade to an unguarded state. Running
deterministic-only is a separate, explicit choice (constructing the Enforcer
without a Screener), not a fallback hidden here.
"""

from typing import cast

from secureSG.config.settings import GuardProvider, Settings
from secureSG.exceptions import ModelLoadError
from secureSG.models.guardformer import QwenGuardProvider, _CompletionModel
from secureSG.models.ollama_provider import OllamaGuardProvider
from secureSG.models.provider import ModelProvider


def load_guard_provider(settings: Settings) -> ModelProvider:
    """Load the configured guard provider: in-process llama-cpp, or Ollama HTTP.

    Raises:
        ModelLoadError: if the llama-cpp path has no weights configured or the
            file is missing.

    Time complexity: O(weights load). Space complexity: O(model size).
    """
    if settings.guard_provider is GuardProvider.OLLAMA:
        return _load_ollama_provider(settings)
    return _load_llamacpp_provider(settings)


def _load_ollama_provider(settings: Settings) -> OllamaGuardProvider:
    """Construct the Ollama HTTP guard provider (no weights, no ML wheels). O(1)."""
    return OllamaGuardProvider(
        settings.ollama_base_url,
        settings.ollama_model,
        timeout=settings.ollama_request_timeout,
        max_output_tokens=settings.model_max_output_tokens,
        logprobs_top_k=settings.model_logprobs_top_k,
        author_max_tokens=settings.model_author_max_tokens,
    )


def _load_llamacpp_provider(settings: Settings) -> QwenGuardProvider:
    """Load the Qwen3 GGUF once and wrap it as a ``ModelProvider``.

    Raises:
        ModelLoadError: if no weights path is configured or the file is missing.

    Time complexity: O(weights load). Space complexity: O(model size).
    """
    if settings.model_path is None:
        raise ModelLoadError(
            "SECURESG_MODEL_PATH is not set; no guard weights to load"
        )
    if not settings.model_path.is_file():
        raise ModelLoadError(f"guard weights not found at {settings.model_path}")
    llm = _construct_llama(settings)
    return QwenGuardProvider(
        llm,
        max_output_tokens=settings.model_max_output_tokens,
        logprobs_top_k=settings.model_logprobs_top_k,
        author_max_tokens=settings.model_author_max_tokens,
    )


def _construct_llama(settings: Settings) -> _CompletionModel:  # pragma: no cover
    # reason: imports the native llama_cpp wheel and loads ~400MB of weights;
    # exercised only by the @pytest.mark.model integration test, never in CI.
    try:
        from llama_cpp import Llama
    except ImportError as exc:
        raise ModelLoadError("llama-cpp-python is not installed") from exc
    return cast(
        _CompletionModel,
        Llama(
            model_path=str(settings.model_path),
            n_ctx=settings.model_context_size,
            n_threads=settings.model_threads,
            logits_all=False,
            verbose=False,
        ),
    )
