"""Tests for the OpenAI guard-provider loader (fail-loud without a key)."""

import pytest

from secureSG.config.settings import Settings
from secureSG.exceptions import ModelLoadError
from secureSG.models import loader
from secureSG.models.openai_provider import OpenAIGuardProvider


def test_missing_api_key_raises_model_load_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=None)
    with pytest.raises(ModelLoadError):
        loader.load_guard_provider(settings)


def test_loads_openai_provider_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    settings = Settings(_env_file=None)
    provider = loader.load_guard_provider(settings)
    assert isinstance(provider, OpenAIGuardProvider)
