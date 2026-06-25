"""Tests for the one-time GuardFormer loader (fail-loud, weights-gated)."""

from pathlib import Path

import pytest

from secureSG.config.settings import Settings
from secureSG.exceptions import ModelLoadError
from secureSG.models import loader
from secureSG.models.guardformer import QwenGuardProvider


def test_missing_model_path_raises_model_load_error() -> None:
    settings = Settings(_env_file=None, model_path=None)
    with pytest.raises(ModelLoadError):
        loader.load_guard_provider(settings)


def test_nonexistent_weights_file_raises_model_load_error(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, model_path=tmp_path / "missing.gguf")
    with pytest.raises(ModelLoadError):
        loader.load_guard_provider(settings)


def test_loads_provider_when_construction_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    weights = tmp_path / "guard.gguf"
    weights.write_bytes(b"not a real gguf")
    sentinel = object()
    monkeypatch.setattr(loader, "_construct_llama", lambda settings: sentinel)
    settings = Settings(_env_file=None, model_path=weights)
    provider = loader.load_guard_provider(settings)
    assert isinstance(provider, QwenGuardProvider)
