"""Tests for the ModelProvider abstract seam."""

import pytest

from secureSG.models.provider import ModelProvider


def test_model_provider_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        ModelProvider()  # type: ignore[abstract]  # reason: testing it is abstract
