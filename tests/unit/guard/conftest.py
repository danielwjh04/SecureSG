"""Shared fixtures for guard tests: a deterministic stub ModelProvider.

The stub is a test double (never shipped in ``secureSG/``); it returns a fixed
probability or raises ``InferenceError`` so screener/enforcer behavior can be
tested without model weights.
"""

from collections.abc import Callable

import pytest

from secureSG.exceptions import InferenceError
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment


class _StubProvider(ModelProvider):
    """Returns a fixed P(unsafe), or raises ``InferenceError``, with no weights."""

    def __init__(self, p_unsafe: float, *, raises: bool) -> None:
        self._p_unsafe = p_unsafe
        self._raises = raises

    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment:
        if self._raises:
            raise InferenceError("stub forced inference failure")
        return SemanticAssessment(task=task, p_unsafe=self._p_unsafe)


@pytest.fixture
def make_provider() -> Callable[..., ModelProvider]:
    """Factory: ``make_provider(p_unsafe=0.0, raises=False) -> ModelProvider``."""

    def _make(p_unsafe: float = 0.0, *, raises: bool = False) -> ModelProvider:
        return _StubProvider(p_unsafe, raises=raises)

    return _make
