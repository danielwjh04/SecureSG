"""Shared fixtures for warden tests: a deterministic stub embedding provider."""

from collections.abc import Callable

import pytest

from secureSG.warden.embeddings import EmbeddingProvider, Vector


class _StubEmbeddingProvider(EmbeddingProvider):
    """Maps fixed texts to fixed vectors so cosines (and verdicts) are exact."""

    def __init__(self, vectors: dict[str, Vector]) -> None:
        self._vectors = vectors

    async def embed(self, texts: list[str]) -> list[Vector]:
        return [self._vectors[text] for text in texts]


@pytest.fixture
def make_embedder() -> Callable[[dict[str, Vector]], EmbeddingProvider]:
    """Factory: ``make_embedder({text: vector, ...}) -> EmbeddingProvider``."""

    def _make(vectors: dict[str, Vector]) -> EmbeddingProvider:
        return _StubEmbeddingProvider(vectors)

    return _make
