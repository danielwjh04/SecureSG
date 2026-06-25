"""Sentence embeddings, a cache, and cosine similarity for Warden governance.

Embeddings come from a swappable :class:`EmbeddingProvider` (real impl: a
sentence-transformers model, lazily loaded and gated). ``cosine_similarity`` is a
pure O(d) function. :class:`EmbeddingCache` memoizes by text so the session intent
vector is embedded once (CLAUDE.md section 2). Used by intent-drift detection and
tool-schema risk discovery.
"""

import asyncio
import math
from abc import ABC, abstractmethod
from typing import Any, Protocol, cast

from secureSG.config.settings import Settings
from secureSG.exceptions import ModelLoadError

type Vector = list[float]


def cosine_similarity(a: Vector, b: Vector) -> float:
    """Cosine similarity of two equal-length vectors; 0.0 if either is zero.

    Time complexity: O(d). Space complexity: O(1).
    """
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


class EmbeddingProvider(ABC):
    """Embeds text into vectors. The swap seam for the embedding backend."""

    @abstractmethod
    async def embed(self, texts: list[str]) -> list[Vector]:
        """Embed each text into a vector, order-preserving."""
        ...


class EmbeddingCache:
    """Memoizes text -> vector so repeated text (e.g. session intent) embeds once."""

    def __init__(self, provider: EmbeddingProvider) -> None:
        self._provider = provider
        self._cache: dict[str, Vector] = {}

    async def get(self, text: str) -> Vector:
        """Return the (cached) embedding of one text. O(1) on a hit."""
        cached = self._cache.get(text)
        if cached is not None:
            return cached
        vectors = await self._provider.embed([text])
        self._cache[text] = vectors[0]
        return vectors[0]

    async def get_many(self, texts: list[str]) -> list[Vector]:
        """Return embeddings for many texts, embedding only the uncached ones."""
        missing = [text for text in texts if text not in self._cache]
        if missing:
            vectors = await self._provider.embed(missing)
            for text, vector in zip(missing, vectors, strict=True):
                self._cache[text] = vector
        return [self._cache[text] for text in texts]


class _Encoder(Protocol):
    """The minimal slice of the sentence-transformers model the provider uses."""

    def encode(self, texts: list[str]) -> Any: ...


class SentenceTransformerProvider(EmbeddingProvider):
    """EmbeddingProvider backed by a sentence-transformers model (CPU)."""

    def __init__(self, model: _Encoder) -> None:
        self._model = model
        self._lock = asyncio.Lock()

    async def embed(self, texts: list[str]) -> list[Vector]:
        """Embed off the event loop; serialized for a single model instance."""
        async with self._lock:
            return await asyncio.to_thread(self._encode, texts)

    def _encode(self, texts: list[str]) -> list[Vector]:
        rows: list[Vector] = self._model.encode(texts).tolist()
        return rows


def load_embedding_provider(settings: Settings) -> SentenceTransformerProvider:
    """Load the embedding model once and wrap it. Fail-loud if unavailable.

    Raises:
        ModelLoadError: if sentence-transformers is not installed.
    """
    return SentenceTransformerProvider(_construct_sentence_transformer(settings))


def _construct_sentence_transformer(
    settings: Settings,
) -> _Encoder:  # pragma: no cover
    # reason: imports sentence-transformers/torch and loads model weights; run
    # only under the @pytest.mark.model gated test, never in CI.
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as exc:
        raise ModelLoadError("sentence-transformers is not installed") from exc
    return cast(_Encoder, SentenceTransformer(settings.embedding_model_name))
