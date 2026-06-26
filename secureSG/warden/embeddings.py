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

import httpx

from secureSG.config.settings import EmbeddingBackend, Settings
from secureSG.exceptions import InferenceError, ModelLoadError

type Vector = list[float]

_EMBED_PATH = "/api/embed"


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


class OllamaEmbeddingProvider(EmbeddingProvider):
    """EmbeddingProvider backed by a local Ollama server's /api/embed (no torch).

    A fresh ``httpx.AsyncClient`` is used per call: requests are stateless and
    idempotent and Ollama serializes its own queue, so no connection or lock is
    owned. Any failure fails closed via ``InferenceError`` — the drift detector's
    caller catches it and blocks (CLAUDE.md section 6), never embedding to a zero
    vector that would silently read as perfect intent alignment.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = f"{base_url.rstrip('/')}{_EMBED_PATH}"
        self._model = model
        self._timeout = timeout
        self._transport = transport

    async def embed(self, texts: list[str]) -> list[Vector]:
        """Embed each text via Ollama, order-preserving; fail closed on error.

        Raises:
            InferenceError: on transport failure, non-2xx status, or a body whose
                shape does not match the request.

        Time complexity: O(sum of text lengths) plus one network round trip.
        Space complexity: O(n * d) for n texts of embedding dimension d.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                response = await client.post(
                    self._url, json={"model": self._model, "input": texts}
                )
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise InferenceError(f"Ollama embedding request failed: {exc}") from exc
        if not isinstance(body, dict):
            raise InferenceError("Ollama returned a non-object embedding response")
        return _extract_embeddings(body, len(texts))


def _extract_embeddings(body: dict[str, Any], expected: int) -> list[Vector]:
    """Validate Ollama's ``embeddings`` matrix and coerce it to ``list[Vector]``.

    Raises:
        InferenceError: if the matrix is missing, the wrong length, or holds a
            malformed or non-numeric row (untrusted external input).

    Time complexity: O(n * d). Space complexity: O(n * d).
    """
    rows = body.get("embeddings")
    if not isinstance(rows, list) or len(rows) != expected:
        raise InferenceError("Ollama embedding response had an unexpected shape")
    result: list[Vector] = []
    for row in rows:
        if not isinstance(row, list) or not row:
            raise InferenceError("Ollama returned a malformed embedding row")
        vector: Vector = []
        for value in row:
            if not isinstance(value, (int, float)):
                raise InferenceError("Ollama embedding contained a non-numeric value")
            vector.append(float(value))
        result.append(vector)
    return result


def load_embedding_provider(settings: Settings) -> EmbeddingProvider:
    """Load the configured embedding provider: sentence-transformers, or Ollama.

    Raises:
        ModelLoadError: if the sentence-transformers wheel is not installed.

    Time complexity: O(model load). Space complexity: O(model size).
    """
    if settings.embedding_provider is EmbeddingBackend.OLLAMA:
        return OllamaEmbeddingProvider(
            settings.ollama_base_url,
            settings.ollama_embedding_model,
            timeout=settings.ollama_request_timeout,
        )
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
