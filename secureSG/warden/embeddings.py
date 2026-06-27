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

from openai import OpenAIError

from secureSG.config.settings import EmbeddingBackend, Settings
from secureSG.exceptions import InferenceError, ModelLoadError

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


class _Embeddings(Protocol):
    async def create(self, *, model: str, input: list[str]) -> Any: ...


class OpenAIEmbeddingClient(Protocol):
    """The minimal slice of ``AsyncOpenAI`` the embedding provider depends on."""

    @property
    def embeddings(self) -> _Embeddings: ...


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """EmbeddingProvider backed by the OpenAI embeddings API (no torch).

    Any failure fails closed via :class:`~secureSG.exceptions.InferenceError` —
    the drift detector's caller catches it and blocks (CLAUDE.md section 6),
    never embedding to a zero vector that would read as perfect intent alignment.
    """

    def __init__(self, client: OpenAIEmbeddingClient, model: str) -> None:
        self._client = client
        self._model = model

    async def embed(self, texts: list[str]) -> list[Vector]:
        """Embed each text via OpenAI, order-preserving; fail closed on error.

        Raises:
            InferenceError: on a client error or a response whose shape or length
                does not match the request.

        Time complexity: O(sum of text lengths) plus one network round trip.
        Space complexity: O(n * d) for n texts of embedding dimension d.
        """
        try:
            response = await self._client.embeddings.create(
                model=self._model, input=texts
            )
        except OpenAIError as exc:
            raise InferenceError(f"OpenAI embedding request failed: {exc}") from exc
        return _extract_openai_embeddings(response, len(texts))


def _extract_openai_embeddings(response: Any, expected: int) -> list[Vector]:
    """Validate the OpenAI ``data`` rows and coerce them to request order.

    Rows are reordered by their ``index`` (untrusted external input): a missing,
    duplicate, or out-of-range index, the wrong count, or a malformed/non-numeric
    vector fails closed (CLAUDE.md section 6).

    Raises:
        InferenceError: if the response shape, length, or any row is invalid.

    Time complexity: O(n * d). Space complexity: O(n * d).
    """
    try:
        rows = list(response.data)
    except (AttributeError, TypeError) as exc:
        raise InferenceError(
            f"OpenAI embedding response had an unexpected shape: {exc}"
        ) from exc
    if len(rows) != expected:
        raise InferenceError("OpenAI embedding response had an unexpected length")
    by_index: dict[int, Vector] = {}
    for row in rows:
        index = getattr(row, "index", None)
        if not isinstance(index, int) or not 0 <= index < expected or index in by_index:
            raise InferenceError("OpenAI embedding row had an invalid index")
        by_index[index] = _coerce_vector(getattr(row, "embedding", None))
    return [by_index[i] for i in range(expected)]


def _coerce_vector(vector: Any) -> Vector:
    """Coerce one embedding row to a non-empty numeric vector (fail-closed)."""
    if not isinstance(vector, list) or not vector:
        raise InferenceError("OpenAI returned a malformed embedding row")
    result: Vector = []
    for value in vector:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InferenceError("OpenAI embedding contained a non-numeric value")
        result.append(float(value))
    return result


def load_embedding_provider(settings: Settings) -> EmbeddingProvider:
    """Load the configured embedding provider: OpenAI, or sentence-transformers.

    Raises:
        ModelLoadError: if OpenAI is selected without an API key, or the
            sentence-transformers wheel is not installed.

    Time complexity: O(model load). Space complexity: O(model size).
    """
    if settings.embedding_provider is EmbeddingBackend.OPENAI:
        if settings.openai_api_key is None:
            raise ModelLoadError(
                "OPENAI_API_KEY is not set; no embedding model to load"
            )
        return OpenAIEmbeddingProvider(
            _build_openai_client(settings), settings.openai_embedding_model
        )
    return SentenceTransformerProvider(_construct_sentence_transformer(settings))


def _build_openai_client(settings: Settings) -> OpenAIEmbeddingClient:
    """Construct the async OpenAI client (no network until first call). O(1)."""
    from openai import AsyncOpenAI

    return cast(
        OpenAIEmbeddingClient,
        AsyncOpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            timeout=settings.openai_request_timeout,
        ),
    )


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
