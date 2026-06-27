"""Tests for embeddings: cosine, cache, provider plumbing, and the loader."""

from typing import Any

import pytest
from openai import OpenAIError

from secureSG.config.settings import Settings
from secureSG.exceptions import InferenceError, ModelLoadError
from secureSG.warden import embeddings
from secureSG.warden.embeddings import (
    EmbeddingCache,
    EmbeddingProvider,
    OpenAIEmbeddingProvider,
    SentenceTransformerProvider,
    Vector,
    cosine_similarity,
)


class _Row:
    def __init__(self, index: object, embedding: object) -> None:
        self.index = index
        self.embedding = embedding


class _Response:
    def __init__(self, data: object) -> None:
        self.data = data


class _Embeddings:
    """Records call kwargs and returns a scripted embeddings response."""

    def __init__(
        self, response: object = None, error: Exception | None = None
    ) -> None:
        self._response = response
        self._error = error
        self.calls: list[dict[str, Any]] = []

    async def create(self, *, model: str, input: list[str]) -> object:
        self.calls.append({"model": model, "input": list(input)})
        if self._error is not None:
            raise self._error
        return self._response


class _Client:
    def __init__(self, embeddings_api: _Embeddings) -> None:
        self.embeddings = embeddings_api


def _openai_provider(
    response: object = None, error: Exception | None = None
) -> tuple[OpenAIEmbeddingProvider, _Embeddings]:
    api = _Embeddings(response=response, error=error)
    return OpenAIEmbeddingProvider(_Client(api), "embed-model"), api


def test_cosine_identical_is_one() -> None:
    assert cosine_similarity([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)


def test_cosine_orthogonal_is_zero() -> None:
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_opposite_is_minus_one() -> None:
    assert cosine_similarity([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)


def test_cosine_zero_vector_is_zero() -> None:
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0


async def test_cache_embeds_each_text_once() -> None:
    seen: list[str] = []

    class _Counting(EmbeddingProvider):
        async def embed(self, texts: list[str]) -> list[Vector]:
            seen.extend(texts)
            return [[1.0, 0.0] for _ in texts]

    cache = EmbeddingCache(_Counting())
    first = await cache.get("alpha")
    again = await cache.get("alpha")
    assert first == again == [1.0, 0.0]
    assert seen == ["alpha"]


async def test_cache_get_many_only_embeds_missing() -> None:
    seen: list[str] = []

    class _Counting(EmbeddingProvider):
        async def embed(self, texts: list[str]) -> list[Vector]:
            seen.extend(texts)
            return [[float(len(text))] for text in texts]

    cache = EmbeddingCache(_Counting())
    await cache.get("ab")
    result = await cache.get_many(["ab", "xyz"])
    assert result == [[2.0], [3.0]]
    assert seen == ["ab", "xyz"]


async def test_cache_get_many_all_cached_skips_embedding() -> None:
    seen: list[str] = []

    class _Counting(EmbeddingProvider):
        async def embed(self, texts: list[str]) -> list[Vector]:
            seen.extend(texts)
            return [[float(len(text))] for text in texts]

    cache = EmbeddingCache(_Counting())
    await cache.get("ab")
    seen.clear()
    result = await cache.get_many(["ab"])
    assert result == [[2.0]]
    assert seen == []


async def test_sentence_transformer_provider_encodes_via_model() -> None:
    class _FakeMatrix:
        def __init__(self, rows: list[Vector]) -> None:
            self._rows = rows

        def tolist(self) -> list[Vector]:
            return self._rows

    class _FakeEncoder:
        def encode(self, texts: list[str]) -> _FakeMatrix:
            return _FakeMatrix([[float(len(text)), 1.0] for text in texts])

    provider = SentenceTransformerProvider(_FakeEncoder())
    vectors = await provider.embed(["ab", "abc"])
    assert vectors == [[2.0, 1.0], [3.0, 1.0]]


async def test_openai_provider_embeds_and_orders_by_index() -> None:
    response = _Response([_Row(1, [3.0, 4.0]), _Row(0, [1.0, 2.0])])
    provider, api = _openai_provider(response=response)
    vectors = await provider.embed(["alpha", "beta"])
    assert vectors == [[1.0, 2.0], [3.0, 4.0]]
    assert api.calls[0] == {"model": "embed-model", "input": ["alpha", "beta"]}


async def test_openai_provider_fails_closed_on_client_error() -> None:
    provider, _ = _openai_provider(error=OpenAIError("boom"))
    with pytest.raises(InferenceError):
        await provider.embed(["alpha"])


async def test_openai_provider_raises_on_count_mismatch() -> None:
    provider, _ = _openai_provider(response=_Response([_Row(0, [1.0])]))
    with pytest.raises(InferenceError):
        await provider.embed(["alpha", "beta"])


async def test_openai_provider_raises_on_invalid_index() -> None:
    provider, _ = _openai_provider(response=_Response([_Row(5, [1.0])]))
    with pytest.raises(InferenceError):
        await provider.embed(["alpha"])


async def test_openai_provider_raises_on_duplicate_index() -> None:
    response = _Response([_Row(0, [1.0]), _Row(0, [2.0])])
    provider, _ = _openai_provider(response=response)
    with pytest.raises(InferenceError):
        await provider.embed(["alpha", "beta"])


async def test_openai_provider_raises_on_empty_row() -> None:
    provider, _ = _openai_provider(response=_Response([_Row(0, [])]))
    with pytest.raises(InferenceError):
        await provider.embed(["alpha"])


async def test_openai_provider_raises_on_non_numeric_value() -> None:
    provider, _ = _openai_provider(response=_Response([_Row(0, [1.0, "x"])]))
    with pytest.raises(InferenceError):
        await provider.embed(["alpha"])


async def test_openai_provider_raises_on_non_iterable_data() -> None:
    provider, _ = _openai_provider(response=_Response(123))
    with pytest.raises(InferenceError):
        await provider.embed(["alpha"])


def test_load_embedding_provider_selects_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    settings = Settings(_env_file=None)  # default embedding_provider is OPENAI
    provider = embeddings.load_embedding_provider(settings)
    assert isinstance(provider, OpenAIEmbeddingProvider)


def test_load_embedding_provider_openai_requires_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=None)
    with pytest.raises(ModelLoadError):
        embeddings.load_embedding_provider(settings)


def test_load_embedding_provider_wraps_sentence_transformer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeEncoder:
        def encode(self, texts: list[str]) -> object:
            raise NotImplementedError

    monkeypatch.setattr(
        embeddings,
        "_construct_sentence_transformer",
        lambda settings: _FakeEncoder(),
    )
    settings = Settings(_env_file=None, embedding_provider="sentence-transformers")
    provider = embeddings.load_embedding_provider(settings)
    assert isinstance(provider, SentenceTransformerProvider)
