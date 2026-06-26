"""Tests for embeddings: cosine, cache, provider plumbing, and the loader."""

import json
from collections.abc import Callable

import httpx
import pytest

from secureSG.config.settings import Settings
from secureSG.exceptions import InferenceError
from secureSG.warden import embeddings
from secureSG.warden.embeddings import (
    EmbeddingCache,
    EmbeddingProvider,
    OllamaEmbeddingProvider,
    SentenceTransformerProvider,
    Vector,
    cosine_similarity,
)

_Handler = Callable[[httpx.Request], httpx.Response]


def _ollama_provider(handler: _Handler) -> OllamaEmbeddingProvider:
    return OllamaEmbeddingProvider(
        "http://localhost:11434",
        "embed-model",
        timeout=5.0,
        transport=httpx.MockTransport(handler),
    )


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


def test_load_embedding_provider_wraps_construction(
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
    provider = embeddings.load_embedding_provider(Settings(_env_file=None))
    assert isinstance(provider, SentenceTransformerProvider)


async def test_ollama_embedding_provider_embeds_via_http() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"embeddings": [[1.0, 2.0], [3.0, 4.0]]})

    vectors = await _ollama_provider(handler).embed(["alpha", "beta"])
    assert vectors == [[1.0, 2.0], [3.0, 4.0]]
    assert captured["url"] == "http://localhost:11434/api/embed"
    assert captured["body"] == {"model": "embed-model", "input": ["alpha", "beta"]}


async def test_ollama_embedding_provider_raises_on_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha"])


async def test_ollama_embedding_provider_raises_on_error_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model not found"})

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha"])


async def test_ollama_embedding_provider_raises_on_non_object_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[[1.0, 2.0]])

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha"])


async def test_ollama_embedding_provider_raises_on_count_mismatch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embeddings": [[1.0, 2.0]]})

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha", "beta"])


async def test_ollama_embedding_provider_raises_on_malformed_row() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embeddings": ["not-a-vector"]})

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha"])


async def test_ollama_embedding_provider_raises_on_empty_row() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embeddings": [[]]})

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha"])


async def test_ollama_embedding_provider_raises_on_non_numeric_value() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embeddings": [[1.0, "oops"]]})

    with pytest.raises(InferenceError):
        await _ollama_provider(handler).embed(["alpha"])


def test_load_embedding_provider_selects_ollama() -> None:
    settings = Settings(_env_file=None, embedding_provider="ollama")
    provider = embeddings.load_embedding_provider(settings)
    assert isinstance(provider, OllamaEmbeddingProvider)
