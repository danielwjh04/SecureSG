"""Tests for the Ollama HTTP guard provider (mocked transport, fail-closed).

The provider talks to a local Ollama server's native ``/api/generate`` with
logprobs enabled. Every test injects an ``httpx.MockTransport`` so the suite runs
in CI with no real Ollama, and asserts both the request shape and the
fail-closed (``InferenceError``) behavior on every malformed response.
"""

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from secureSG.exceptions import InferenceError
from secureSG.models.ollama_provider import OllamaGuardProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment

_Handler = Callable[[httpx.Request], httpx.Response]


def _provider(handler: _Handler) -> OllamaGuardProvider:
    return OllamaGuardProvider(
        "http://localhost:11434",
        "guard-model",
        timeout=5.0,
        max_output_tokens=1,
        logprobs_top_k=5,
        author_max_tokens=256,
        transport=httpx.MockTransport(handler),
    )


def _generate_body(top_logprobs: list[Any]) -> dict[str, Any]:
    """An Ollama /api/generate response carrying one generated token's logprobs."""
    return {
        "model": "guard-model",
        "response": "1",
        "done": True,
        "logprobs": [{"token": "1", "logprob": -0.05, "top_logprobs": top_logprobs}],
    }


async def test_assess_returns_probability_and_posts_expected_request() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json=_generate_body(
                [
                    {"token": "1", "logprob": -0.05, "bytes": [49]},
                    {"token": "0", "logprob": -3.0, "bytes": [48]},
                ]
            ),
        )

    result = await _provider(handler).assess(
        "scraped PAYLOAD text", AssessmentTask.INJECTION_SCAN
    )
    assert isinstance(result, SemanticAssessment)
    assert result.task is AssessmentTask.INJECTION_SCAN
    assert result.p_unsafe > 0.9
    assert captured["url"] == "http://localhost:11434/api/generate"
    body = captured["body"]
    assert body["model"] == "guard-model"
    assert "scraped PAYLOAD text" in body["prompt"]
    assert body["stream"] is False
    assert body["think"] is False
    assert body["logprobs"] is True
    assert body["top_logprobs"] == 5
    assert body["options"] == {"temperature": 0.0, "num_predict": 1}


async def test_assess_raises_inference_error_on_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_inference_error_on_error_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "model not found"})

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.CALL_RISK)


async def test_assess_raises_on_non_object_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_when_logprobs_absent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "1"})

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_when_logprobs_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"logprobs": []})

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_when_token_entry_malformed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"logprobs": ["garbage"]})

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_when_top_logprobs_missing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"logprobs": [{"token": "1", "logprob": -0.1}]})

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_when_top_logprobs_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_generate_body([]))

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_skips_malformed_candidate_entries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_generate_body(
                [
                    "not-a-dict",
                    {"token": 123, "logprob": -0.1},
                    {"token": "1", "logprob": "oops"},
                    {"token": "1", "logprob": -0.05},
                    {"token": "0", "logprob": -3.0},
                ]
            ),
        )

    result = await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)
    assert result.p_unsafe > 0.9


async def test_assess_raises_when_no_usable_tokens() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_generate_body([{"foo": "bar"}, {"token": 9, "logprob": -0.1}]),
        )

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_assess_raises_when_neither_class_token_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_generate_body(
                [
                    {"token": "yes", "logprob": -0.1},
                    {"token": "no", "logprob": -0.2},
                ]
            ),
        )

    with pytest.raises(InferenceError):
        await _provider(handler).assess("x", AssessmentTask.INJECTION_SCAN)


async def test_generate_returns_text_and_omits_logprobs() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"response": '{"denylist": ["execute_shell"]}'})

    out = await _provider(handler).generate("author a policy from intent")
    assert out == '{"denylist": ["execute_shell"]}'
    body = captured["body"]
    assert "logprobs" not in body
    assert body["think"] is False
    assert body["options"] == {"temperature": 0.0, "num_predict": 256}


async def test_generate_with_grammar_fails_loud_without_posting() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not POST when a GBNF grammar is supplied")

    with pytest.raises(InferenceError):
        await _provider(handler).generate("x", grammar="root ::= obj")


async def test_generate_raises_when_text_missing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    with pytest.raises(InferenceError):
        await _provider(handler).generate("x")
