"""Ollama-backed GuardFormer: P(unsafe) over HTTP, with zero Python ML wheels.

The judge can run on a local Ollama server instead of an in-process llama-cpp
model. The model still answers the guard prompt with a single SAFE/UNSAFE digit;
this provider reads that digit's token logprobs from Ollama's native
``/api/generate`` response and reuses :mod:`secureSG.models.guard_classifier`
for prompt construction and the logprob->P(unsafe) calibration — identical math
to :class:`~secureSG.models.guardformer.QwenGuardProvider`, only the transport
differs (an ``httpx`` POST instead of a native call). The laptop then needs only
the Ollama app; no torch / llama-cpp wheels are installed.

Every failure — a transport error, a non-2xx status, a non-object body, missing
logprobs, or neither class token among them — is raised as
:class:`~secureSG.exceptions.InferenceError`, so the Screener fails closed
(CLAUDE.md section 6) and never silently allows on a model outage. A fresh
``httpx.AsyncClient`` is used per call: requests are stateless and idempotent,
Ollama serializes its own queue, so no shared connection or lock is owned here.
"""

from typing import Any

import httpx

from secureSG.exceptions import InferenceError
from secureSG.models.guard_classifier import build_guard_prompt, p_unsafe_from_logprobs
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment

_GENERATE_PATH = "/api/generate"


class OllamaGuardProvider(ModelProvider):
    """GuardFormer over a local Ollama server via the native generate API."""

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout: float,
        max_output_tokens: int,
        logprobs_top_k: int,
        author_max_tokens: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = f"{base_url.rstrip('/')}{_GENERATE_PATH}"
        self._model = model
        self._timeout = timeout
        self._max_output_tokens = max_output_tokens
        self._logprobs_top_k = logprobs_top_k
        self._author_max_tokens = author_max_tokens
        self._transport = transport

    async def assess(
        self, content: str, task: AssessmentTask
    ) -> SemanticAssessment:
        """Return P(unsafe) for ``content`` under ``task`` via Ollama logprobs.

        Time complexity: O(prompt) plus one network round trip and a single
        generated token. Space complexity: O(prompt).
        """
        prompt = build_guard_prompt(content, task)
        body = await self._post(
            {
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "logprobs": True,
                "top_logprobs": self._logprobs_top_k,
                "options": {
                    "temperature": 0.0,
                    "num_predict": self._max_output_tokens,
                },
            }
        )
        return SemanticAssessment(
            task=task, p_unsafe=p_unsafe_from_logprobs(_extract_top_logprobs(body))
        )

    async def generate(self, prompt: str, *, grammar: str | None = None) -> str:
        """Generate plain text via Ollama; GBNF grammars are unsupported here.

        Ollama constrains output with a JSON-schema ``format``, not the GBNF
        grammars the llama-cpp authoring path uses, so a non-None ``grammar``
        fails loud (CLAUDE.md: no silent approximation) — keep grammar-constrained
        policy authoring on the llama-cpp provider.

        Time complexity: O(prompt + generated tokens). Space complexity: O(same).
        """
        if grammar is not None:
            raise InferenceError(
                "OllamaGuardProvider does not support GBNF grammars; use the "
                "llama-cpp provider for grammar-constrained policy authoring"
            )
        body = await self._post(
            {
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "options": {
                    "temperature": 0.0,
                    "num_predict": self._author_max_tokens,
                },
            }
        )
        text = body.get("response")
        if not isinstance(text, str):
            raise InferenceError("Ollama response did not contain generated text")
        return text

    async def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to Ollama and return the JSON object body, failing closed.

        Raises:
            InferenceError: on any transport failure, non-2xx status, or a body
                that is not a JSON object.

        Time complexity: O(payload) plus network. Space complexity: O(response).
        """
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                response = await client.post(self._url, json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise InferenceError(f"Ollama request failed: {exc}") from exc
        if not isinstance(body, dict):
            raise InferenceError("Ollama returned a non-object response")
        return body


def _extract_top_logprobs(body: dict[str, Any]) -> dict[str, float]:
    """Convert Ollama's ``logprobs[0].top_logprobs`` list to a token->logprob map.

    Ollama returns ``logprobs`` as a per-generated-token list; element 0 is the
    single digit we requested, and its ``top_logprobs`` is a list of
    ``{token, logprob, bytes}`` candidates. Malformed candidate entries are
    skipped; the structure being absent, or yielding no usable candidate, fails
    closed (CLAUDE.md section 6).

    Raises:
        InferenceError: if the logprob structure is missing or unusable.

    Time complexity: O(k) in the number of candidates. Space complexity: O(k).
    """
    token_logprobs = body.get("logprobs")
    if not isinstance(token_logprobs, list) or not token_logprobs:
        raise InferenceError("Ollama response is missing token logprobs")
    first = token_logprobs[0]
    if not isinstance(first, dict):
        raise InferenceError("Ollama token logprob entry is malformed")
    candidates = first.get("top_logprobs")
    if not isinstance(candidates, list) or not candidates:
        raise InferenceError("Ollama response is missing top_logprobs")
    result: dict[str, float] = {}
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        token = entry.get("token")
        logprob = entry.get("logprob")
        if isinstance(token, str) and isinstance(logprob, (int, float)):
            result[token] = float(logprob)
    if not result:
        raise InferenceError("Ollama top_logprobs contained no usable tokens")
    return result
