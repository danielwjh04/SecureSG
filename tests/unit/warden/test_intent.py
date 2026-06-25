"""Tests for intent-to-action drift detection."""

from collections.abc import Callable

import pytest

from secureSG.exceptions import InferenceError
from secureSG.schemas.verdict import Verdict
from secureSG.warden.embeddings import EmbeddingCache, EmbeddingProvider, Vector
from secureSG.warden.intent import IntentDriftDetector

# intent=[1,0]: aligned cos=1.0 (>=0.45 ALLOW); mid cos~0.287 ([0.20,0.45) HAR);
# far cos=0.0 (<0.20 BLOCK).
_VECTORS: dict[str, Vector] = {
    "intent": [1.0, 0.0],
    "aligned": [1.0, 0.0],
    "mid": [0.3, 1.0],
    "far": [0.0, 1.0],
}


def _detector(make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider]) -> (
    IntentDriftDetector
):
    cache = EmbeddingCache(make_embedder(_VECTORS))
    return IntentDriftDetector(cache, review_threshold=0.45, block_threshold=0.20)


async def test_aligned_call_is_allowed(
    make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider],
) -> None:
    detector = _detector(make_embedder)
    await detector.set_intent("intent")
    assessment = await detector.assess_call("aligned")
    assert assessment.verdict is Verdict.ALLOW
    assert assessment.similarity == pytest.approx(1.0)


async def test_mid_drift_requires_human_approval(
    make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider],
) -> None:
    detector = _detector(make_embedder)
    await detector.set_intent("intent")
    assert (await detector.assess_call("mid")).verdict is (
        Verdict.HUMAN_APPROVAL_REQUIRED
    )


async def test_far_drift_is_blocked(
    make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider],
) -> None:
    detector = _detector(make_embedder)
    await detector.set_intent("intent")
    assert (await detector.assess_call("far")).verdict is Verdict.BLOCK


async def test_assess_before_set_intent_fails_closed(
    make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider],
) -> None:
    detector = _detector(make_embedder)
    with pytest.raises(InferenceError):
        await detector.assess_call("aligned")
