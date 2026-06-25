"""Intent-to-action drift detection via embedding cosine similarity.

The user's stated session intent is embedded once and cached; each tool call is
embedded and compared (cosine) against that intent vector. Low similarity is
drift. The detector emits a :class:`~secureSG.schemas.verdict.Verdict` so the
proxy (SP5) can fold it into the same tighten-only escalation as the screener.
"""

from dataclasses import dataclass

from secureSG.exceptions import InferenceError
from secureSG.schemas.verdict import Verdict
from secureSG.warden.embeddings import EmbeddingCache, Vector, cosine_similarity


@dataclass(frozen=True, slots=True)
class DriftAssessment:
    """A call's alignment with session intent and the resulting verdict."""

    similarity: float
    verdict: Verdict


class IntentDriftDetector:
    """Flags tool calls whose embedding drifts from the cached session intent."""

    def __init__(
        self,
        cache: EmbeddingCache,
        *,
        review_threshold: float,
        block_threshold: float,
    ) -> None:
        self._cache = cache
        self._review = review_threshold
        self._block = block_threshold
        self._intent: Vector | None = None

    async def set_intent(self, intent_text: str) -> None:
        """Cache the session intent vector once. O(embedding)."""
        self._intent = await self._cache.get(intent_text)

    async def assess_call(self, call_text: str) -> DriftAssessment:
        """Score a call's alignment with intent; low cosine is drift.

        Raises:
            InferenceError: if called before ``set_intent`` (no grounded intent).

        Time complexity: O(embedding + d). Space complexity: O(1).
        """
        if self._intent is None:
            raise InferenceError("intent vector not set; call set_intent first")
        call_vector = await self._cache.get(call_text)
        similarity = cosine_similarity(self._intent, call_vector)
        return DriftAssessment(
            similarity=similarity, verdict=self._verdict_for(similarity)
        )

    def _verdict_for(self, similarity: float) -> Verdict:
        if similarity >= self._review:
            return Verdict.ALLOW
        if similarity >= self._block:
            return Verdict.HUMAN_APPROVAL_REQUIRED
        return Verdict.BLOCK
