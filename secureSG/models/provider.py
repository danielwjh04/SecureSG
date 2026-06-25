"""The swappable judge-model seam.

``ModelProvider`` is the only surface that changes when the judge model is
swapped (local Qwen3 -> hosted guard model later). Implementations own their own
prompt formatting; thresholds and verdict mapping stay out of here — they live in
the Screener and settings (CLAUDE.md section 6).
"""

from abc import ABC, abstractmethod

from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment


class ModelProvider(ABC):
    """Scores text for a semantic task, returning a probability that it is unsafe."""

    @abstractmethod
    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment:
        """Return the probability that ``content`` is unsafe for ``task``."""
        ...
