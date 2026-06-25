"""Semantic assessment contracts: the question asked and the model's answer.

``AssessmentTask`` names which semantic question the guard model is answering;
``SemanticAssessment`` carries the resulting probability that the inspected text
is unsafe. The probability — not a parsed verdict — is the model's output, per
CLAUDE.md section 6; the ALLOW/HUMAN_APPROVAL_REQUIRED/BLOCK thresholds live in
settings, never here.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AssessmentTask(StrEnum):
    """Which semantic question the model is being asked."""

    INJECTION_SCAN = "INJECTION_SCAN"  # untrusted content -> P(prompt injection)
    CALL_RISK = "CALL_RISK"  # serialized tool call -> P(malicious action)


class SemanticAssessment(BaseModel):
    """A model's probability that a piece of content is unsafe for its task."""

    model_config = ConfigDict(frozen=True)

    task: AssessmentTask
    p_unsafe: float = Field(ge=0.0, le=1.0)
