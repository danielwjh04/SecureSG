"""Tests for the semantic assessment schema."""

import pytest
from pydantic import ValidationError

from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment


def test_assessment_task_has_two_members() -> None:
    assert {t.value for t in AssessmentTask} == {"INJECTION_SCAN", "CALL_RISK"}


def test_semantic_assessment_holds_fields() -> None:
    assessment = SemanticAssessment(task=AssessmentTask.INJECTION_SCAN, p_unsafe=0.73)
    assert assessment.task is AssessmentTask.INJECTION_SCAN
    assert assessment.p_unsafe == 0.73


def test_semantic_assessment_is_immutable() -> None:
    assessment = SemanticAssessment(task=AssessmentTask.CALL_RISK, p_unsafe=0.1)
    with pytest.raises(ValidationError):
        assessment.p_unsafe = 0.9  # type: ignore[misc]  # reason: testing frozen


@pytest.mark.parametrize("bad", [-0.01, 1.01])
def test_semantic_assessment_rejects_out_of_range_probability(bad: float) -> None:
    with pytest.raises(ValidationError):
        SemanticAssessment(task=AssessmentTask.CALL_RISK, p_unsafe=bad)
