"""Tests for the Verdict enum and the PolicyVerdict model."""

import pytest
from pydantic import ValidationError

from secureSG.schemas.verdict import PolicyVerdict, Verdict


def test_verdict_has_exactly_three_members() -> None:
    assert {v.value for v in Verdict} == {
        "ALLOW",
        "BLOCK",
        "HUMAN_APPROVAL_REQUIRED",
    }


def test_verdict_is_a_string() -> None:
    assert isinstance(Verdict.BLOCK, str)
    assert Verdict.ALLOW == "ALLOW"


def test_verdict_round_trips_from_value() -> None:
    assert Verdict("HUMAN_APPROVAL_REQUIRED") is Verdict.HUMAN_APPROVAL_REQUIRED


def test_policy_verdict_holds_fields() -> None:
    decision = PolicyVerdict(
        verdict=Verdict.BLOCK,
        reason="HIGH-taint argument sent to an external-comms tool",
        rule_id="taint.high_to_external",
        tool_name="send_email",
    )
    assert decision.verdict is Verdict.BLOCK
    assert decision.rule_id == "taint.high_to_external"
    assert decision.tool_name == "send_email"


def test_policy_verdict_is_immutable() -> None:
    decision = PolicyVerdict(
        verdict=Verdict.ALLOW, reason="ok", rule_id="policy.read_file", tool_name="x"
    )
    with pytest.raises(ValidationError):
        decision.verdict = Verdict.BLOCK  # type: ignore[misc]  # reason: testing frozen


def test_policy_verdict_rejects_unknown_verdict() -> None:
    with pytest.raises(ValidationError):
        PolicyVerdict(verdict="NOPE", reason="x", rule_id="y", tool_name=None)
