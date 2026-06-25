"""Tests for the Verdict enum."""

from secureSG.schemas.verdict import Verdict


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
