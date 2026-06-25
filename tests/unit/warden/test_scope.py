"""Tests for scope reduction (risks -> recommended denylist policy delta)."""

from secureSG.warden.discovery import ToolRisk
from secureSG.warden.scope import ScopeReducer


def _risk(name: str, score: float, is_risky: bool) -> ToolRisk:
    return ToolRisk(tool_name=name, risk_score=score, is_risky=is_risky)


def test_generate_denylist_filters_risky_tools() -> None:
    reducer = ScopeReducer()
    risks = [_risk("a", 0.9, True), _risk("b", 0.1, False), _risk("c", 0.8, True)]
    assert reducer.generate_denylist(risks) == frozenset({"a", "c"})


def test_generate_scope_is_a_sorted_denylist_policy_delta() -> None:
    reducer = ScopeReducer()
    risks = [_risk("c", 0.9, True), _risk("a", 0.8, True), _risk("b", 0.1, False)]
    scope = reducer.generate_scope(risks)
    assert scope.denylist == ["a", "c"]
    assert scope.tool_rules == {}
    assert scope.external_comms_tools == []


def test_no_risky_tools_yields_empty_scope() -> None:
    scope = ScopeReducer().generate_scope([_risk("a", 0.1, False)])
    assert scope.denylist == []
