"""Tests for the tool-grounded policy grammar builder."""

import pytest

from secureSG.warden.grammar import build_policy_grammar


def test_grammar_grounds_tool_names() -> None:
    grammar = build_policy_grammar(["execute_shell", "send_email"])
    assert "execute_shell" in grammar
    assert "send_email" in grammar


def test_grammar_includes_verdict_and_tier_enums() -> None:
    grammar = build_policy_grammar(["read_file"])
    for token in ("ALLOW", "BLOCK", "HUMAN_APPROVAL_REQUIRED", "LOW", "MEDIUM", "HIGH"):
        assert token in grammar


def test_grammar_includes_all_policy_fields() -> None:
    grammar = build_policy_grammar(["read_file"])
    for field in (
        "denylist",
        "external_comms_tools",
        "content_scan_sources",
        "tool_rules",
        "taint_sources",
    ):
        assert field in grammar


def test_grammar_starts_with_root_rule() -> None:
    assert build_policy_grammar(["read_file"]).startswith("root ::=")


def test_empty_inventory_raises_value_error() -> None:
    with pytest.raises(ValueError, match="empty tool inventory"):
        build_policy_grammar([])
