"""Tests for the rule_id -> attack-category mapping."""

import pytest

from secureSG.dashboard.categories import category_for


@pytest.mark.parametrize(
    ("rule_id", "category"),
    [
        ("injection.signature", "Prompt Injection"),
        ("injection.semantic", "Prompt Injection"),
        ("injection.clean", "Clean Content"),
        ("taint.high_to_external", "Data Exfiltration"),
        ("trajectory.sensitive_to_external", "Exfiltration Sequence"),
        ("trajectory.clear", "Exfiltration Sequence"),
        ("drift.intent", "Intent Drift"),
        ("denylist", "Forbidden Tool"),
        ("schema.invalid", "Malformed Request"),
        ("semantic.call_risk", "Semantic Risk"),
        ("default.fail_mode", "Unconfigured Tool"),
        ("policy.read_file", "Allowed by Policy"),
        ("content.untracked", "Clean Content"),
        ("mystery.rule", "Other"),
        ("", "Other"),
    ],
)
def test_category_for(rule_id: str, category: str) -> None:
    assert category_for(rule_id) == category
