"""Tests for the LLM policy authoring pipeline (parse + validate + ground + diff)."""

import json

import pytest

from secureSG.exceptions import AuthoringError
from secureSG.guard.policy import CompiledPolicy
from secureSG.guard.taint import TaintTier
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment
from secureSG.schemas.verdict import Verdict
from secureSG.warden.authoring import PolicyDiff, author_policy

EMPTY = CompiledPolicy(
    denylist=frozenset(),
    external_comms_tools=frozenset(),
    taint_sources={},
    tool_rules={},
    injection_signatures=frozenset(),
    content_scan_sources=frozenset(),
)


class _AuthorStub(ModelProvider):
    """A ModelProvider whose generate returns a scripted policy string."""

    def __init__(self, output: str) -> None:
        self._output = output

    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment:
        raise NotImplementedError

    async def generate(self, prompt: str, *, grammar: str | None = None) -> str:
        return self._output


async def test_author_produces_valid_grounded_proposal() -> None:
    output = json.dumps(
        {
            "denylist": ["execute_shell"],
            "external_comms_tools": [],
            "content_scan_sources": [],
            "tool_rules": {"send_email": "HUMAN_APPROVAL_REQUIRED"},
            "taint_sources": {},
        }
    )
    proposal = await author_policy(
        _AuthorStub(output),
        "lock down shell and gate email",
        tools=["execute_shell", "send_email"],
        current_policy=EMPTY,
    )
    assert "execute_shell" in proposal.policy.denylist
    assert proposal.policy.tool_rules["send_email"] is Verdict.HUMAN_APPROVAL_REQUIRED
    assert proposal.intent == "lock down shell and gate email"


async def test_author_rejects_malformed_json() -> None:
    with pytest.raises(AuthoringError):
        await author_policy(
            _AuthorStub("definitely not json {{"),
            "x",
            tools=["read_file"],
            current_policy=EMPTY,
        )


async def test_author_rejects_schema_invalid_output() -> None:
    with pytest.raises(AuthoringError):
        await author_policy(
            _AuthorStub(json.dumps({"tool_rules": {"read_file": "NOPE"}})),
            "x",
            tools=["read_file"],
            current_policy=EMPTY,
        )


async def test_author_rejects_ungrounded_tool() -> None:
    with pytest.raises(AuthoringError, match="not in the inventory"):
        await author_policy(
            _AuthorStub(json.dumps({"denylist": ["nonexistent_tool"]})),
            "x",
            tools=["read_file"],
            current_policy=EMPTY,
        )


async def test_diff_reports_all_field_additions() -> None:
    output = json.dumps(
        {
            "denylist": ["execute_shell"],
            "external_comms_tools": ["send_email"],
            "content_scan_sources": ["scrape_page"],
            "tool_rules": {"read_file": "HUMAN_APPROVAL_REQUIRED"},
            "taint_sources": {"read_secret": "HIGH"},
        }
    )
    tools = ["execute_shell", "send_email", "scrape_page", "read_file", "read_secret"]
    proposal = await author_policy(
        _AuthorStub(output), "broad policy", tools=tools, current_policy=EMPTY
    )
    diff = proposal.diff
    assert not diff.is_empty()
    assert "execute_shell" in diff.denylist_added
    assert "send_email" in diff.external_comms_added
    assert "scrape_page" in diff.content_scan_added
    assert diff.tool_rules_changed["read_file"] == (
        None,
        Verdict.HUMAN_APPROVAL_REQUIRED,
    )
    assert diff.taint_sources_changed["read_secret"] == (None, TaintTier.HIGH)
    rendered = diff.render()
    for token in tools:
        assert token in rendered


async def test_diff_reports_value_changes_against_existing_policy() -> None:
    current = CompiledPolicy(
        denylist=frozenset(),
        external_comms_tools=frozenset(),
        taint_sources={"read_secret": TaintTier.MEDIUM},
        tool_rules={"send_email": Verdict.ALLOW},
        injection_signatures=frozenset(),
        content_scan_sources=frozenset(),
    )
    output = json.dumps(
        {
            "tool_rules": {"send_email": "BLOCK"},
            "taint_sources": {"read_secret": "HIGH"},
        }
    )
    proposal = await author_policy(
        _AuthorStub(output),
        "tighten",
        tools=["send_email", "read_secret"],
        current_policy=current,
    )
    assert proposal.diff.tool_rules_changed["send_email"] == (
        Verdict.ALLOW,
        Verdict.BLOCK,
    )
    assert proposal.diff.taint_sources_changed["read_secret"] == (
        TaintTier.MEDIUM,
        TaintTier.HIGH,
    )
    rendered = proposal.diff.render()
    assert "ALLOW -> BLOCK" in rendered
    assert "MEDIUM -> HIGH" in rendered


def test_empty_diff_is_empty_and_renders_no_change() -> None:
    diff = PolicyDiff(
        denylist_added=frozenset(),
        external_comms_added=frozenset(),
        content_scan_added=frozenset(),
        tool_rules_changed={},
        taint_sources_changed={},
    )
    assert diff.is_empty()
    assert "no change" in diff.render()
