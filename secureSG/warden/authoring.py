"""LLM policy authoring: natural-language intent -> validated, grounded proposal.

The pipeline is defense-in-depth: the model returns a JSON object, then the parsed
output passes a structural gate (``PolicySchema``) and a grounding gate (every
referenced tool must exist) before a :class:`PolicyProposal` is returned. Any
failure raises :class:`AuthoringError`; a partial or unvalidated policy is never
produced. The proposal is a delta fragment that merges into the active policy on
activation — it is never auto-applied.
"""

import json
from dataclasses import dataclass

from pydantic import ValidationError

from secureSG.exceptions import AuthoringError
from secureSG.guard.policy import CompiledPolicy, PolicySchema
from secureSG.guard.taint import TaintTier
from secureSG.models.provider import ModelProvider
from secureSG.schemas.verdict import Verdict


@dataclass(frozen=True, slots=True)
class PolicyDiff:
    """The effect of a proposed policy on the currently active policy."""

    denylist_added: frozenset[str]
    external_comms_added: frozenset[str]
    content_scan_added: frozenset[str]
    tool_rules_changed: dict[str, tuple[Verdict | None, Verdict]]
    taint_sources_changed: dict[str, tuple[TaintTier | None, TaintTier]]

    def is_empty(self) -> bool:
        """Whether the proposal changes nothing vs the current policy. O(1)."""
        return not (
            self.denylist_added
            or self.external_comms_added
            or self.content_scan_added
            or self.tool_rules_changed
            or self.taint_sources_changed
        )

    def render(self) -> str:
        """Human-readable summary of the proposal's effect. O(change count)."""
        lines: list[str] = []
        lines += [f"denylist += {t}" for t in sorted(self.denylist_added)]
        lines += [
            f"external_comms_tools += {t}" for t in sorted(self.external_comms_added)
        ]
        lines += [
            f"content_scan_sources += {t}" for t in sorted(self.content_scan_added)
        ]
        for tool in sorted(self.tool_rules_changed):
            old, new = self.tool_rules_changed[tool]
            previous = old.value if old is not None else "(none)"
            lines.append(f"tool_rules: {tool} {previous} -> {new.value}")
        for tool in sorted(self.taint_sources_changed):
            old_tier, new_tier = self.taint_sources_changed[tool]
            previous = old_tier.name if old_tier is not None else "(none)"
            lines.append(f"taint_sources: {tool} {previous} -> {new_tier.name}")
        return "\n".join(lines) if lines else "(no change vs current policy)"


@dataclass(frozen=True, slots=True)
class PolicyProposal:
    """A validated, grounded policy delta plus its diff and originating intent."""

    policy: PolicySchema
    diff: PolicyDiff
    intent: str


def _build_author_prompt(intent: str, tools: list[str]) -> str:
    """Build the authoring prompt (pure). O(tool count + intent length)."""
    inventory = "\n".join(f"- {tool}" for tool in tools)
    return (
        "You are a security policy author for an AI agent guard. Convert the "
        "operator's intent into a JSON policy.\n\n"
        f"Available tools:\n{inventory}\n\n"
        f"Operator intent: {intent}\n\n"
        "Emit a JSON object with keys denylist, external_comms_tools, "
        "content_scan_sources (arrays of tool names), tool_rules (tool name -> "
        "one of ALLOW/BLOCK/HUMAN_APPROVAL_REQUIRED), and taint_sources (tool "
        "name -> one of LOW/MEDIUM/HIGH). Use only the listed tools. JSON:"
    )


def _parse_and_validate(raw: str, inventory: frozenset[str]) -> PolicySchema:
    """Parse, structurally validate, and ground-check generated policy JSON.

    Raises:
        AuthoringError: on malformed JSON, schema violation, or an ungrounded tool.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthoringError(f"model did not return valid JSON: {exc}") from exc
    try:
        proposed = PolicySchema.model_validate(data)
    except ValidationError as exc:
        raise AuthoringError(
            f"generated policy failed schema validation: {exc}"
        ) from exc
    referenced = (
        set(proposed.denylist)
        | set(proposed.external_comms_tools)
        | set(proposed.content_scan_sources)
        | set(proposed.tool_rules)
        | set(proposed.taint_sources)
    )
    unknown = sorted(referenced - inventory)
    if unknown:
        raise AuthoringError(f"policy references tools not in the inventory: {unknown}")
    return proposed


def _compute_diff(current: CompiledPolicy, proposed: PolicySchema) -> PolicyDiff:
    """Diff a proposed delta against the active policy. O(proposal size)."""
    return PolicyDiff(
        denylist_added=frozenset(proposed.denylist) - current.denylist,
        external_comms_added=(
            frozenset(proposed.external_comms_tools) - current.external_comms_tools
        ),
        content_scan_added=(
            frozenset(proposed.content_scan_sources) - current.content_scan_sources
        ),
        tool_rules_changed={
            tool: (current.rule_for(tool), verdict)
            for tool, verdict in proposed.tool_rules.items()
            if current.rule_for(tool) != verdict
        },
        taint_sources_changed={
            tool: (current.taint_tier_for_source(tool), tier)
            for tool, tier in proposed.taint_sources.items()
            if current.taint_tier_for_source(tool) != tier
        },
    )


async def author_policy(
    provider: ModelProvider,
    intent: str,
    *,
    tools: list[str],
    current_policy: CompiledPolicy,
) -> PolicyProposal:
    """Author a validated, tool-grounded policy proposal from plain-language intent.

    Raises:
        AuthoringError: on any generation/parse/validation/grounding failure.
        ValueError: if the tool inventory is empty.

    Time complexity: O(inference) + O(proposal size). Space complexity: O(same).
    """
    prompt = _build_author_prompt(intent, tools)
    raw = await provider.generate(prompt)
    proposed = _parse_and_validate(raw, frozenset(tools))
    diff = _compute_diff(current_policy, proposed)
    return PolicyProposal(policy=proposed, diff=diff, intent=intent)
