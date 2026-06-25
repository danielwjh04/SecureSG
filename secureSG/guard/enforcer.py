"""Deterministic policy: a typed IR loaded from YAML, plus the verdict engine.

Policy is authored as typed YAML, validated, then compiled into O(1)-lookup
structures. The :class:`Enforcer` consults the compiled policy to decide verdicts
deterministically (the model is never used here) and records each decision to the
audit chain.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import fail_mode_for
from secureSG.exceptions import PolicyError
from secureSG.guard.taint import SessionTaintStore, TaintLabel, TaintTier
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.tool_call import ToolCallSchema, ToolResult
from secureSG.schemas.verdict import PolicyVerdict, Verdict


class PolicySchema(BaseModel):
    """Validated on-disk policy; one or more YAML files merge into this shape."""

    model_config = ConfigDict(extra="forbid")

    denylist: list[str] = Field(default_factory=list)
    external_comms_tools: list[str] = Field(default_factory=list)
    taint_sources: dict[str, TaintTier] = Field(default_factory=dict)
    tool_rules: dict[str, Verdict] = Field(default_factory=dict)

    @field_validator("taint_sources", mode="before")
    @classmethod
    def _tiers_by_name(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        coerced: dict[str, TaintTier] = {}
        for tool, tier in value.items():
            if isinstance(tier, str):
                try:
                    coerced[tool] = TaintTier[tier]
                except KeyError as exc:
                    raise ValueError(f"unknown taint tier: {tier!r}") from exc
            else:
                coerced[tool] = tier
        return coerced


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Compiled, O(1)-lookup form of the merged policy."""

    denylist: frozenset[str]
    external_comms_tools: frozenset[str]
    taint_sources: dict[str, TaintTier]
    tool_rules: dict[str, Verdict]

    def is_denied(self, tool: str) -> bool:
        """Whether a tool is unconditionally blocked. O(1)."""
        return tool in self.denylist

    def is_external_comms(self, tool: str) -> bool:
        """Whether a tool is an external-communication sink. O(1)."""
        return tool in self.external_comms_tools

    def taint_tier_for_source(self, tool: str) -> TaintTier | None:
        """The taint tier a tool's output carries, if it is a source. O(1)."""
        return self.taint_sources.get(tool)

    def rule_for(self, tool: str) -> Verdict | None:
        """The affirmative verdict for a tool, if one is defined. O(1)."""
        return self.tool_rules.get(tool)


def load_policy(policy_dir: Path) -> CompiledPolicy:
    """Load and merge every ``*.yaml`` policy file in a directory.

    Raises:
        PolicyError: if any policy file is malformed.

    Time complexity: O(total policy size). Space complexity: O(rule count).
    """
    merged = PolicySchema()
    for path in sorted(policy_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            partial = PolicySchema.model_validate(data)
        except (yaml.YAMLError, ValidationError) as exc:
            raise PolicyError(f"invalid policy file {path.name}: {exc}") from exc
        merged = PolicySchema(
            denylist=[*merged.denylist, *partial.denylist],
            external_comms_tools=[
                *merged.external_comms_tools,
                *partial.external_comms_tools,
            ],
            taint_sources={**merged.taint_sources, **partial.taint_sources},
            tool_rules={**merged.tool_rules, **partial.tool_rules},
        )
    return CompiledPolicy(
        denylist=frozenset(merged.denylist),
        external_comms_tools=frozenset(merged.external_comms_tools),
        taint_sources=dict(merged.taint_sources),
        tool_rules=dict(merged.tool_rules),
    )


class Enforcer:
    """Deterministic verdict engine; records every decision to the audit chain."""

    def __init__(self, policy: CompiledPolicy, audit_logger: AuditLogger) -> None:
        self._policy = policy
        self._audit = audit_logger

    def observe_result(
        self, result: ToolResult, taint_store: SessionTaintStore
    ) -> None:
        """Register taint from a tool result if its source tool is sensitive.

        Time complexity: O(result string length). Space complexity: O(same).
        """
        tier = self._policy.taint_tier_for_source(result.tool_name)
        if tier is not None:
            taint_store.ingest(result.result, TaintLabel(result.tool_name, tier))

    def _decide(
        self, raw_call: dict[str, Any], taint_store: SessionTaintStore
    ) -> PolicyVerdict:
        try:
            call = ToolCallSchema.model_validate(raw_call)
        except ValidationError:
            return PolicyVerdict(
                verdict=Verdict.BLOCK,
                reason="inbound call failed JSON-RPC schema validation",
                rule_id="schema.invalid",
                tool_name=None,
            )
        tool = call.tool_name
        if self._policy.is_denied(tool):
            return PolicyVerdict(
                verdict=Verdict.BLOCK,
                reason=f"tool '{tool}' is denylisted",
                rule_id="denylist",
                tool_name=tool,
            )
        if self._policy.is_external_comms(tool):
            tainted = taint_store.scan_arguments(call.arguments)
            high = sorted(f for f, t in tainted.items() if t is TaintTier.HIGH)
            if high:
                return PolicyVerdict(
                    verdict=Verdict.BLOCK,
                    reason=(
                        f"HIGH-taint argument(s) {high} sent to "
                        f"external-comms tool '{tool}'"
                    ),
                    rule_id="taint.high_to_external",
                    tool_name=tool,
                )
        rule = self._policy.rule_for(tool)
        if rule is not None:
            return PolicyVerdict(
                verdict=rule,
                reason=f"policy rule for '{tool}'",
                rule_id=f"policy.{tool}",
                tool_name=tool,
            )
        return PolicyVerdict(
            verdict=fail_mode_for(tool),
            reason=f"no policy rule for '{tool}'; applied fail mode",
            rule_id="default.fail_mode",
            tool_name=tool,
        )

    async def evaluate(
        self,
        raw_call: dict[str, Any],
        taint_store: SessionTaintStore,
        transaction_id: UUID,
    ) -> PolicyVerdict:
        """Decide a verdict for a call and append it to the audit chain.

        The decision (``_decide``) is pure; this method adds the idempotent audit
        append. Time complexity: O(argument size) decision + O(1) audit append.
        """
        verdict = self._decide(raw_call, taint_store)
        await self._audit.append(
            AuditRecord(
                transaction_id=transaction_id,
                created_at=datetime.now(UTC),
                verdict=verdict.verdict,
                tool_name=verdict.tool_name,
                details={"reason": verdict.reason, "rule_id": verdict.rule_id},
            )
        )
        return verdict
