"""Policy verdict engine: a typed IR loaded from YAML plus the enforcer.

Policy is authored as typed YAML, validated, then compiled into O(1)-lookup
structures. The :class:`Enforcer` decides verdicts from the compiled policy and
records each decision to the audit chain. Deterministic rules (denylist, taint,
tool rules) decide on their own; an optional :class:`~secureSG.guard.screening.Screener`
adds the semantic layer, consulted only on flagged calls and on untrusted tool
results, and only ever to *tighten* a verdict.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import fail_mode_for
from secureSG.exceptions import ModelError, PolicyError
from secureSG.guard.screening import Screener
from secureSG.guard.taint import SessionTaintStore, TaintLabel, TaintTier
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.tool_call import JsonValue, ToolCallSchema, ToolResult
from secureSG.schemas.verdict import PolicyVerdict, Verdict


class PolicySchema(BaseModel):
    """Validated on-disk policy; one or more YAML files merge into this shape."""

    model_config = ConfigDict(extra="forbid")

    denylist: list[str] = Field(default_factory=list)
    external_comms_tools: list[str] = Field(default_factory=list)
    taint_sources: dict[str, TaintTier] = Field(default_factory=dict)
    tool_rules: dict[str, Verdict] = Field(default_factory=dict)
    injection_signatures: list[str] = Field(default_factory=list)
    content_scan_sources: list[str] = Field(default_factory=list)

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
    injection_signatures: frozenset[str]
    content_scan_sources: frozenset[str]

    def is_denied(self, tool: str) -> bool:
        """Whether a tool is unconditionally blocked. O(1)."""
        return tool in self.denylist

    def is_external_comms(self, tool: str) -> bool:
        """Whether a tool is an external-communication sink. O(1)."""
        return tool in self.external_comms_tools

    def is_content_scan_source(self, tool: str) -> bool:
        """Whether a tool's results are untrusted content to scan. O(1)."""
        return tool in self.content_scan_sources

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
            injection_signatures=[
                *merged.injection_signatures,
                *partial.injection_signatures,
            ],
            content_scan_sources=[
                *merged.content_scan_sources,
                *partial.content_scan_sources,
            ],
        )
    return CompiledPolicy(
        denylist=frozenset(merged.denylist),
        external_comms_tools=frozenset(merged.external_comms_tools),
        taint_sources=dict(merged.taint_sources),
        tool_rules=dict(merged.tool_rules),
        injection_signatures=frozenset(merged.injection_signatures),
        content_scan_sources=frozenset(merged.content_scan_sources),
    )


def _result_text(result: JsonValue) -> str:
    """Flatten a tool result to text for content screening. O(result size)."""
    if isinstance(result, str):
        return result
    return json.dumps(result, sort_keys=True)


class Enforcer:
    """Verdict engine over deterministic policy and an optional semantic screener."""

    def __init__(
        self,
        policy: CompiledPolicy,
        audit_logger: AuditLogger,
        screener: Screener | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit_logger
        self._screener = screener

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
        """Decide a verdict for a call, optionally adjudicate it, and audit it.

        ``_decide`` is the pure deterministic baseline. When a screener is present
        and the baseline is flagged (no rule, or HUMAN_APPROVAL_REQUIRED) and not
        already BLOCK, the semantic model may *tighten* it. The final verdict is
        appended to the audit chain idempotently.

        Time complexity: O(argument size) + optional O(inference) + O(1) append.
        """
        verdict = self._decide(raw_call, taint_store)
        if self._screener is not None and self._should_adjudicate(verdict):
            call = ToolCallSchema.model_validate(raw_call)
            verdict = await self._screener.assess_call(call, verdict)
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

    @staticmethod
    def _should_adjudicate(baseline: PolicyVerdict) -> bool:
        """Whether a baseline is a flagged, non-BLOCK call for the model. O(1)."""
        if baseline.verdict is Verdict.BLOCK:
            return False
        return (
            baseline.rule_id == "default.fail_mode"
            or baseline.verdict is Verdict.HUMAN_APPROVAL_REQUIRED
        )

    async def screen_result(
        self, result: ToolResult, transaction_id: UUID
    ) -> PolicyVerdict:
        """Screen an untrusted tool result for injection and audit the verdict.

        Results from tools that are not content-scan sources pass through
        untouched. Scanning a scan-source result requires a screener.

        Raises:
            ModelError: if a scan-source result arrives but no screener exists.

        Time complexity: O(result size) + O(inference) + O(1) audit append.
        """
        if not self._policy.is_content_scan_source(result.tool_name):
            verdict = PolicyVerdict(
                verdict=Verdict.ALLOW,
                reason=f"'{result.tool_name}' results are not scanned for injection",
                rule_id="content.untracked",
                tool_name=result.tool_name,
            )
        elif self._screener is None:
            raise ModelError(
                "content screening requested but no screener is configured"
            )
        else:
            decision = await self._screener.screen_content(
                _result_text(result.result)
            )
            verdict = decision.model_copy(update={"tool_name": result.tool_name})
        await self._audit.append(
            AuditRecord(
                transaction_id=transaction_id,
                created_at=datetime.now(UTC),
                verdict=verdict.verdict,
                tool_name=result.tool_name,
                details={"reason": verdict.reason, "rule_id": verdict.rule_id},
            )
        )
        return verdict
