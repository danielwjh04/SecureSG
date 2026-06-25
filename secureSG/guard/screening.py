"""Defense-in-depth content/call screening: signatures first, then the model.

The screener composes two layers. A deterministic Aho-Corasick matcher over
known injection signatures gives reliable, explainable BLOCKs of known attacks.
For content that passes, the semantic ``ModelProvider`` generalizes to novel
attacks, its probability mapped to a verdict by the configured thresholds.

The core safety invariant (SP3 design): the model can only *tighten*.
``assess_call`` returns ``max(deterministic_baseline, model_verdict)`` by
severity, so the model may raise caution but never weaken a deterministic
verdict. Signature and threshold logic are pure functions; only ``assess`` is
async (it calls the model).
"""

import json

from secureSG.config.settings import fail_mode_for
from secureSG.exceptions import InferenceError
from secureSG.guard.matching import AhoCorasick
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask
from secureSG.schemas.tool_call import ToolCallSchema
from secureSG.schemas.verdict import PolicyVerdict, Verdict

_SEVERITY: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.HUMAN_APPROVAL_REQUIRED: 1,
    Verdict.BLOCK: 2,
}

_INJECTION_RULE_IDS: dict[Verdict, str] = {
    Verdict.BLOCK: "injection.semantic",
    Verdict.HUMAN_APPROVAL_REQUIRED: "injection.semantic.review",
    Verdict.ALLOW: "injection.clean",
}


def map_probability_to_verdict(
    p_unsafe: float, *, review: float, block: float
) -> Verdict:
    """Map a probability to a verdict by threshold band. O(1)."""
    if p_unsafe >= block:
        return Verdict.BLOCK
    if p_unsafe >= review:
        return Verdict.HUMAN_APPROVAL_REQUIRED
    return Verdict.ALLOW


def escalate(baseline: Verdict, candidate: Verdict) -> Verdict:
    """Return the more severe verdict; the model may only tighten. O(1)."""
    return candidate if _SEVERITY[candidate] > _SEVERITY[baseline] else baseline


def serialize_call(call: ToolCallSchema) -> str:
    """Render a tool call as deterministic text for semantic adjudication. O(n)."""
    arguments = json.dumps(call.arguments, sort_keys=True, separators=(",", ":"))
    return f"{call.tool_name}({arguments})"


class Screener:
    """Composes signature matching and the semantic model into verdicts."""

    def __init__(
        self,
        *,
        injection_signatures: frozenset[str],
        provider: ModelProvider,
        block_threshold: float,
        review_threshold: float,
    ) -> None:
        self._provider = provider
        self._block = block_threshold
        self._review = review_threshold
        self._signatures: list[str] = sorted(s.lower() for s in injection_signatures)
        self._automaton = AhoCorasick()
        for index, signature in enumerate(self._signatures):
            self._automaton.add(signature, index)

    def _matched_signatures(self, content: str) -> list[str]:
        indices = self._automaton.search(content.lower())
        return sorted(self._signatures[index] for index in indices)

    async def screen_content(self, content: str) -> PolicyVerdict:
        """Screen untrusted content: signatures first, then the semantic model.

        Time complexity: O(content length) + O(inference). Space complexity: O(1).
        """
        matched = self._matched_signatures(content)
        if matched:
            return PolicyVerdict(
                verdict=Verdict.BLOCK,
                reason=f"content matched injection signature(s): {matched}",
                rule_id="injection.signature",
                tool_name=None,
            )
        try:
            assessment = await self._provider.assess(
                content, AssessmentTask.INJECTION_SCAN
            )
        except InferenceError:
            return PolicyVerdict(
                verdict=Verdict.BLOCK,
                reason="semantic injection scan unavailable; failing closed",
                rule_id="injection.unavailable",
                tool_name=None,
            )
        verdict = map_probability_to_verdict(
            assessment.p_unsafe, review=self._review, block=self._block
        )
        return PolicyVerdict(
            verdict=verdict,
            reason=f"semantic injection scan p_unsafe={assessment.p_unsafe:.3f}",
            rule_id=_INJECTION_RULE_IDS[verdict],
            tool_name=None,
        )

    async def assess_call(
        self, call: ToolCallSchema, baseline: PolicyVerdict
    ) -> PolicyVerdict:
        """Adjudicate a flagged call; the model may only tighten ``baseline``.

        Time complexity: O(inference). Space complexity: O(1).
        """
        try:
            assessment = await self._provider.assess(
                serialize_call(call), AssessmentTask.CALL_RISK
            )
        except InferenceError:
            failed = escalate(baseline.verdict, fail_mode_for(call.tool_name))
            if failed is baseline.verdict:
                return baseline
            return PolicyVerdict(
                verdict=failed,
                reason="semantic adjudication unavailable; applied fail mode",
                rule_id="semantic.unavailable",
                tool_name=call.tool_name,
            )
        model_verdict = map_probability_to_verdict(
            assessment.p_unsafe, review=self._review, block=self._block
        )
        final = escalate(baseline.verdict, model_verdict)
        if final is baseline.verdict:
            return baseline
        return PolicyVerdict(
            verdict=final,
            reason=(
                f"semantic call-risk p_unsafe={assessment.p_unsafe:.3f} "
                "escalated the verdict"
            ),
            rule_id="semantic.call_risk",
            tool_name=call.tool_name,
        )
