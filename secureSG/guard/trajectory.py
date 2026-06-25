"""Bounded per-session call trajectory with one sequence-based escalation rule.

The trajectory remembers a bounded window of recent ``(tool, verdict)`` pairs
and applies a single tighten-only rule: if a HIGH-taint source tool was earlier
*allowed* in the session and the current call targets an external-communication
sink, escalate to BLOCK. This is a defense-in-depth backstop for exfiltration
that field-level taint missed — for example, a secret the agent paraphrased
before sending, so the literal value never appears in the outbound arguments.

The "earlier allowed HIGH-taint source" condition is kept as an O(1) running
counter, maintained on every append/eviction, so :meth:`assess` never scans the
buffer (CLAUDE.md section 2: runtime lookups target O(1)).
"""

from collections import deque

from secureSG.guard.policy import CompiledPolicy
from secureSG.guard.taint import TaintTier
from secureSG.schemas.verdict import PolicyVerdict, Verdict


class SessionTrajectory:
    """Bounded ``(tool, verdict)`` history plus the sensitive-then-external rule."""

    def __init__(self, policy: CompiledPolicy, *, max_depth: int) -> None:
        self._policy = policy
        self._max_depth = max_depth
        self._history: deque[tuple[str, Verdict]] = deque(maxlen=max_depth)
        self._sensitive_count = 0

    def assess(self, tool_name: str) -> PolicyVerdict:
        """Verdict for the current call given history; tighten-only.

        BLOCK iff a HIGH-taint source was earlier allowed inside the window and
        this call targets an external-comms sink; otherwise ALLOW.

        Time complexity: O(1). Space complexity: O(1).
        """
        if self._sensitive_count > 0 and self._policy.is_external_comms(tool_name):
            return PolicyVerdict(
                verdict=Verdict.BLOCK,
                reason=(
                    f"external-comms tool '{tool_name}' called after an allowed "
                    "HIGH-taint source earlier in this session"
                ),
                rule_id="trajectory.sensitive_to_external",
                tool_name=tool_name,
            )
        return PolicyVerdict(
            verdict=Verdict.ALLOW,
            reason="no sensitive-to-external sequence in the session window",
            rule_id="trajectory.clear",
            tool_name=tool_name,
        )

    def record(self, tool_name: str, verdict: Verdict) -> None:
        """Append ``(tool, verdict)``, evicting the oldest, maintaining the counter.

        Eviction is handled explicitly (rather than relying on the deque's silent
        drop) so the sensitive-entry counter stays exact.

        Time complexity: O(1). Space complexity: O(1).
        """
        if len(self._history) == self._max_depth:
            evicted_tool, evicted_verdict = self._history[0]
            if self._is_sensitive(evicted_tool, evicted_verdict):
                self._sensitive_count -= 1
        self._history.append((tool_name, verdict))
        if self._is_sensitive(tool_name, verdict):
            self._sensitive_count += 1

    def _is_sensitive(self, tool_name: str, verdict: Verdict) -> bool:
        """Whether an entry is an *allowed* HIGH-taint source. O(1)."""
        return (
            verdict is Verdict.ALLOW
            and self._policy.taint_tier_for_source(tool_name) is TaintTier.HIGH
        )
