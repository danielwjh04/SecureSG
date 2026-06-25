"""Scope reduction: turn discovered tool risks into a recommended denylist.

Warden recommends; a human activates (via the SP3.5 propose/activate path) or the
enforcer loads it. Output is a ``PolicySchema`` delta so it flows through the
existing policy plumbing unchanged. Pure and synchronous; ``is_risky`` already
encodes the discovery threshold, so the reducer holds no threshold of its own.
"""

from secureSG.guard.policy import PolicySchema
from secureSG.warden.discovery import ToolRisk


class ScopeReducer:
    """Builds a denylist recommendation from discovered tool risks."""

    def generate_denylist(self, risks: list[ToolRisk]) -> frozenset[str]:
        """The names of tools flagged risky. O(tool count)."""
        return frozenset(risk.tool_name for risk in risks if risk.is_risky)

    def generate_scope(self, risks: list[ToolRisk]) -> PolicySchema:
        """A ``PolicySchema`` delta denylisting the risky tools. O(tool count)."""
        return PolicySchema(denylist=sorted(self.generate_denylist(risks)))
