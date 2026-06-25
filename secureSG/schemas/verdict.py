"""The policy verdict enumeration and the richer PolicyVerdict decision object.

``Verdict`` is the bare outcome; ``PolicyVerdict`` adds the reason, the rule that
fired, and the tool — the explainable decision the enforcer returns and logs.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Verdict(StrEnum):
    """The outcome of a policy evaluation for one tool call."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"


class PolicyVerdict(BaseModel):
    """An explainable policy decision: the verdict plus why it was reached."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    reason: str
    rule_id: str
    tool_name: str | None
