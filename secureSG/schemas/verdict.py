"""The policy verdict enumeration.

A verdict is the outcome of evaluating a single tool call. It is a string enum
so it serializes cleanly into JSON and into the audit log payload.
"""

from enum import StrEnum


class Verdict(StrEnum):
    """The outcome of a policy evaluation for one tool call."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
