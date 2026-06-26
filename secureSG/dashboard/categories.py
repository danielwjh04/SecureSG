"""Map audit ``rule_id`` strings to human-readable attack categories.

The Monthly Summary groups verdict counts by category, and the Alert Feed labels
each incident. Categorization is pure and centralized here so every panel agrees
on the same taxonomy. Exact rule ids are matched first (so ``injection.clean`` —
a benign scan result — is not lumped with the injection threats), then by family
prefix, falling back to ``"Other"`` for any rule id introduced by a later cycle.
"""

from typing import Final

_EXACT: Final[dict[str, str]] = {
    "injection.clean": "Clean Content",
    "content.untracked": "Clean Content",
    "denylist": "Forbidden Tool",
    "schema.invalid": "Malformed Request",
    "default.fail_mode": "Unconfigured Tool",
}

_BY_PREFIX: Final[tuple[tuple[str, str], ...]] = (
    ("injection.", "Prompt Injection"),
    ("taint.", "Data Exfiltration"),
    ("trajectory.", "Exfiltration Sequence"),
    ("drift.", "Intent Drift"),
    ("semantic.", "Semantic Risk"),
    ("content.", "Clean Content"),
    ("policy.", "Allowed by Policy"),
)

_FALLBACK: Final[str] = "Other"


def category_for(rule_id: str) -> str:
    """Return the attack category for an audit ``rule_id``.

    Time complexity: O(number of prefixes). Space complexity: O(1).
    """
    exact = _EXACT.get(rule_id)
    if exact is not None:
        return exact
    for prefix, category in _BY_PREFIX:
        if rule_id.startswith(prefix):
            return category
    return _FALLBACK
