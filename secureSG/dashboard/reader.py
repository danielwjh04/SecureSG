"""Read-only summary queries over the audit chain for the Monthly Summary panel.

The audit chain is the durable source of truth; this opens its own connection
(the same approach as :class:`~secureSG.audit.verifier.ChainVerifier`) and only
ever SELECTs, so dashboard reads never touch the writer's connection. Counts come
from the denormalized ``verdict`` column; the ``rule_id`` (and thus attack
category) is parsed from each row's canonical payload, so no SQLite JSON1
extension is required.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import aiosqlite

from secureSG.dashboard.categories import category_for
from secureSG.schemas.dashboard import CategoryCount, SummaryReport
from secureSG.schemas.verdict import Verdict

_VERDICT_KEY: Final[dict[Verdict, str]] = {
    Verdict.ALLOW: "allow",
    Verdict.HUMAN_APPROVAL_REQUIRED: "human_approval_required",
    Verdict.BLOCK: "block",
}


def _rule_id_of(payload_text: str) -> str:
    data: dict[str, Any] = json.loads(payload_text)
    details = data.get("details", {})
    rule_id = details.get("rule_id", "") if isinstance(details, dict) else ""
    return rule_id if isinstance(rule_id, str) else ""


def _to_counts(tallies: dict[str, dict[str, int]]) -> list[CategoryCount]:
    counts: list[CategoryCount] = []
    for category in sorted(tallies):
        bucket = tallies[category]
        counts.append(
            CategoryCount(
                category=category,
                allow=bucket["allow"],
                human_approval_required=bucket["human_approval_required"],
                block=bucket["block"],
                total=sum(bucket.values()),
            )
        )
    return counts


class AuditReader:
    """Read-only aggregate queries over the ``audit_log`` table."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def summary(self, window_days: int) -> SummaryReport:
        """Tally verdict counts by attack category over the recent window.

        Time complexity: O(rows in window). Space complexity: O(categories).
        """
        generated_at = datetime.now(UTC)
        cutoff = (generated_at - timedelta(days=window_days)).isoformat()
        tallies: dict[str, dict[str, int]] = {}
        async with aiosqlite.connect(str(self._db_path)) as conn, conn.execute(
            "SELECT verdict, payload FROM audit_log WHERE created_at >= ?", (cutoff,)
        ) as cursor:
            async for verdict_value, payload_text in cursor:
                category = category_for(_rule_id_of(payload_text))
                bucket = tallies.setdefault(
                    category,
                    {"allow": 0, "human_approval_required": 0, "block": 0},
                )
                bucket[_VERDICT_KEY[Verdict(verdict_value)]] += 1
        return SummaryReport(
            window_days=window_days,
            generated_at=generated_at,
            categories=_to_counts(tallies),
        )
