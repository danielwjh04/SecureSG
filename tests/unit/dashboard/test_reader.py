"""Tests for the read-only audit summary reader."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.dashboard.reader import AuditReader
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.verdict import Verdict

GENESIS = derive_genesis_hash("reader-test")


def _record(verdict: Verdict, rule_id: str, created_at: datetime) -> AuditRecord:
    return AuditRecord(
        transaction_id=uuid4(),
        created_at=created_at,
        verdict=verdict,
        tool_name="t",
        details={"reason": "r", "rule_id": rule_id},
    )


async def _write(db_path: Path, records: Sequence[AuditRecord]) -> None:
    logger = AuditLogger(db_path=db_path, genesis_hash=GENESIS)
    await logger.initialize()
    for record in records:
        await logger.append(record)
    await logger.close()


async def test_summary_tallies_by_category_and_verdict(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    db_path = tmp_path / "audit.db"
    await _write(
        db_path,
        [
            _record(Verdict.BLOCK, "injection.signature", now),
            _record(Verdict.BLOCK, "taint.high_to_external", now),
            _record(Verdict.HUMAN_APPROVAL_REQUIRED, "drift.intent", now),
            _record(Verdict.ALLOW, "policy.read_file", now),
            _record(Verdict.ALLOW, "injection.clean", now),
        ],
    )
    report = await AuditReader(db_path).summary(window_days=30)
    by_category = {count.category: count for count in report.categories}
    assert by_category["Prompt Injection"].block == 1
    assert by_category["Data Exfiltration"].block == 1
    assert by_category["Intent Drift"].human_approval_required == 1
    assert by_category["Allowed by Policy"].allow == 1
    assert by_category["Clean Content"].allow == 1
    assert by_category["Prompt Injection"].total == 1


async def test_summary_excludes_rows_outside_window(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    db_path = tmp_path / "audit.db"
    await _write(
        db_path,
        [
            _record(Verdict.BLOCK, "injection.signature", now - timedelta(days=60)),
            _record(Verdict.BLOCK, "taint.high_to_external", now),
        ],
    )
    report = await AuditReader(db_path).summary(window_days=30)
    categories = {count.category for count in report.categories}
    assert "Data Exfiltration" in categories
    assert "Prompt Injection" not in categories


async def test_summary_empty_window(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    await _write(db_path, [])
    report = await AuditReader(db_path).summary(window_days=30)
    assert report.categories == []
    assert report.window_days == 30
