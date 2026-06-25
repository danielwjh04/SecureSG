"""Property-based tests for the audit chain (hypothesis).

These fuzz the two security invariants of the chain:
1. Any intact chain of N records verifies as CHAIN_OK.
2. Tampering any single entry's payload is detected at exactly that entry's seq.
"""

import asyncio
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from hypothesis import given, settings
from hypothesis import strategies as st

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.audit.verifier import ChainStatus, ChainVerifier
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.verdict import Verdict

GENESIS = derive_genesis_hash("property-seed")


def make_record() -> AuditRecord:
    return AuditRecord(
        transaction_id=uuid4(),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        verdict=Verdict.ALLOW,
        tool_name="tool",
        details={},
    )


async def _build(path: Path, count: int) -> None:
    logger = AuditLogger(db_path=path, genesis_hash=GENESIS)
    await logger.initialize()
    for _ in range(count):
        await logger.append(make_record())
    await logger.close()


def _verify(path: Path) -> ChainStatus:
    result = asyncio.run(ChainVerifier(db_path=path, genesis_hash=GENESIS).verify())
    return result.status


def tamper(path: Path, seq: int, column: str, value: str) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(f"UPDATE audit_log SET {column} = ? WHERE seq = ?", (value, seq))
    conn.commit()
    conn.close()


@given(count=st.integers(min_value=0, max_value=15))
@settings(max_examples=25, deadline=None)
def test_any_intact_chain_verifies(count: int) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.db"
        asyncio.run(_build(path, count))
        assert _verify(path) is ChainStatus.CHAIN_OK


@given(data=st.data())
@settings(max_examples=25, deadline=None)
def test_single_payload_tamper_detected_at_its_seq(data: st.DataObject) -> None:
    count = data.draw(st.integers(min_value=1, max_value=15))
    target = data.draw(st.integers(min_value=1, max_value=count))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.db"
        asyncio.run(_build(path, count))
        tamper(path, target, "payload", '{"tampered":true}')
        result = asyncio.run(
            ChainVerifier(db_path=path, genesis_hash=GENESIS).verify()
        )
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == target
