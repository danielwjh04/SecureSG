"""Tests for the append-only, hash-chained AuditLogger."""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiosqlite
import pytest
import pytest_asyncio

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.verdict import Verdict

GENESIS = derive_genesis_hash("test-seed")


def make_record(**overrides: Any) -> AuditRecord:
    base: dict[str, Any] = {
        "transaction_id": uuid4(),
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "verdict": Verdict.ALLOW,
        "tool_name": "read_file",
        "details": {},
    }
    base.update(overrides)
    return AuditRecord(**base)


@pytest_asyncio.fixture
async def logger(tmp_path: Path) -> AsyncIterator[AuditLogger]:
    instance = AuditLogger(db_path=tmp_path / "audit.db", genesis_hash=GENESIS)
    await instance.initialize()
    yield instance
    await instance.close()


async def test_first_append_links_to_genesis(logger: AuditLogger) -> None:
    entry = await logger.append(make_record())
    assert entry.seq == 1
    assert entry.prev_hash == GENESIS
    assert len(entry.curr_hash) == 64


async def test_second_append_links_to_first(logger: AuditLogger) -> None:
    first = await logger.append(make_record())
    second = await logger.append(make_record())
    assert second.seq == 2
    assert second.prev_hash == first.curr_hash


async def test_get_chain_tail_tracks_latest(logger: AuditLogger) -> None:
    assert logger.get_chain_tail() == GENESIS
    first = await logger.append(make_record())
    assert logger.get_chain_tail() == first.curr_hash


async def test_append_is_idempotent_on_transaction_id(logger: AuditLogger) -> None:
    record = make_record()
    first = await logger.append(record)
    replay = await logger.append(record)
    assert replay.seq == first.seq
    assert replay.curr_hash == first.curr_hash
    assert logger.get_chain_tail() == first.curr_hash


async def test_tail_reloads_after_reinitialize(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    first_logger = AuditLogger(db_path=path, genesis_hash=GENESIS)
    await first_logger.initialize()
    first = await first_logger.append(make_record())
    await first_logger.close()

    reopened = AuditLogger(db_path=path, genesis_hash=GENESIS)
    await reopened.initialize()
    assert reopened.get_chain_tail() == first.curr_hash
    second = await reopened.append(make_record())
    assert second.seq == 2
    assert second.prev_hash == first.curr_hash
    await reopened.close()


async def test_append_before_initialize_raises(tmp_path: Path) -> None:
    from secureSG.exceptions import AuditError

    uninitialized = AuditLogger(db_path=tmp_path / "x.db", genesis_hash=GENESIS)
    with pytest.raises(AuditError):
        await uninitialized.append(make_record())


def test_invalid_journal_mode_is_rejected(tmp_path: Path) -> None:
    from secureSG.exceptions import AuditError

    with pytest.raises(AuditError):
        AuditLogger(
            db_path=tmp_path / "x.db",
            genesis_hash=GENESIS,
            journal_mode="DROP TABLE audit_log",
        )


async def test_close_is_idempotent(tmp_path: Path) -> None:
    instance = AuditLogger(db_path=tmp_path / "x.db", genesis_hash=GENESIS)
    await instance.initialize()
    await instance.close()
    await instance.close()  # second close is a no-op, must not raise


async def test_concurrent_appends_stay_linked(logger: AuditLogger) -> None:
    records = [make_record() for _ in range(10)]
    await asyncio.gather(*(logger.append(record) for record in records))

    async with aiosqlite.connect(str(logger.db_path)) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT seq, prev_hash, curr_hash FROM audit_log ORDER BY seq"
        ) as cursor:
            rows = await cursor.fetchall()

    assert [row["seq"] for row in rows] == list(range(1, 11))
    prev = GENESIS
    for row in rows:
        assert row["prev_hash"] == prev
        prev = row["curr_hash"]
