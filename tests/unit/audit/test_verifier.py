"""Tests for the audit-chain verifier (tamper detection)."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.audit.verifier import ChainStatus, ChainVerifier
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.verdict import Verdict

GENESIS = derive_genesis_hash("verify-seed")


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


async def build_chain(path: Path, count: int) -> None:
    logger = AuditLogger(db_path=path, genesis_hash=GENESIS)
    await logger.initialize()
    for _ in range(count):
        await logger.append(make_record())
    await logger.close()


def tamper(path: Path, seq: int, column: str, value: str) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(f"UPDATE audit_log SET {column} = ? WHERE seq = ?", (value, seq))
    conn.commit()
    conn.close()


def verifier(path: Path) -> ChainVerifier:
    return ChainVerifier(db_path=path, genesis_hash=GENESIS)


async def test_empty_chain_is_ok(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 0)
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_OK
    assert result.first_invalid_seq is None


async def test_intact_chain_is_ok(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 5)
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_OK
    assert result.first_invalid_seq is None


async def test_tampered_first_entry_breaks_at_one(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 5)
    tamper(path, 1, "payload", '{"evil":true}')
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == 1


async def test_tampered_middle_payload_breaks_at_that_seq(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 5)
    tamper(path, 3, "payload", '{"evil":true}')
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == 3


async def test_tampered_last_entry_breaks_at_n(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 5)
    tamper(path, 5, "payload", '{"evil":true}')
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == 5


async def test_tampered_curr_hash_breaks(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 4)
    tamper(path, 2, "curr_hash", "f" * 64)
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == 2


async def test_tampered_prev_hash_breaks(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    await build_chain(path, 4)
    tamper(path, 2, "prev_hash", "e" * 64)
    result = await verifier(path).verify()
    assert result.status is ChainStatus.CHAIN_BROKEN
    assert result.first_invalid_seq == 2
