"""Append-only, hash-chained audit log backed by SQLite.

The logger is the only writer to the chain. Appends are serialized with an
``asyncio.Lock`` so the ``prev_hash`` linkage can never be corrupted by
interleaving coroutines, and each append is idempotent on ``transaction_id``.
The in-memory tail is reloaded from the database on ``initialize`` — the row IS
the tail, so there is no second write to keep atomic.
"""

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import aiosqlite

from secureSG.audit.chain import canonical_payload, compute_link_hash
from secureSG.exceptions import AuditError
from secureSG.schemas.audit import AuditEntry, AuditRecord

_VALID_JOURNAL_MODES = frozenset(
    {"WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"}
)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL,
    verdict        TEXT NOT NULL,
    tool_name      TEXT,
    payload        TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    curr_hash      TEXT NOT NULL
)
"""

_INSERT = """
INSERT INTO audit_log
    (transaction_id, created_at, verdict, tool_name, payload, prev_hash, curr_hash)
VALUES (?, ?, ?, ?, ?, ?, ?)
"""


class AuditLogger:
    """Writes audit records as links in a tamper-evident SHA-256 hash chain."""

    def __init__(
        self,
        db_path: Path,
        genesis_hash: str,
        journal_mode: str = "WAL",
    ) -> None:
        if journal_mode not in _VALID_JOURNAL_MODES:
            raise AuditError(f"unsupported SQLite journal mode: {journal_mode!r}")
        self.db_path = db_path
        self._genesis_hash = genesis_hash
        self._journal_mode = journal_mode
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._tail_hash = genesis_hash
        self._tail_seq = 0

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise AuditError(
                "AuditLogger.initialize() must be called before this operation"
            )
        return self._conn

    async def initialize(self) -> None:
        """Open the database, enable the journal mode, create the table, load tail.

        Time complexity: O(1) (single indexed tail lookup). Space complexity: O(1).
        """
        conn = await aiosqlite.connect(str(self.db_path))
        await conn.execute(f"PRAGMA journal_mode={self._journal_mode}")
        await conn.execute(_CREATE_TABLE)
        await conn.commit()
        self._conn = conn
        await self._load_tail()

    async def _load_tail(self) -> None:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT seq, curr_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            self._tail_seq, self._tail_hash = 0, self._genesis_hash
        else:
            self._tail_seq, self._tail_hash = int(row[0]), str(row[1])

    def get_chain_tail(self) -> str:
        """Return the current chain-tail hash. Time complexity: O(1)."""
        return self._tail_hash

    async def append(self, record: AuditRecord) -> AuditEntry:
        """Append one record as the next link, atomically and idempotently.

        A replayed ``transaction_id`` returns the existing entry without writing a
        duplicate link. Appends are serialized by an ``asyncio.Lock`` so the
        ``prev_hash`` linkage cannot be corrupted by interleaving coroutines.

        Time complexity: O(1) amortized. Space complexity: O(1).
        """
        conn = self._require_conn()
        async with self._lock:
            existing = await self._find_by_transaction_id(record.transaction_id)
            if existing is not None:
                return existing
            payload = canonical_payload(record)
            prev_hash = self._tail_hash
            curr_hash = compute_link_hash(prev_hash, payload)
            cursor = await conn.execute(
                _INSERT,
                (
                    str(record.transaction_id),
                    record.created_at.isoformat(),
                    record.verdict.value,
                    record.tool_name,
                    payload.decode("utf-8"),
                    prev_hash,
                    curr_hash,
                ),
            )
            await conn.commit()
            seq = int(cursor.lastrowid or 0)
            self._tail_seq, self._tail_hash = seq, curr_hash
            return AuditEntry(
                seq=seq, record=record, prev_hash=prev_hash, curr_hash=curr_hash
            )

    async def _find_by_transaction_id(
        self, transaction_id: UUID
    ) -> AuditEntry | None:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT seq, payload, prev_hash, curr_hash "
            "FROM audit_log WHERE transaction_id = ?",
            (str(transaction_id),),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        seq, payload_text, prev_hash, curr_hash = row
        return AuditEntry(
            seq=int(seq),
            record=_record_from_payload(str(payload_text)),
            prev_hash=str(prev_hash),
            curr_hash=str(curr_hash),
        )

    async def close(self) -> None:
        """Close the database connection. Idempotent."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None


def _record_from_payload(payload_text: str) -> AuditRecord:
    """Reconstruct an :class:`AuditRecord` from its stored canonical payload."""
    data: dict[str, Any] = json.loads(payload_text)
    return AuditRecord(
        transaction_id=data["transaction_id"],
        created_at=data["created_at"],
        verdict=data["verdict"],
        tool_name=data["tool_name"],
        details=data["details"],
    )
