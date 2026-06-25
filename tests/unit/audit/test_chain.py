"""Tests for the audit hash-chain primitives (pure crypto, no I/O)."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from secureSG.audit.chain import (
    canonical_payload,
    compute_link_hash,
    derive_genesis_hash,
)
from secureSG.schemas.audit import AuditRecord
from secureSG.schemas.verdict import Verdict

FIXED_TX = UUID("12345678-1234-5678-1234-567812345678")
FIXED_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def record_with(details: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        transaction_id=FIXED_TX,
        created_at=FIXED_TS,
        verdict=Verdict.ALLOW,
        tool_name="read_file",
        details=details,
    )


def test_derive_genesis_hash_matches_sha256() -> None:
    assert derive_genesis_hash("seed") == hashlib.sha256(b"seed").hexdigest()


def test_derive_genesis_hash_is_64_hex_chars() -> None:
    digest = derive_genesis_hash("anything")
    assert len(digest) == 64
    int(digest, 16)  # parses as hex


def test_compute_link_hash_matches_manual_sha256() -> None:
    prev = "0" * 64
    payload = b'{"x":1}'
    expected = hashlib.sha256(prev.encode() + payload).hexdigest()
    assert compute_link_hash(prev, payload) == expected


def test_compute_link_hash_is_deterministic() -> None:
    assert compute_link_hash("a" * 64, b"p") == compute_link_hash("a" * 64, b"p")


def test_compute_link_hash_depends_on_prev_hash() -> None:
    assert compute_link_hash("a" * 64, b"p") != compute_link_hash("b" * 64, b"p")


def test_compute_link_hash_depends_on_payload() -> None:
    assert compute_link_hash("a" * 64, b"p") != compute_link_hash("a" * 64, b"q")


def test_canonical_payload_returns_bytes() -> None:
    assert isinstance(canonical_payload(record_with({})), bytes)


def test_canonical_payload_is_key_order_independent() -> None:
    first = canonical_payload(record_with({"a": 1, "b": 2}))
    second = canonical_payload(record_with({"b": 2, "a": 1}))
    assert first == second


def test_canonical_payload_distinguishes_content() -> None:
    assert canonical_payload(record_with({"a": 1})) != canonical_payload(
        record_with({"a": 2})
    )


def test_canonical_payload_serializes_known_fields() -> None:
    data = json.loads(canonical_payload(record_with({"k": "v"})).decode())
    assert data == {
        "created_at": FIXED_TS.isoformat(),
        "details": {"k": "v"},
        "tool_name": "read_file",
        "transaction_id": str(FIXED_TX),
        "verdict": "ALLOW",
    }
