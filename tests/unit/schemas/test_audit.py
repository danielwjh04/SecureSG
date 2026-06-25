"""Tests for the audit record and entry schemas."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from secureSG.schemas.audit import AuditEntry, AuditRecord
from secureSG.schemas.verdict import Verdict


def make_record(**overrides: Any) -> AuditRecord:
    base: dict[str, Any] = {
        "transaction_id": uuid4(),
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "verdict": Verdict.ALLOW,
        "tool_name": "read_file",
        "details": {"path": "/etc/hosts"},
    }
    base.update(overrides)
    return AuditRecord(**base)


def test_audit_record_holds_its_fields() -> None:
    tx = uuid4()
    rec = make_record(transaction_id=tx, verdict=Verdict.BLOCK)
    assert rec.transaction_id == tx
    assert rec.verdict is Verdict.BLOCK
    assert rec.tool_name == "read_file"
    assert rec.details == {"path": "/etc/hosts"}


def test_tool_name_is_optional() -> None:
    assert make_record(tool_name=None).tool_name is None


def test_details_defaults_to_empty_dict() -> None:
    rec = AuditRecord(
        transaction_id=uuid4(),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        verdict=Verdict.ALLOW,
        tool_name=None,
    )
    assert rec.details == {}


def test_record_rejects_unknown_verdict() -> None:
    with pytest.raises(ValidationError):
        make_record(verdict="MAYBE")


def test_audit_record_is_immutable() -> None:
    rec = make_record()
    with pytest.raises(ValidationError):
        rec.verdict = Verdict.BLOCK  # type: ignore[misc]  # reason: testing frozen


def test_audit_entry_wraps_record_with_chain_fields() -> None:
    rec = make_record()
    entry = AuditEntry(seq=1, record=rec, prev_hash="0" * 64, curr_hash="a" * 64)
    assert entry.seq == 1
    assert entry.record is rec
    assert entry.prev_hash == "0" * 64
    assert entry.curr_hash == "a" * 64
