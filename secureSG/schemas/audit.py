"""Pydantic schemas for the audit log.

``AuditRecord`` is the canonical, hashable content of one logged decision.
``AuditEntry`` is a persisted record together with its position in the hash
chain. The two are kept separate (composition, not inheritance) so the chain
metadata — ``seq`` / ``prev_hash`` / ``curr_hash`` — can never accidentally be
folded into the hashed payload.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from secureSG.schemas.verdict import Verdict


class AuditRecord(BaseModel):
    """The canonical, hashable content of a single audit log entry."""

    model_config = ConfigDict(frozen=True)

    transaction_id: UUID
    created_at: datetime
    verdict: Verdict
    tool_name: str | None
    details: dict[str, Any] = Field(default_factory=dict)


class AuditEntry(BaseModel):
    """An :class:`AuditRecord` together with its position in the hash chain."""

    model_config = ConfigDict(frozen=True)

    seq: int
    record: AuditRecord
    prev_hash: str
    curr_hash: str
