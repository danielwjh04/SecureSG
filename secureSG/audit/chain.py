"""Hash-chain primitives for the audit log.

These functions are pure — no I/O, no global state — so they are trivially unit-
and property-testable. :class:`~secureSG.audit.logger.AuditLogger` composes them
with SQLite persistence; :class:`~secureSG.audit.verifier.ChainVerifier` replays
them. The algorithm is pinned to ``HASH_ALGORITHM`` (SHA-256) — never weakened.
"""

import hashlib
import json

from secureSG.config.settings import HASH_ALGORITHM
from secureSG.schemas.audit import AuditRecord


def derive_genesis_hash(seed: str) -> str:
    """Derive the genesis link hash from a configured seed.

    Args:
        seed: Arbitrary seed string. Changing it starts a new, independent chain.

    Returns:
        Hex SHA-256 digest of the UTF-8 seed; the ``prev_hash`` of link 1.

    Time complexity: O(n) in len(seed). Space complexity: O(1).
    """
    return hashlib.new(HASH_ALGORITHM, seed.encode("utf-8")).hexdigest()


def canonical_payload(record: AuditRecord) -> bytes:
    """Serialize an audit record to canonical, hash-stable bytes.

    Fields are enumerated explicitly (never via ``model_dump`` of a possible
    subclass) so chain metadata can never leak into the hashed payload. Keys are
    sorted at every level, so dictionary insertion order does not affect the hash.

    Time complexity: O(n) in the serialized size. Space complexity: O(n).
    """
    data = {
        "transaction_id": str(record.transaction_id),
        "created_at": record.created_at.isoformat(),
        "verdict": record.verdict.value,
        "tool_name": record.tool_name,
        "details": record.details,
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_link_hash(prev_hash: str, payload: bytes) -> str:
    """Compute the next link in the audit hash chain.

    Args:
        prev_hash: Hex digest of the previous link (genesis for link 1).
        payload: Canonical serialized bytes of the current record.

    Returns:
        Hex SHA-256 digest of ``prev_hash`` (UTF-8) concatenated with ``payload``.

    Time complexity: O(n) in len(payload). Space complexity: O(1).
    """
    digest = hashlib.new(HASH_ALGORITHM, prev_hash.encode("utf-8"))
    digest.update(payload)
    return digest.hexdigest()
