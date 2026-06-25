"""Forward-pass integrity checker for the audit hash chain.

Verification is a single streaming pass from the genesis hash. On the first
broken link it reports the offending ``seq`` so an operator sees exactly where
tampering occurred. It catches a tampered payload, a tampered ``curr_hash``, and
a tampered ``prev_hash`` (broken linkage / reordering / insertion).
"""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import aiosqlite

from secureSG.audit.chain import compute_link_hash


class ChainStatus(StrEnum):
    """Outcome of an audit-chain verification."""

    CHAIN_OK = "CHAIN_OK"
    CHAIN_BROKEN = "CHAIN_BROKEN"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """The result of verifying the audit chain.

    ``first_invalid_seq`` is the ``seq`` of the first broken link, or ``None``
    when the chain is intact.
    """

    status: ChainStatus
    first_invalid_seq: int | None = None


class ChainVerifier:
    """Replays the hash chain to detect tampering of any past entry."""

    def __init__(self, db_path: Path, genesis_hash: str) -> None:
        self._db_path = db_path
        self._genesis_hash = genesis_hash

    async def verify(self) -> VerificationResult:
        """Verify the whole chain in a single forward pass.

        Time complexity: O(n) in the number of entries.
        Space complexity: O(1) — rows are streamed, never buffered.
        """
        expected_prev = self._genesis_hash
        async with aiosqlite.connect(str(self._db_path)) as conn, conn.execute(
            "SELECT seq, payload, prev_hash, curr_hash FROM audit_log ORDER BY seq"
        ) as cursor:
            async for seq, payload_text, prev_hash, curr_hash in cursor:
                if prev_hash != expected_prev:
                    return VerificationResult(ChainStatus.CHAIN_BROKEN, int(seq))
                recomputed = compute_link_hash(
                    expected_prev, payload_text.encode("utf-8")
                )
                if recomputed != curr_hash:
                    return VerificationResult(ChainStatus.CHAIN_BROKEN, int(seq))
                expected_prev = curr_hash
        return VerificationResult(ChainStatus.CHAIN_OK, None)
