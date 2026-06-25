"""Runtime configuration for SecureSG, loaded from the environment.

Every configurable runtime value lives here (per CLAUDE.md: no hardcoded
literals in logic). Security invariants that must never be weakened — such as
the audit hash algorithm — are module-level constants, deliberately *not*
exposed as env-overridable fields.
"""

from pathlib import Path
from typing import Final, Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from secureSG.schemas.verdict import Verdict

HASH_ALGORITHM: Final[str] = "sha256"
"""Audit hash algorithm. SHA-256 only — never weaken this (CLAUDE.md section 6)."""


class Settings(BaseSettings):
    """SecureSG runtime configuration, populated from ``SECURESG_*`` env vars."""

    model_config = SettingsConfigDict(
        env_prefix="SECURESG_",
        env_file=".env",
        extra="ignore",
        protected_namespaces=(),  # fields are named model_* by intent, not ML models
    )

    db_path: Path = Path("securesg_audit.db")
    genesis_seed: str = "securesg-genesis-v1"
    sqlite_journal_mode: str = "WAL"
    policy_dir: Path = Path(__file__).resolve().parent.parent / "policies"

    # GuardFormer semantic layer (SP3). model_path is unset until weights exist.
    model_path: Path | None = None
    model_repo_id: str = "bartowski/Qwen_Qwen3-0.6B-GGUF"
    model_filename: str = "Qwen_Qwen3-0.6B-Q4_K_M.gguf"
    model_dir: Path = Path("model_weights")
    model_context_size: int = 2048
    model_threads: int = 4
    model_max_output_tokens: int = 1
    model_logprobs_top_k: int = 20
    semantic_block_threshold: float = 0.80
    semantic_review_threshold: float = 0.50

    @model_validator(mode="after")
    def _validate_thresholds(self) -> Self:
        """Fail loudly unless ``0 < review < block <= 1`` (fail-closed config).

        Time complexity: O(1). Space complexity: O(1).
        """
        if not (
            0.0
            < self.semantic_review_threshold
            < self.semantic_block_threshold
            <= 1.0
        ):
            raise ValueError(
                "semantic thresholds must satisfy 0 < review < block <= 1; got "
                f"review={self.semantic_review_threshold}, "
                f"block={self.semantic_block_threshold}"
            )
        return self


DEFAULT_FAIL_MODE: Final[Verdict] = Verdict.BLOCK
"""Verdict applied when a tool's verdict cannot be computed (fail-closed)."""

TOOL_FAIL_MODES: Final[dict[str, Verdict]] = {
    "read_secret": Verdict.BLOCK,
    "send_email": Verdict.BLOCK,
    "execute_shell": Verdict.BLOCK,
    "read_file": Verdict.ALLOW,
}
"""Per-tool fail modes. High-risk tools fail closed; read-only tools may fail open."""


def fail_mode_for(tool_name: str) -> Verdict:
    """Return the fail-mode verdict for a tool, defaulting to fail-closed.

    Time complexity: O(1) hash lookup. Space complexity: O(1).
    """
    return TOOL_FAIL_MODES.get(tool_name, DEFAULT_FAIL_MODE)
