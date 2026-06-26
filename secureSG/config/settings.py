"""Runtime configuration for SecureSG, loaded from the environment.

Every configurable runtime value lives here (per CLAUDE.md: no hardcoded
literals in logic). Security invariants that must never be weakened — such as
the audit hash algorithm — are module-level constants, deliberately *not*
exposed as env-overridable fields.
"""

from pathlib import Path
from typing import Final, Self
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from secureSG.schemas.verdict import Verdict

HASH_ALGORITHM: Final[str] = "sha256"
"""Audit hash algorithm. SHA-256 only — never weaken this (CLAUDE.md section 6)."""

_ALLOWED_BACKEND_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
"""URL schemes permitted for the MCP backend; O(1) membership, fail-closed."""


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
    proposed_policy_dir: Path = (
        Path(__file__).resolve().parent.parent / "policies" / "proposed"
    )

    # GuardFormer semantic layer (SP3). model_path is unset until weights exist.
    model_path: Path | None = None
    model_repo_id: str = "bartowski/Qwen_Qwen3-0.6B-GGUF"
    model_filename: str = "Qwen_Qwen3-0.6B-Q4_K_M.gguf"
    model_dir: Path = Path("model_weights")
    model_context_size: int = 2048
    model_threads: int = 4
    model_max_output_tokens: int = 1
    model_logprobs_top_k: int = 20
    model_author_max_tokens: int = 512
    semantic_block_threshold: float = 0.80
    semantic_review_threshold: float = 0.50

    # Warden governance (SP4).
    embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    drift_review_threshold: float = 0.45
    drift_block_threshold: float = 0.20
    tool_risk_threshold: float = 0.45
    risk_anchors_path: Path = (
        Path(__file__).resolve().parent.parent / "warden" / "risk_anchors.yaml"
    )

    # Runtime proxy + MCP backend (SP5).
    proxy_host: str = "127.0.0.1"  # loopback default; never 0.0.0.0 (ruff S104)
    proxy_port: int = 8080
    mcp_backend_url: str | None = None
    mcp_backend_timeout: float = 30.0
    max_trajectory_depth: int = 50

    # Dashboard + live feed (SP6).
    dashboard_enabled: bool = True
    dashboard_ws_queue_size: int = 100  # per-subscriber bounded queue
    dashboard_max_alerts: int = 200  # alert ring capacity
    dashboard_max_registry: int = 200  # safe-content ring capacity
    dashboard_summary_window_days: int = 30
    dashboard_content_preview_chars: int = 2000  # cap content shipped to dashboard

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

    @model_validator(mode="after")
    def _validate_drift_thresholds(self) -> Self:
        """Drift similarity floors: ``0 <= block < review <= 1``; risk in [0, 1]."""
        if not (
            0.0
            <= self.drift_block_threshold
            < self.drift_review_threshold
            <= 1.0
        ):
            raise ValueError(
                "drift thresholds must satisfy 0 <= block < review <= 1; got "
                f"block={self.drift_block_threshold}, "
                f"review={self.drift_review_threshold}"
            )
        if not (0.0 <= self.tool_risk_threshold <= 1.0):
            raise ValueError(
                f"tool_risk_threshold must be in [0, 1]; got {self.tool_risk_threshold}"
            )
        return self

    @model_validator(mode="after")
    def _validate_proxy(self) -> Self:
        """Fail loudly on out-of-bounds proxy/backend/trajectory config.

        Enforces a valid TCP port, a positive backend timeout, a trajectory
        depth of at least one, and an http(s) backend URL when one is set.

        Time complexity: O(1). Space complexity: O(1).
        """
        if not (1 <= self.proxy_port <= 65535):
            raise ValueError(f"proxy_port must be in [1, 65535]; got {self.proxy_port}")
        if self.mcp_backend_timeout <= 0.0:
            raise ValueError(
                f"mcp_backend_timeout must be > 0; got {self.mcp_backend_timeout}"
            )
        if self.max_trajectory_depth < 1:
            raise ValueError(
                f"max_trajectory_depth must be >= 1; got {self.max_trajectory_depth}"
            )
        if self.mcp_backend_url is not None:
            scheme = urlparse(self.mcp_backend_url).scheme
            if scheme not in _ALLOWED_BACKEND_SCHEMES:
                raise ValueError(
                    "mcp_backend_url scheme must be one of "
                    f"{sorted(_ALLOWED_BACKEND_SCHEMES)}; got '{scheme}'"
                )
        return self

    @model_validator(mode="after")
    def _validate_dashboard(self) -> Self:
        """Fail loudly unless every dashboard sizing field is positive.

        Time complexity: O(1). Space complexity: O(1).
        """
        sizes = {
            "dashboard_ws_queue_size": self.dashboard_ws_queue_size,
            "dashboard_max_alerts": self.dashboard_max_alerts,
            "dashboard_max_registry": self.dashboard_max_registry,
            "dashboard_summary_window_days": self.dashboard_summary_window_days,
            "dashboard_content_preview_chars": self.dashboard_content_preview_chars,
        }
        for name, value in sizes.items():
            if value < 1:
                raise ValueError(f"{name} must be >= 1; got {value}")
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
