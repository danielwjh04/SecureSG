"""Tests for SecureSG runtime settings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from secureSG.config.settings import (
    DEFAULT_FAIL_MODE,
    HASH_ALGORITHM,
    Settings,
    fail_mode_for,
)
from secureSG.schemas.verdict import Verdict


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "DB_PATH",
        "GENESIS_SEED",
        "SQLITE_JOURNAL_MODE",
        "MODEL_PATH",
        "MODEL_CONTEXT_SIZE",
        "MODEL_THREADS",
        "MODEL_MAX_OUTPUT_TOKENS",
        "MODEL_LOGPROBS_TOP_K",
        "SEMANTIC_BLOCK_THRESHOLD",
        "SEMANTIC_REVIEW_THRESHOLD",
        "MODEL_AUTHOR_MAX_TOKENS",
        "PROPOSED_POLICY_DIR",
        "EMBEDDING_MODEL_NAME",
        "DRIFT_REVIEW_THRESHOLD",
        "DRIFT_BLOCK_THRESHOLD",
        "TOOL_RISK_THRESHOLD",
        "RISK_ANCHORS_PATH",
        "PROXY_HOST",
        "PROXY_PORT",
        "MCP_BACKEND_URL",
        "MCP_BACKEND_TIMEOUT",
        "MAX_TRAJECTORY_DEPTH",
        "DASHBOARD_ENABLED",
        "DASHBOARD_WS_QUEUE_SIZE",
        "DASHBOARD_MAX_ALERTS",
        "DASHBOARD_MAX_REGISTRY",
        "DASHBOARD_SUMMARY_WINDOW_DAYS",
        "DASHBOARD_CONTENT_PREVIEW_CHARS",
    ):
        monkeypatch.delenv(f"SECURESG_{key}", raising=False)


def test_defaults_load(clean_env: None) -> None:
    settings = Settings(_env_file=None)
    assert settings.sqlite_journal_mode == "WAL"
    assert settings.genesis_seed != ""


def test_policy_dir_defaults_to_package_policies(clean_env: None) -> None:
    settings = Settings(_env_file=None)
    assert settings.policy_dir.name == "policies"
    assert settings.policy_dir.is_dir()


def test_env_overrides_db_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_DB_PATH", "audit_custom.db")
    settings = Settings(_env_file=None)
    assert settings.db_path == Path("audit_custom.db")


def test_env_overrides_genesis_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_GENESIS_SEED", "another-seed")
    settings = Settings(_env_file=None)
    assert settings.genesis_seed == "another-seed"


def test_hash_algorithm_is_sha256_and_not_a_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_HASH_ALGORITHM", "md5")
    Settings(_env_file=None)
    assert HASH_ALGORITHM == "sha256"
    assert "hash_algorithm" not in Settings.model_fields


def test_default_fail_mode_is_block() -> None:
    assert DEFAULT_FAIL_MODE is Verdict.BLOCK


def test_high_risk_tools_fail_closed() -> None:
    assert fail_mode_for("read_secret") is Verdict.BLOCK
    assert fail_mode_for("send_email") is Verdict.BLOCK
    assert fail_mode_for("execute_shell") is Verdict.BLOCK


def test_read_file_fails_open() -> None:
    assert fail_mode_for("read_file") is Verdict.ALLOW


def test_unknown_tool_uses_default_fail_closed() -> None:
    assert fail_mode_for("totally_unknown_tool") is Verdict.BLOCK


def test_model_path_defaults_to_none(clean_env: None) -> None:
    assert Settings(_env_file=None).model_path is None


def test_semantic_thresholds_have_safe_default_ordering(clean_env: None) -> None:
    settings = Settings(_env_file=None)
    assert (
        0.0
        < settings.semantic_review_threshold
        < settings.semantic_block_threshold
        <= 1.0
    )


def test_env_overrides_model_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_MODEL_PATH", "weights/guard.gguf")
    assert Settings(_env_file=None).model_path == Path("weights/guard.gguf")


def test_rejects_review_threshold_not_below_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_SEMANTIC_REVIEW_THRESHOLD", "0.9")
    monkeypatch.setenv("SECURESG_SEMANTIC_BLOCK_THRESHOLD", "0.8")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_block_threshold_above_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_SEMANTIC_BLOCK_THRESHOLD", "1.5")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_non_positive_review_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_SEMANTIC_REVIEW_THRESHOLD", "0.0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_model_author_max_tokens_has_positive_default(clean_env: None) -> None:
    assert Settings(_env_file=None).model_author_max_tokens > 0


def test_proposed_policy_dir_sits_under_policies(clean_env: None) -> None:
    proposed = Settings(_env_file=None).proposed_policy_dir
    assert proposed.name == "proposed"
    assert proposed.parent.name == "policies"


def test_drift_thresholds_have_valid_default_ordering(clean_env: None) -> None:
    settings = Settings(_env_file=None)
    assert (
        0.0
        <= settings.drift_block_threshold
        < settings.drift_review_threshold
        <= 1.0
    )


def test_tool_risk_threshold_in_range(clean_env: None) -> None:
    assert 0.0 <= Settings(_env_file=None).tool_risk_threshold <= 1.0


def test_risk_anchors_path_points_into_warden(clean_env: None) -> None:
    path = Settings(_env_file=None).risk_anchors_path
    assert path.name == "risk_anchors.yaml"
    assert path.parent.name == "warden"


def test_rejects_drift_block_not_below_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_DRIFT_BLOCK_THRESHOLD", "0.6")
    monkeypatch.setenv("SECURESG_DRIFT_REVIEW_THRESHOLD", "0.5")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_tool_risk_threshold_above_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_TOOL_RISK_THRESHOLD", "1.5")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_proxy_defaults_are_safe(clean_env: None) -> None:
    settings = Settings(_env_file=None)
    assert settings.proxy_host == "127.0.0.1"
    assert 1 <= settings.proxy_port <= 65535
    assert settings.mcp_backend_url is None
    assert settings.mcp_backend_timeout > 0.0
    assert settings.max_trajectory_depth >= 1


def test_env_overrides_proxy_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_PROXY_PORT", "9443")
    assert Settings(_env_file=None).proxy_port == 9443


def test_rejects_proxy_port_above_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_PROXY_PORT", "70000")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_proxy_port_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_PROXY_PORT", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_non_positive_backend_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_MCP_BACKEND_TIMEOUT", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_trajectory_depth_below_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_MAX_TRAJECTORY_DEPTH", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_accepts_mcp_backend_url_with_http_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_MCP_BACKEND_URL", "http://localhost:9000/rpc")
    assert Settings(_env_file=None).mcp_backend_url == "http://localhost:9000/rpc"


def test_rejects_mcp_backend_url_with_unsupported_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_MCP_BACKEND_URL", "ftp://example.com")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_dashboard_defaults_are_positive(clean_env: None) -> None:
    settings = Settings(_env_file=None)
    assert settings.dashboard_enabled is True
    assert settings.dashboard_ws_queue_size > 0
    assert settings.dashboard_max_alerts > 0
    assert settings.dashboard_max_registry > 0
    assert settings.dashboard_summary_window_days > 0
    assert settings.dashboard_content_preview_chars > 0


def test_env_disables_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_DASHBOARD_ENABLED", "false")
    assert Settings(_env_file=None).dashboard_enabled is False


def test_rejects_non_positive_ws_queue_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_DASHBOARD_WS_QUEUE_SIZE", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_non_positive_max_alerts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESG_DASHBOARD_MAX_ALERTS", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_non_positive_summary_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_DASHBOARD_SUMMARY_WINDOW_DAYS", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_rejects_non_positive_content_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESG_DASHBOARD_CONTENT_PREVIEW_CHARS", "-1")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
