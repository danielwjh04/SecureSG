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
