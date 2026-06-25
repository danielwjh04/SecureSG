"""Tests for SecureSG runtime settings."""

from pathlib import Path

import pytest

from secureSG.config.settings import (
    DEFAULT_FAIL_MODE,
    HASH_ALGORITHM,
    Settings,
    fail_mode_for,
)
from secureSG.schemas.verdict import Verdict


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("DB_PATH", "GENESIS_SEED", "SQLITE_JOURNAL_MODE"):
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
