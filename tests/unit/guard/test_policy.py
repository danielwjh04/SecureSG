"""Tests for policy loading and compilation."""

from pathlib import Path

import pytest

from secureSG.config.settings import Settings
from secureSG.exceptions import PolicyError
from secureSG.guard.enforcer import CompiledPolicy, load_policy
from secureSG.guard.taint import TaintTier
from secureSG.schemas.verdict import Verdict


def real_policy() -> CompiledPolicy:
    return load_policy(Settings(_env_file=None).policy_dir)


def test_loads_denylist_as_frozenset() -> None:
    policy = real_policy()
    assert policy.is_denied("execute_shell")
    assert not policy.is_denied("read_file")
    assert isinstance(policy.denylist, frozenset)


def test_loads_external_comms_tools() -> None:
    policy = real_policy()
    assert policy.is_external_comms("send_email")
    assert not policy.is_external_comms("read_file")


def test_loads_taint_sources_with_tiers() -> None:
    policy = real_policy()
    assert policy.taint_tier_for_source("read_secret") is TaintTier.HIGH
    assert policy.taint_tier_for_source("read_file") is None


def test_loads_tool_rules() -> None:
    policy = real_policy()
    assert policy.rule_for("read_file") is Verdict.ALLOW
    assert policy.rule_for("nonexistent_tool") is None


def test_empty_dir_compiles_to_empty_policy(tmp_path: Path) -> None:
    policy = load_policy(tmp_path)
    assert policy.rule_for("anything") is None
    assert not policy.is_denied("anything")


def test_malformed_verdict_raises_policy_error(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("tool_rules:\n  read_file: NOPE\n")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_unknown_policy_key_raises_policy_error(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("mystery_key: 1\n")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_bad_taint_tier_raises_policy_error(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("taint_sources:\n  read_secret: SUPER\n")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_non_mapping_taint_sources_raises_policy_error(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("taint_sources:\n  - read_secret\n")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_loads_injection_signatures_as_frozenset() -> None:
    policy = real_policy()
    assert isinstance(policy.injection_signatures, frozenset)
    assert "ignore previous instructions" in policy.injection_signatures


def test_loads_content_scan_sources() -> None:
    policy = real_policy()
    assert policy.is_content_scan_source("scrape_page")
    assert not policy.is_content_scan_source("read_file")


def test_empty_dir_has_no_signatures_or_scan_sources(tmp_path: Path) -> None:
    policy = load_policy(tmp_path)
    assert policy.injection_signatures == frozenset()
    assert not policy.is_content_scan_source("scrape_page")


def test_merges_injection_signatures_across_files(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text('injection_signatures:\n  - "aaa"\n')
    (tmp_path / "b.yaml").write_text('injection_signatures:\n  - "bbb"\n')
    policy = load_policy(tmp_path)
    assert {"aaa", "bbb"} <= policy.injection_signatures
