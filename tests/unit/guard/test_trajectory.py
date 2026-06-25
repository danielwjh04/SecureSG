"""Tests for the bounded session trajectory and its one sequence rule."""

from secureSG.guard.policy import CompiledPolicy
from secureSG.guard.taint import TaintTier
from secureSG.guard.trajectory import SessionTrajectory
from secureSG.schemas.verdict import Verdict


def _policy() -> CompiledPolicy:
    return CompiledPolicy(
        denylist=frozenset(),
        external_comms_tools=frozenset({"send_email"}),
        taint_sources={"read_secret": TaintTier.HIGH, "read_log": TaintTier.MEDIUM},
        tool_rules={},
        injection_signatures=frozenset(),
        content_scan_sources=frozenset(),
    )


def test_empty_trajectory_allows() -> None:
    traj = SessionTrajectory(_policy(), max_depth=50)
    assert traj.assess("send_email").verdict is Verdict.ALLOW


def test_allowed_high_source_then_external_blocks() -> None:
    traj = SessionTrajectory(_policy(), max_depth=50)
    traj.record("read_secret", Verdict.ALLOW)
    verdict = traj.assess("send_email")
    assert verdict.verdict is Verdict.BLOCK
    assert verdict.rule_id == "trajectory.sensitive_to_external"
    assert verdict.tool_name == "send_email"


def test_high_source_then_non_external_allows() -> None:
    traj = SessionTrajectory(_policy(), max_depth=50)
    traj.record("read_secret", Verdict.ALLOW)
    assert traj.assess("read_file").verdict is Verdict.ALLOW


def test_medium_source_does_not_trigger() -> None:
    traj = SessionTrajectory(_policy(), max_depth=50)
    traj.record("read_log", Verdict.ALLOW)  # MEDIUM tier, not HIGH
    assert traj.assess("send_email").verdict is Verdict.ALLOW


def test_blocked_high_source_is_not_counted() -> None:
    traj = SessionTrajectory(_policy(), max_depth=50)
    traj.record("read_secret", Verdict.BLOCK)  # denied -> no secret flowed
    assert traj.assess("send_email").verdict is Verdict.ALLOW


def test_sensitive_entry_within_window_still_blocks() -> None:
    traj = SessionTrajectory(_policy(), max_depth=3)
    traj.record("read_secret", Verdict.ALLOW)
    traj.record("read_file", Verdict.ALLOW)
    assert traj.assess("send_email").verdict is Verdict.BLOCK


def test_eviction_drops_the_sensitive_entry() -> None:
    traj = SessionTrajectory(_policy(), max_depth=2)
    traj.record("read_secret", Verdict.ALLOW)  # sensitive, counted
    traj.record("read_file", Verdict.ALLOW)
    traj.record("list_dir", Verdict.ALLOW)  # evicts read_secret, decrements counter
    assert traj.assess("send_email").verdict is Verdict.ALLOW
