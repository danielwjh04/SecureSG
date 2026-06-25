"""Tests for the propose/activate policy-authoring CLI core."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.policy_author import activate_policy, propose_policy
from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.audit.verifier import ChainStatus, ChainVerifier
from secureSG.exceptions import AuthoringError
from secureSG.guard.policy import load_policy
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment

GENESIS = derive_genesis_hash("author-test")

_ALL_FIELDS = json.dumps(
    {
        "denylist": ["execute_shell"],
        "external_comms_tools": ["send_email"],
        "content_scan_sources": ["scrape_page"],
        "tool_rules": {"read_file": "ALLOW"},
        "taint_sources": {"read_secret": "HIGH"},
    }
)
_TOOLS = ["execute_shell", "send_email", "scrape_page", "read_file", "read_secret"]


class _Stub(ModelProvider):
    def __init__(self, output: str) -> None:
        self._output = output

    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment:
        raise NotImplementedError

    async def generate(self, prompt: str, *, grammar: str | None = None) -> str:
        return self._output


async def test_propose_writes_staged_file_without_activating(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    proposed_dir = tmp_path / "proposed"
    path, proposal = await propose_policy(
        _Stub(_ALL_FIELDS),
        "broad lockdown",
        tools=_TOOLS,
        policy_dir=policy_dir,
        proposed_dir=proposed_dir,
        name="lockdown",
    )
    assert path == proposed_dir / "lockdown.yaml"
    content = path.read_text(encoding="utf-8")
    assert "broad lockdown" in content  # intent provenance in the header
    assert "execute_shell" in content
    assert not proposal.diff.is_empty()
    # propose must never touch the active policy directory
    assert list(policy_dir.glob("*.yaml")) == []


async def test_activate_promotes_and_audits_to_chain(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    proposed_dir = tmp_path / "proposed"
    db_path = tmp_path / "audit.db"
    staged, _ = await propose_policy(
        _Stub(json.dumps({"denylist": ["execute_shell"]})),
        "block shell",
        tools=["execute_shell"],
        policy_dir=policy_dir,
        proposed_dir=proposed_dir,
        name="lockdown",
    )
    logger = AuditLogger(db_path=db_path, genesis_hash=GENESIS)
    await logger.initialize()
    target = await activate_policy(
        staged, policy_dir=policy_dir, audit_logger=logger, transaction_id=uuid4()
    )
    assert target == policy_dir / "lockdown.yaml"
    assert load_policy(policy_dir).is_denied("execute_shell")
    assert logger.get_chain_tail() != GENESIS
    await logger.close()
    result = await ChainVerifier(db_path=db_path, genesis_hash=GENESIS).verify()
    assert result.status is ChainStatus.CHAIN_OK


async def test_activate_rejects_invalid_staged_file(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    bad = tmp_path / "bad.yaml"
    bad.write_text("tool_rules:\n  read_file: NOPE\n", encoding="utf-8")
    logger = AuditLogger(db_path=tmp_path / "audit.db", genesis_hash=GENESIS)
    await logger.initialize()
    with pytest.raises(AuthoringError):
        await activate_policy(
            bad, policy_dir=policy_dir, audit_logger=logger, transaction_id=uuid4()
        )
    await logger.close()
