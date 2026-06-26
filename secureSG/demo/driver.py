"""Self-contained demo: runs the scripted attack through the proxy in-process.

Run it with ``python -m secureSG.demo.driver``. It builds the SecureSG proxy
over a mock MCP server, declares an intent, fires the scripted steps, and prints
the verdict each defense returns — then verifies the audit chain is intact. No
network and no model weights are required: the verdicts come from deterministic
signatures, field-level taint, and the trajectory rule, never from ML.
"""

import asyncio
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.audit.verifier import ChainStatus, ChainVerifier
from secureSG.config.settings import Settings
from secureSG.demo.scenario import (
    DEMO_GENESIS_SEED,
    DEMO_INTENT,
    DEMO_RESPONSES,
    DEMO_STEPS,
    DemoStep,
)
from secureSG.guard.backend import MockMcpBackend
from secureSG.guard.enforcer import Enforcer
from secureSG.guard.policy import load_policy
from secureSG.guard.proxy import create_app
from secureSG.guard.screening import Screener
from secureSG.models.provider import ModelProvider
from secureSG.schemas.assessment import AssessmentTask, SemanticAssessment


class _BenignJudge(ModelProvider):
    """The demo's deterministic semantic stand-in (the real Qwen judge is
    validated after SP7). It reports every input benign, so the demo's BLOCKs
    are driven purely by deterministic signatures, taint, and the trajectory
    rule — never by ML.
    """

    async def assess(self, content: str, task: AssessmentTask) -> SemanticAssessment:
        return SemanticAssessment(task=task, p_unsafe=0.0)

    async def generate(self, prompt: str, *, grammar: str | None = None) -> str:
        return ""


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """The classified result of one demo step."""

    label: str
    blocked: bool
    rule_id: str | None
    matched_expectation: bool


def _rpc(rpc_id: int, step: DemoStep) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": step.tool, "arguments": step.arguments},
    }


def _build_app(settings: Settings, audit_logger: AuditLogger) -> FastAPI:
    policy = load_policy(settings.policy_dir)
    screener = Screener(
        injection_signatures=policy.injection_signatures,
        provider=_BenignJudge(),
        block_threshold=settings.semantic_block_threshold,
        review_threshold=settings.semantic_review_threshold,
    )
    enforcer = Enforcer(policy=policy, audit_logger=audit_logger, screener=screener)
    return create_app(
        settings=settings,
        enforcer=enforcer,
        audit_logger=audit_logger,
        policy=policy,
        mcp_backend=MockMcpBackend(DEMO_RESPONSES),
    )


def _classify(step: DemoStep, body: dict[str, Any]) -> StepOutcome:
    error = body.get("error")
    if error is None:
        return StepOutcome(
            step.label,
            blocked=False,
            rule_id=None,
            matched_expectation=step.expected_rule_id is None,
        )
    rule_id: str = error["data"]["rule_id"]
    return StepOutcome(
        step.label,
        blocked=True,
        rule_id=rule_id,
        matched_expectation=rule_id == step.expected_rule_id,
    )


def _render(index: int, outcome: StepOutcome) -> str:
    decision = (
        f"BLOCK [{outcome.rule_id}]" if outcome.blocked else "ALLOW (forwarded)"
    )
    mark = "OK" if outcome.matched_expectation else "UNEXPECTED"
    return f"  step {index}: {outcome.label} -> {decision}  [{mark}]"


async def run_demo(
    db_path: Path, *, emit: Callable[[str], None] = print
) -> list[StepOutcome]:
    """Run the scripted scenario against the in-process proxy, emitting a report.

    Time complexity: O(steps). Space complexity: O(steps).
    """
    settings = Settings(
        _env_file=None, db_path=db_path, genesis_seed=DEMO_GENESIS_SEED
    )
    genesis = derive_genesis_hash(settings.genesis_seed)
    audit_logger = AuditLogger(
        db_path=db_path,
        genesis_hash=genesis,
        journal_mode=settings.sqlite_journal_mode,
    )
    app = _build_app(settings, audit_logger)
    outcomes: list[StepOutcome] = []
    emit(f"SecureSG demo - declared intent: {DEMO_INTENT}")
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://demo"
        ) as client:
            created = await client.post("/sessions", json={"intent": DEMO_INTENT})
            session = created.json()["session_id"]
            for index, step in enumerate(DEMO_STEPS, start=1):
                response = await client.post(
                    f"/sessions/{session}/rpc", json=_rpc(index, step)
                )
                outcome = _classify(step, response.json())
                outcomes.append(outcome)
                emit(_render(index, outcome))
    result = await ChainVerifier(db_path=db_path, genesis_hash=genesis).verify()
    intact = result.status is ChainStatus.CHAIN_OK
    emit(f"audit chain: {'INTACT' if intact else 'BROKEN'}")
    return outcomes


def main() -> None:
    """Run the demo against a throwaway audit database and print the report."""
    with tempfile.TemporaryDirectory() as tmp:
        asyncio.run(run_demo(Path(tmp) / "demo_audit.db"))


if __name__ == "__main__":  # pragma: no cover
    main()
