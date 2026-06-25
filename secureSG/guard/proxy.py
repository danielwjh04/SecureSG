"""The transparent FastAPI proxy and its per-session orchestrator.

An agent first creates a session, declaring its intent (which grounds the SP4
drift detector). Every subsequent JSON-RPC tool call for that session runs the
full guard pipeline under a per-session lock:

    validate -> trajectory signal -> drift signal -> enforcer.evaluate
    (deterministic + folded signals + optional semantic, severity-max, audited)
    -> forward to the MCP backend only on ALLOW -> screen the untrusted result
    -> taint the result -> record the trajectory -> return.

The pipeline is fail-closed at every branch: an unparseable call, a missing
session, a backend failure, a malformed response, or an unavailable screener all
deny rather than forward unvalidated data. Replays are idempotent — a repeated
``(session, request id, arguments)`` returns the first response without
re-forwarding the call or re-writing the audit chain (CLAUDE.md section 2).
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import Settings
from secureSG.exceptions import BackendError, InferenceError, ModelError
from secureSG.guard.backend import McpBackend
from secureSG.guard.enforcer import Enforcer
from secureSG.guard.interceptor import (
    derive_result_transaction_id,
    derive_transaction_id,
    extract_result,
    parse_call,
)
from secureSG.guard.policy import CompiledPolicy
from secureSG.guard.screening import serialize_call
from secureSG.guard.taint import SessionTaintStore
from secureSG.guard.trajectory import SessionTrajectory
from secureSG.schemas.tool_call import JsonValue, ToolCallSchema
from secureSG.schemas.verdict import PolicyVerdict, Verdict
from secureSG.warden.embeddings import EmbeddingCache
from secureSG.warden.intent import IntentDriftDetector

_JSONRPC_VERSION: Final[str] = "2.0"
# JSON-RPC server-error range (-32000..-32099); distinct codes per denial cause.
_BLOCK_CODE: Final[int] = -32001
_APPROVAL_CODE: Final[int] = -32002
_SESSION_CODE: Final[int] = -32004
_BACKEND_CODE: Final[int] = -32010


class _SessionCreate(BaseModel):
    intent: str | None = None


class _SessionCreated(BaseModel):
    session_id: str


def _response_id(body: dict[str, Any]) -> int | str | None:
    """Return the JSON-RPC request id to echo, or None if absent/ill-typed."""
    rpc_id = body.get("id")
    return rpc_id if isinstance(rpc_id, (int, str)) else None


def _jsonrpc_success(rpc_id: int | str | None, result: JsonValue) -> dict[str, Any]:
    return {"jsonrpc": _JSONRPC_VERSION, "id": rpc_id, "result": result}


def _jsonrpc_error(
    rpc_id: int | str | None,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": _JSONRPC_VERSION, "id": rpc_id, "error": error}


def _deny(rpc_id: int | str | None, verdict: PolicyVerdict) -> dict[str, Any]:
    """Render a non-ALLOW verdict as a JSON-RPC denial carrying its provenance."""
    code = (
        _APPROVAL_CODE
        if verdict.verdict is Verdict.HUMAN_APPROVAL_REQUIRED
        else _BLOCK_CODE
    )
    return _jsonrpc_error(
        rpc_id,
        code,
        f"SecureSG {verdict.verdict.value}: {verdict.reason}",
        data={"verdict": verdict.verdict.value, "rule_id": verdict.rule_id},
    )


async def _drift_signal(
    detector: IntentDriftDetector, call: ToolCallSchema
) -> PolicyVerdict:
    """Render the drift assessment for a call as a tighten-only signal.

    A drift assessment before the intent is set (which the session-create
    endpoint prevents) fails closed to BLOCK rather than propagating.

    Time complexity: O(embedding dim). Space complexity: O(1).
    """
    try:
        assessment = await detector.assess_call(serialize_call(call))
    except InferenceError:
        return PolicyVerdict(
            verdict=Verdict.BLOCK,
            reason="intent drift unavailable; failing closed",
            rule_id="drift.unavailable",
            tool_name=call.tool_name,
        )
    return PolicyVerdict(
        verdict=assessment.verdict,
        reason=f"intent drift cosine={assessment.similarity:.3f}",
        rule_id="drift.intent",
        tool_name=call.tool_name,
    )


class SessionGuard:
    """Owns one session's mutable guard state and runs its call pipeline."""

    def __init__(
        self,
        session_id: str,
        *,
        policy: CompiledPolicy,
        settings: Settings,
        enforcer: Enforcer,
        mcp_backend: McpBackend,
        embedding_cache: EmbeddingCache | None,
    ) -> None:
        self.session_id = session_id
        self.lock = asyncio.Lock()
        self._enforcer = enforcer
        self._backend = mcp_backend
        self._taint = SessionTaintStore()
        self._trajectory = SessionTrajectory(
            policy, max_depth=settings.max_trajectory_depth
        )
        self._drift = (
            IntentDriftDetector(
                embedding_cache,
                review_threshold=settings.drift_review_threshold,
                block_threshold=settings.drift_block_threshold,
            )
            if embedding_cache is not None
            else None
        )
        self._responses: dict[UUID, dict[str, Any]] = {}

    async def set_intent(self, intent: str) -> None:
        """Ground drift detection in the agent's stated intent (once). O(embed)."""
        if self._drift is not None:
            await self._drift.set_intent(intent)

    async def handle_call(self, body: dict[str, Any]) -> dict[str, Any]:
        """Run the full guard pipeline for one tool call; idempotent on replay.

        Time complexity: O(call size + signals) + optional inference + forward.
        Space complexity: O(1) per call.
        """
        call = parse_call(body)
        response_id = _response_id(body)
        arguments = call.arguments if call is not None else {}
        txn = derive_transaction_id(
            self.session_id, response_id if response_id is not None else "", arguments
        )
        cached = self._responses.get(txn)
        if cached is not None:
            return cached
        response = await self._adjudicate(call, body, txn, response_id)
        self._responses[txn] = response
        return response

    async def _adjudicate(
        self,
        call: ToolCallSchema | None,
        body: dict[str, Any],
        txn: UUID,
        response_id: int | str | None,
    ) -> dict[str, Any]:
        if call is None:
            verdict = await self._enforcer.evaluate(
                body, self._taint, txn, session_id=self.session_id
            )
            return _deny(response_id, verdict)
        signals = [self._trajectory.assess(call.tool_name)]
        if self._drift is not None:
            signals.append(await _drift_signal(self._drift, call))
        verdict = await self._enforcer.evaluate(
            body,
            self._taint,
            txn,
            external_signals=signals,
            session_id=self.session_id,
        )
        self._trajectory.record(call.tool_name, verdict.verdict)
        if verdict.verdict is not Verdict.ALLOW:
            return _deny(response_id, verdict)
        return await self._forward_and_screen(call, response_id, txn)

    async def _forward_and_screen(
        self, call: ToolCallSchema, response_id: int | str | None, call_txn: UUID
    ) -> dict[str, Any]:
        try:
            raw_response = await self._backend.forward(call)
        except BackendError:
            return _jsonrpc_error(response_id, _BACKEND_CODE, "MCP backend unavailable")
        result = extract_result(raw_response, call.tool_name)
        if result is None:
            if "error" in raw_response:
                return raw_response  # the tool's own JSON-RPC error, forwarded as-is
            return _jsonrpc_error(
                response_id, _BLOCK_CODE, "malformed backend response; blocked"
            )
        result_txn = derive_result_transaction_id(call_txn)
        try:
            screen = await self._enforcer.screen_result(
                result, result_txn, session_id=self.session_id
            )
        except ModelError:
            return _jsonrpc_error(
                response_id, _BLOCK_CODE, "result screening unavailable; blocked"
            )
        if screen.verdict is Verdict.BLOCK:
            return _deny(response_id, screen)
        self._enforcer.observe_result(result, self._taint)
        return _jsonrpc_success(response_id, result.result)


def create_app(
    *,
    settings: Settings,
    enforcer: Enforcer,
    audit_logger: AuditLogger,
    policy: CompiledPolicy,
    mcp_backend: McpBackend,
    embedding_cache: EmbeddingCache | None = None,
) -> FastAPI:
    """Wire the SecureSG proxy: session control plane plus the RPC data plane.

    The audit logger is opened on startup and the logger and backend are closed
    on shutdown via the app lifespan. Time complexity: O(1).
    """

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await audit_logger.initialize()
        try:
            yield
        finally:
            await mcp_backend.aclose()
            await audit_logger.close()

    app = FastAPI(title="SecureSG Proxy", lifespan=lifespan)
    app.state.sessions = {}
    drift_enabled = embedding_cache is not None

    @app.post("/sessions", response_model=_SessionCreated)
    async def create_session(payload: _SessionCreate) -> _SessionCreated:
        if drift_enabled and not (payload.intent and payload.intent.strip()):
            raise HTTPException(
                status_code=422,
                detail="intent is required when drift detection is enabled",
            )
        session_id = uuid4().hex
        guard = SessionGuard(
            session_id,
            policy=policy,
            settings=settings,
            enforcer=enforcer,
            mcp_backend=mcp_backend,
            embedding_cache=embedding_cache,
        )
        if payload.intent is not None:
            await guard.set_intent(payload.intent)
        app.state.sessions[session_id] = guard
        return _SessionCreated(session_id=session_id)

    @app.post("/sessions/{session_id}/rpc")
    async def handle_rpc(session_id: str, body: dict[str, Any]) -> JSONResponse:
        guard: SessionGuard | None = app.state.sessions.get(session_id)
        if guard is None:
            return JSONResponse(
                status_code=404,
                content=_jsonrpc_error(
                    _response_id(body), _SESSION_CODE, "unknown session"
                ),
            )
        async with guard.lock:
            response = await guard.handle_call(body)
        return JSONResponse(content=response)

    return app
