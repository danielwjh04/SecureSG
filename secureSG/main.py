"""Entrypoint: build the proxy from settings and serve it, degrading gracefully.

The heavy ML providers (the guard model, the embedding model) are loaded if
their weights and wheels are present; otherwise the proxy runs in
deterministic-only mode — no semantic screening, no intent drift — rather than
refusing to start. The deterministic policy, field-level taint tracking, the
trajectory rule, and the audit chain are always active.
"""

import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import Settings
from secureSG.dashboard import api as dashboard_api
from secureSG.dashboard import ws as dashboard_ws
from secureSG.dashboard.hub import EventHub
from secureSG.dashboard.reader import AuditReader
from secureSG.dashboard.service import DashboardService
from secureSG.dashboard.store import DashboardStore
from secureSG.exceptions import ModelLoadError, SecureSGError
from secureSG.guard.backend import HttpMcpBackend, McpBackend
from secureSG.guard.enforcer import Enforcer
from secureSG.guard.policy import CompiledPolicy, load_policy
from secureSG.guard.proxy import create_app
from secureSG.guard.screening import Screener
from secureSG.models.loader import load_guard_provider
from secureSG.warden.embeddings import EmbeddingCache, load_embedding_provider

_LOGGER = logging.getLogger("secureSG.main")

_SPA_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


def _mount_spa(app: FastAPI, dist: Path = _SPA_DIST) -> None:
    """Serve the built dashboard SPA at / when its dist directory exists.

    Mounted last so the API routes registered earlier always win; ``html=True``
    serves ``index.html`` for ``/`` and the hashed assets under ``/assets``.
    """
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="spa")


def _build_backend(settings: Settings) -> McpBackend:
    """Build the HTTP MCP backend, failing loudly if no URL is configured."""
    if settings.mcp_backend_url is None:
        raise SecureSGError(
            "SECURESG_MCP_BACKEND_URL must be set to forward calls to the MCP server"
        )
    return HttpMcpBackend(
        settings.mcp_backend_url, timeout=settings.mcp_backend_timeout
    )


def _build_screener(settings: Settings, policy: CompiledPolicy) -> Screener | None:
    """Build the semantic screener, or None if the guard model cannot load."""
    try:
        provider = load_guard_provider(settings)
    except ModelLoadError as exc:
        _LOGGER.warning(
            "guard model unavailable (%s); running deterministic-only screening",
            exc.__class__.__name__,
        )
        return None
    return Screener(
        injection_signatures=policy.injection_signatures,
        provider=provider,
        block_threshold=settings.semantic_block_threshold,
        review_threshold=settings.semantic_review_threshold,
    )


def _build_embedding_cache(settings: Settings) -> EmbeddingCache | None:
    """Build the embedding cache, or None if the embedding model cannot load."""
    try:
        provider = load_embedding_provider(settings)
    except ModelLoadError as exc:
        _LOGGER.warning(
            "embedding model unavailable (%s); intent drift detection disabled",
            exc.__class__.__name__,
        )
        return None
    return EmbeddingCache(provider)


def _build_dashboard(settings: Settings, genesis_hash: str) -> DashboardService | None:
    """Build the dashboard service, or None when the dashboard is disabled."""
    if not settings.dashboard_enabled:
        return None
    hub = EventHub(queue_size=settings.dashboard_ws_queue_size)
    store = DashboardStore(
        max_alerts=settings.dashboard_max_alerts,
        max_registry=settings.dashboard_max_registry,
    )
    return DashboardService(
        hub=hub, store=store, db_path=settings.db_path, genesis_hash=genesis_hash
    )


def _mount_dashboard(
    app: FastAPI, settings: Settings, dashboard: DashboardService
) -> None:
    """Mount the dashboard routers and place its dependencies on app state."""
    app.state.dashboard = dashboard
    app.state.audit_reader = AuditReader(settings.db_path)
    app.state.settings = settings
    app.include_router(dashboard_api.router)
    app.include_router(dashboard_ws.router)


def build_app(settings: Settings) -> FastAPI:
    """Construct the proxy app, degrading to deterministic-only without models.

    Mounts the dashboard (REST + WebSocket) and wires its live-event emitter
    when ``dashboard_enabled``; otherwise the proxy runs headless.

    Time complexity: O(policy size) plus a one-time model load.
    Space complexity: O(model size).
    """
    backend = _build_backend(settings)
    policy = load_policy(settings.policy_dir)
    genesis_hash = derive_genesis_hash(settings.genesis_seed)
    audit_logger = AuditLogger(
        db_path=settings.db_path,
        genesis_hash=genesis_hash,
        journal_mode=settings.sqlite_journal_mode,
    )
    enforcer = Enforcer(
        policy=policy,
        audit_logger=audit_logger,
        screener=_build_screener(settings, policy),
    )
    dashboard = _build_dashboard(settings, genesis_hash)
    app = create_app(
        settings=settings,
        enforcer=enforcer,
        audit_logger=audit_logger,
        policy=policy,
        mcp_backend=backend,
        embedding_cache=_build_embedding_cache(settings),
        emit=dashboard.handle if dashboard is not None else None,
    )
    if dashboard is not None:
        _mount_dashboard(app, settings, dashboard)
    _mount_spa(app)
    return app


def main() -> None:
    """Build the proxy from environment settings and serve it with uvicorn."""
    settings = Settings()
    app = build_app(settings)
    uvicorn.run(app, host=settings.proxy_host, port=settings.proxy_port)


if __name__ == "__main__":  # pragma: no cover
    main()
