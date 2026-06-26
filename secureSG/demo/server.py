"""Self-contained demo server: the proxy, a mock MCP backend, the dashboard, and
the built SPA, all on one port.

Run it with ``python -m secureSG.demo.server`` and open the printed URL: the
React dashboard's "Run Attack Demo" button drives the SP5 attack through this
proxy and the panels light up live. Unlike ``secureSG.main`` (which forwards to a
real MCP server), this wires ``MockMcpBackend`` with the canned demo tools and a
deterministic benign judge, so it needs no model weights and no external MCP. The
dashboard is always on here — it is the point of the demo.
"""

import uvicorn
from fastapi import FastAPI

from secureSG.audit.chain import derive_genesis_hash
from secureSG.audit.logger import AuditLogger
from secureSG.config.settings import Settings
from secureSG.dashboard.hub import EventHub
from secureSG.dashboard.service import DashboardService
from secureSG.dashboard.store import DashboardStore
from secureSG.demo.driver import _BenignJudge
from secureSG.demo.scenario import DEMO_RESPONSES
from secureSG.guard.backend import MockMcpBackend
from secureSG.guard.enforcer import Enforcer
from secureSG.guard.policy import load_policy
from secureSG.guard.proxy import create_app
from secureSG.guard.screening import Screener
from secureSG.main import _mount_dashboard, _mount_spa


def build_demo_app(settings: Settings) -> FastAPI:
    """Build the demo app: proxy over a mock MCP backend, dashboard, and SPA.

    Time complexity: O(policy size). Space complexity: O(1).
    """
    policy = load_policy(settings.policy_dir)
    genesis_hash = derive_genesis_hash(settings.genesis_seed)
    audit_logger = AuditLogger(
        db_path=settings.db_path,
        genesis_hash=genesis_hash,
        journal_mode=settings.sqlite_journal_mode,
    )
    screener = Screener(
        injection_signatures=policy.injection_signatures,
        provider=_BenignJudge(),
        block_threshold=settings.semantic_block_threshold,
        review_threshold=settings.semantic_review_threshold,
    )
    enforcer = Enforcer(policy=policy, audit_logger=audit_logger, screener=screener)
    dashboard = DashboardService(
        hub=EventHub(queue_size=settings.dashboard_ws_queue_size),
        store=DashboardStore(
            max_alerts=settings.dashboard_max_alerts,
            max_registry=settings.dashboard_max_registry,
        ),
        db_path=settings.db_path,
        genesis_hash=genesis_hash,
    )
    app = create_app(
        settings=settings,
        enforcer=enforcer,
        audit_logger=audit_logger,
        policy=policy,
        mcp_backend=MockMcpBackend(DEMO_RESPONSES),
        embedding_cache=None,
        emit=dashboard.handle,
    )
    _mount_dashboard(app, settings, dashboard)
    _mount_spa(app)
    return app


def main() -> None:  # pragma: no cover
    """Serve the self-contained demo app with uvicorn."""
    settings = Settings()
    app = build_demo_app(settings)
    uvicorn.run(app, host=settings.proxy_host, port=settings.proxy_port)


if __name__ == "__main__":  # pragma: no cover
    main()
