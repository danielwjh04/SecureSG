"""Test the self-contained demo server wiring (mock backend + dashboard)."""

from pathlib import Path
from typing import Any

import httpx

from secureSG.config.settings import Settings
from secureSG.demo.server import build_demo_app


def _rpc(rpc_id: int, name: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": {}},
    }


async def test_demo_server_runs_scenario_and_records_alert(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, db_path=tmp_path / "audit.db")
    app = build_demo_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            session = (await client.post("/sessions", json={})).json()["session_id"]
            await client.post(f"/sessions/{session}/rpc", json=_rpc(1, "scrape_page"))
            alerts = (await client.get("/dashboard/alerts")).json()
    assert any(alert["rule_id"] == "injection.signature" for alert in alerts)
