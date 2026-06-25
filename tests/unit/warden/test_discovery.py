"""Tests for tool-schema risk discovery and risk-anchor loading."""

from collections.abc import Callable
from pathlib import Path

import pytest

from secureSG.config.settings import Settings
from secureSG.exceptions import PolicyError
from secureSG.schemas.tool_schema import ToolSchema
from secureSG.warden.discovery import ToolRiskDiscovery, load_risk_anchors
from secureSG.warden.embeddings import EmbeddingCache, EmbeddingProvider, Vector


def test_load_risk_anchors_reads_bundled_file() -> None:
    anchors = load_risk_anchors(Settings(_env_file=None).risk_anchors_path)
    assert anchors and all(isinstance(anchor, str) for anchor in anchors)


def test_load_risk_anchors_rejects_missing_key(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("other: 1\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_risk_anchors(bad)


def test_load_risk_anchors_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        load_risk_anchors(tmp_path / "nope.yaml")


def test_discovery_requires_at_least_one_anchor(
    make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider],
) -> None:
    with pytest.raises(ValueError, match="at least one risk anchor"):
        ToolRiskDiscovery(EmbeddingCache(make_embedder({})), [], threshold=0.45)


async def test_discovery_flags_tool_near_a_risk_anchor(
    make_embedder: Callable[[dict[str, Vector]], EmbeddingProvider],
) -> None:
    vectors: dict[str, Vector] = {
        "c1": [1.0, 0.0, 0.0],
        "c2": [0.0, 1.0, 0.0],
        "evil_tool: dangerous": [0.0, 1.0, 0.0],  # matches c2 -> max cosine 1.0
        "safe_tool: benign": [0.0, 0.0, 1.0],  # orthogonal to both anchors
    }
    discovery = ToolRiskDiscovery(
        EmbeddingCache(make_embedder(vectors)), ["c1", "c2"], threshold=0.45
    )
    risks = await discovery.assess_tools(
        [
            ToolSchema(name="evil_tool", description="dangerous"),
            ToolSchema(name="safe_tool", description="benign"),
        ]
    )
    by_name = {risk.tool_name: risk for risk in risks}
    assert by_name["evil_tool"].is_risky
    assert by_name["evil_tool"].risk_score == pytest.approx(1.0)
    assert not by_name["safe_tool"].is_risky
