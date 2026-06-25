"""Tool-schema risk discovery via embedding similarity to risk-concept anchors.

Each tool's name and description is embedded and compared (cosine) to a set of
configurable risk-concept anchors; a tool's risk score is its highest similarity
to any anchor. Tools scoring at or above the threshold are flagged for scope
reduction. Anchors are data (``warden/risk_anchors.yaml``), never inline literals.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml

from secureSG.exceptions import PolicyError
from secureSG.schemas.tool_schema import ToolSchema
from secureSG.warden.embeddings import EmbeddingCache, cosine_similarity


@dataclass(frozen=True, slots=True)
class ToolRisk:
    """A discovered tool's risk score and whether it crosses the threshold."""

    tool_name: str
    risk_score: float
    is_risky: bool


def load_risk_anchors(path: Path) -> list[str]:
    """Load risk-concept anchor phrases from a YAML file.

    Raises:
        PolicyError: if the file is missing, malformed, or has no anchors.

    Time complexity: O(file size). Space complexity: O(anchor count).
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot load risk anchors from {path}: {exc}") from exc
    anchors = data.get("risk_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise PolicyError(f"risk anchors file {path} has no 'risk_anchors' list")
    return [str(anchor) for anchor in anchors]


class ToolRiskDiscovery:
    """Scores MCP tools by embedding similarity to risk-concept anchors."""

    def __init__(
        self, cache: EmbeddingCache, anchors: list[str], *, threshold: float
    ) -> None:
        if not anchors:
            raise ValueError("ToolRiskDiscovery requires at least one risk anchor")
        self._cache = cache
        self._anchors = anchors
        self._threshold = threshold

    async def assess_tools(self, tools: list[ToolSchema]) -> list[ToolRisk]:
        """Score each tool by its max cosine to any risk anchor.

        Time complexity: O(tools * anchors * d). Space: O(tools + anchors).
        """
        anchor_vectors = await self._cache.get_many(self._anchors)
        tool_texts = [f"{tool.name}: {tool.description}" for tool in tools]
        tool_vectors = await self._cache.get_many(tool_texts)
        risks: list[ToolRisk] = []
        for tool, tool_vector in zip(tools, tool_vectors, strict=True):
            score = max(
                cosine_similarity(tool_vector, anchor) for anchor in anchor_vectors
            )
            risks.append(
                ToolRisk(
                    tool_name=tool.name,
                    risk_score=score,
                    is_risky=score >= self._threshold,
                )
            )
        return risks
