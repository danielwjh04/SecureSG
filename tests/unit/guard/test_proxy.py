"""Unit tests for proxy helpers whose paths are awkward to reach over HTTP."""

from secureSG.guard.proxy import _drift_signal
from secureSG.schemas.tool_call import ToolCallSchema
from secureSG.schemas.verdict import Verdict
from secureSG.warden.embeddings import EmbeddingCache, EmbeddingProvider, Vector
from secureSG.warden.intent import IntentDriftDetector


class _StubEmbedder(EmbeddingProvider):
    async def embed(self, texts: list[str]) -> list[Vector]:
        return [[1.0, 0.0] for _ in texts]


def _call(name: str) -> ToolCallSchema:
    return ToolCallSchema.model_validate(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        }
    )


async def test_drift_signal_fails_closed_when_intent_unset() -> None:
    detector = IntentDriftDetector(
        EmbeddingCache(_StubEmbedder()), review_threshold=0.45, block_threshold=0.20
    )
    signal = await _drift_signal(detector, _call("read_file"))
    assert signal.verdict is Verdict.BLOCK
    assert signal.rule_id == "drift.unavailable"
