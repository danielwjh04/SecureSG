# SP4 — Warden Governance — Design Spec

**Status:** Approved (2026-06-26).
**Depends on:** SP1 (audit), SP2 (policy IR), SP3 (model provider pattern), SP3.5 (authoring / PolicySchema).
**Delivers:** the Warden's four governance components — embeddings, intent-to-action drift detection, tool-schema risk discovery, and scope reduction — each tested standalone behind a deterministic stub.

---

## 1. Decisions locked

| Question | Decision |
|---|---|
| Embedding backend | **sentence-transformers + PyTorch** (all-MiniLM-L6-v2) behind a swappable `EmbeddingProvider`. Lazy-imported, fail-loud loader; CI uses a deterministic stub, the real path is `@pytest.mark.model`-gated. |
| Cosine similarity | **Pure-Python, O(d)** over `list[float]` — no numpy forced on CI; a single dot product is not a numpy-array loop, and correctness-first beats premature vectorization. |
| Drift output | The detector emits a `Verdict`, so SP5 folds it into the same **tighten-only** max as the screener. |
| Scope output | Warden **recommends** a denylist as a `PolicySchema` delta that flows through the SP3.5 human-approved propose/activate path or the enforcer — never auto-applied to live policy. |

---

## 2. Module layout

```
secureSG/
  warden/
    embeddings.py   # EmbeddingProvider ABC + SentenceTransformerProvider + loader;
                    #   EmbeddingCache; pure-Python cosine_similarity
    intent.py       # IntentDriftDetector: cache session intent vector once, cosine vs each call
    discovery.py    # ToolRiskDiscovery: embed tool schema vs risk-concept anchors -> ToolRisk
    scope.py        # ScopeReducer: ToolRisk[] -> denylist / PolicySchema delta
    risk_anchors.yaml  # curated risk-concept phrases (data, not code)
  schemas/
    tool_schema.py  # ToolSchema(name, description) — minimal MCP tool descriptor
```

---

## 3. Embeddings (`warden/embeddings.py`)

- `type Vector = list[float]`.
- `cosine_similarity(a: Vector, b: Vector) -> float` — pure, O(d); returns 0.0 if either vector has zero norm (no division by zero).
- `class EmbeddingProvider(ABC)`: `async def embed(self, texts: list[str]) -> list[Vector]`. The real `SentenceTransformerProvider` wraps `SentenceTransformer(...).encode(texts)` in `asyncio.to_thread` (CPU-bound, off the event loop) and returns `.tolist()` rows; the native import + model load are gated.
- `class EmbeddingCache`: memoizes `text -> Vector` via the provider so the session intent vector (and any repeated text) is embedded once (CLAUDE.md §2). `async def get(self, text) -> Vector`.
- `load_embedding_provider(settings) -> SentenceTransformerProvider` — lazy import; missing dependency or load failure raises `ModelLoadError` (fail-loud, no silent degrade).

Tests use a `StubEmbeddingProvider` mapping fixed texts to fixed vectors, so cosines and verdicts are exact.

---

## 4. Intent-to-action drift (`warden/intent.py`)

`class IntentDriftDetector(cache, *, review_threshold, block_threshold)`:
- `async def set_intent(self, intent_text)` — caches `embed(intent)` once via the cache.
- `async def assess_call(self, call_text) -> DriftAssessment` — `similarity = cosine(intent_vec, embed(call_text))`; **low** similarity is drift. Thresholds are similarity floors with `review > block`: `sim ≥ review → ALLOW`; `block ≤ sim < review → HUMAN_APPROVAL_REQUIRED`; `sim < block → BLOCK`.
- `DriftAssessment(frozen)`: `similarity: float`, `verdict: Verdict`.
- Calling `assess_call` before `set_intent` raises `InferenceError` (fail-closed; no ungrounded comparison).

---

## 5. Tool-schema risk discovery (`warden/discovery.py`)

- `ToolRisk(frozen)`: `tool_name: str`, `risk_score: float`, `is_risky: bool`.
- `class ToolRiskDiscovery(provider, anchors: list[str], *, threshold)`:
  - `async def assess_tools(self, tools: list[ToolSchema]) -> list[ToolRisk]` — embeds each tool's `"name: description"` and every anchor (batched), scores each tool by its **max cosine to any anchor**, flags `is_risky = score ≥ threshold`.
- Anchors load from `warden/risk_anchors.yaml` (`load_risk_anchors(path) -> list[str]`), e.g. "execute arbitrary code or shell commands", "send data to external recipients", "delete or destroy data", "read secrets or credentials". Configurable data, never inline literals; empty/malformed anchors file raises `PolicyError`.

---

## 6. Scope reduction (`warden/scope.py`)

`class ScopeReducer(*, threshold)`:
- `generate_denylist(self, risks: list[ToolRisk]) -> frozenset[str]` — the risky tool names.
- `generate_scope(self, risks: list[ToolRisk]) -> PolicySchema` — a `PolicySchema` with `denylist` filled, ready for the SP3.5 propose/activate path or direct enforcer load. Pure, O(tool count).

---

## 7. Settings / deps / errors

Settings: `embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"`, `drift_review_threshold: float = 0.45`, `drift_block_threshold: float = 0.20` (validated `0 ≤ block < review ≤ 1`), `tool_risk_threshold: float = 0.45`, `risk_anchors_path: Path` (default bundled). Deps: `sentence-transformers`, `torch` (lazy, gated; mypy `ignore_missing_imports` override). Reuse `ModelLoadError`/`InferenceError`; no new exception (YAGNI).

---

## 8. Testing

`StubEmbeddingProvider` (tests) maps texts to fixed vectors → exact cosines, no torch in CI. Coverage:
- `cosine_similarity`: identical → 1, orthogonal → 0, opposite → -1, zero-norm → 0.
- drift: aligned call → ALLOW, mid → HUMAN_APPROVAL_REQUIRED, far → BLOCK; `assess_call` before `set_intent` → `InferenceError`.
- discovery: a tool near a risk anchor → `is_risky`, a benign tool → not; max-over-anchors scoring.
- scope: risks → denylist + `PolicySchema` delta.
- settings threshold validator; anchor loading (valid + malformed).
- One `@pytest.mark.model`-gated real-MiniLM test: semantically similar texts score high, dissimilar low.
- Gates: coverage ≥ 85%, ruff, `mypy --strict`.

---

## 9. Scope boundary

SP4 delivers the four components, tested standalone. **Wiring** drift + discovery into the live request flow and session lifecycle is **SP5** (the proxy owns sessions and the agent's stated intent). No dashboard (SP6). No auto-application of recommended scope.

---

## 10. Build order (TDD)

1. Settings (embedding/drift/risk fields + validator), deps, mypy override; `schemas/tool_schema.py`; `warden/risk_anchors.yaml`.
2. `warden/embeddings.py` — `cosine_similarity` + `EmbeddingProvider` + `EmbeddingCache` (stub-tested) + `SentenceTransformerProvider`/loader (gated).
3. `warden/intent.py` — `IntentDriftDetector`.
4. `warden/discovery.py` — anchor loader + `ToolRiskDiscovery`.
5. `warden/scope.py` — `ScopeReducer`.
6. Verify (suite, coverage ≥ 85%, ruff, mypy --strict); no competitor-reference leak; commit in logical commits.

---

## 11. Success criteria

- All SP1–SP3.5 tests stay green; every new public function has a unit test.
- Drift correctly bands aligned/uncertain/drifted calls; discovery flags tools near risk concepts; scope yields a human-approvable denylist.
- Coverage ≥ 85%, ruff clean, `mypy --strict` clean.
