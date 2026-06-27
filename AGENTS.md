# AGENTS.md — SecureSG

## What This File Is

This file is the single source of truth for how code is written, reasoned about, and reviewed in this repository. Every session starts here. Read it fully before touching anything.

---

## Project Identity

**SecureSG** is a runtime control layer and governance engine that sits as a bidirectional transparent proxy between an LLM agent and its MCP server environment. The core value proposition is **Verifiable Enforcement**: cryptographic audit trails that prove the guard was correct, rather than asking users to trust the vendor.

Two subsystems:
- **Guard**: inline interceptor that evaluates tool calls (ALLOW / BLOCK / HUMAN_APPROVAL_REQUIRED)
- **Warden**: governance engine that performs risk discovery, scope reduction, and intent-to-action drift detection

Stack: Python 3.12+, FastAPI, Uvicorn, PyTorch, HuggingFace Transformers (Qwen3-0.8B q4_K_M), Pydantic, SQLite, WebSockets/HTTP.

This is the official github repo: https://github.com/danielwjh04/SecureSG.git

---

## Hackathon Context & Build Targets

SecureSG is a **build2026 / PetaniAI** hackathon submission. Weigh every feature decision against the rubric below — ship demonstrable value, not infrastructure for its own sake. The engineering rules in the rest of this file still hold; this section sets *what to build toward*.

### Challenge fit
- **Primary — #3 Security, Resilience & Defense:** SecureSG hardens organizations and individuals against the new attack surface of autonomous AI agents (prompt injection, secret exfiltration, unsafe tool use).
- **Secondary — #4 AI-Native Organizations:** it is the safety layer that lets a business adopt agent-driven operations without losing control.

### Judging criteria → how to win each
| Criterion | Weight | What to optimize |
|---|---|---|
| Proof of Work — Functionality | 25% | A real, live build. The agent-hook demo must block a *real* agent on stage with the dashboard reacting live. No mocked demos. |
| Problem fit & Market Value | 25% | Real user = any dev or org running coding/agent tools. Lead with the concrete threat and who pays to stop it. |
| Design, Craft & Taste | 20% | The dashboard is the product's face. Intuitive, purposeful, tasteful — every panel earns its place. |
| Innovation & Sponsor Tech | 30% | **Highest weight.** A sponsor tool (OpenAI/Codex, Exa, Cursor, Zo) must be *central and inventive*, not bolted on. The core idea must read as genuinely fresh. |

### Strategic priority — the 30% lever
The single biggest scoring lever is **sponsor-tech centrality (30%)**. SecureSG currently centers on Claude Code + Ollama — **neither is a listed sponsor.** Closing this gap is the top non-engineering priority. Make one sponsor tool load-bearing in the demo, e.g.:
- **OpenAI / Codex** — guard a Codex agent via its PreToolUse hooks (same mechanism as the existing Claude Code integration). Most natural fit; closes the sponsor gap directly.
- **Exa** — power *dynamic* URL/content reputation in the Warden, replacing the static blocklist with live search-based risk discovery.
- **Cursor / Zo** — protect the agent operating inside those environments.

Do not bolt a sponsor on as an afterthought. Pick one and make the demo *depend* on it.

### Submission checklist (all required)
1. Pitch deck link
2. Public repo link (https://github.com/danielwjh04/SecureSG.git)
3. Demo video link
4. Live website URL
5. Social post (X / Instagram / LinkedIn) tagging **#supcareer #build2026 #hackathon #PetaniAI**

---

## 0. Think Before Coding

Do not assume. Do not hide confusion. Surface tradeoffs.

Before implementing:
- State assumptions explicitly. If uncertain, ask in the session rather than guessing.
- If multiple interpretations exist, present them. Never pick one silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what is confusing. Ask.

This rule sits above all others. In a security product, a wrong primitive built confidently is worse than a missing one flagged early.

---

## 1. Core Engineering Philosophy

These rules are non-negotiable. They apply to every file, every function, every PR.

### No Shortcuts. Ever.

If there is a correct way to implement something and a shortcut that approximates it, the correct way is always chosen. This is a security system. Approximations in security systems are vulnerabilities.

- Never stub out a validation step with `pass` or a TODO in production paths.
- Never use a regex where a proper parser is required.
- Never skip a hash verification step because it probably has not changed.
- Never trust input from any external source without passing it through the schema validator.

### Zero Placeholders, Full Completeness

Deliver the finished product, not a plan or a blueprint.

- Never leave `// TODO: implement later`, dangling endpoints, or stubbed returns in a delivered path.
- Never offer a workaround when a permanent fix is reachable.
- Scope completeness means edge cases, documentation, and tests ship together with the feature.
- Complexity or time pressure is never a reason to compromise on depth.

### No Hardcoding

Zero hardcoded values anywhere in the codebase. Every configurable value lives in one of three places:

| Type | Location |
|------|----------|
| Runtime config (ports, paths, timeouts) | `config/settings.py` via Pydantic `BaseSettings` |
| Policy rules | `policies/` directory, loaded at startup |
| Secrets / API keys | Environment variables only, never in code |

If you find yourself typing a literal like `"localhost"`, `8080`, `"sha256"`, or a model name inline, stop. It belongs in `settings.py`.

### Simplicity First

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No flexibility or configurability that was not requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

The test: would a senior engineer call this overcomplicated? If yes, simplify. Speculative abstraction is itself a shortcut.

### OOP and Coding Discipline

Use object-oriented structure where it models the domain (Guard, Warden, AuditChain, Verdict are objects, not loose functions). Keep behavior and the state it owns together. Favor composition over deep inheritance.

### Explicit Over Implicit

- No magic. No hidden side effects.
- If a function modifies state, the name and signature make that obvious.
- Prefer longer, descriptive names over short ambiguous ones.
- No wildcard imports.

### Fail Loudly, Not Silently

- Raise a typed exception with a descriptive message instead of returning `None` or `-1` on error.
- Never swallow exceptions with a bare `except:` or `except Exception: pass`.
- On I/O or provider APIs (Anthropic / OpenAI / model inference), never swallow the exception. Log a warning with the exact exception class.
- High-risk tools are fail-closed by default. If a verdict cannot be computed, the action is blocked.

---

## 2. Algorithmic Standards

Every data structure and algorithm choice must be justified against these criteria.

### Correctness Before Cleverness

Every non-trivial algorithm must:
1. Be implemented correctly per its specification first.
2. Have its time and space complexity documented in the docstring.
3. Only then be optimized, if a profile shows it is a bottleneck.

Suboptimal-but-correct always beats clever-but-wrong. Premature optimization is not permitted.

### Vectorization

All data pipelines and ML feature work must be strictly vectorized. Zero `for` loops over pandas Series or numpy arrays. Use vectorized ops, broadcasting, or `np.vectorize` only as a last resort with a documented reason.

### Idempotency

Execution, routing, and state changes must be strictly idempotent. Replaying the same intercepted tool call, the same audit append, or the same policy load must not corrupt state or double-write the chain.

### Time Complexity Targets

Runtime operations target O(1) or O(log n). The table below is the contract.

| Operation | Target | Notes |
|-----------|--------|-------|
| Denylist lookup | O(1) | `frozenset` or hash set, never a list scan |
| Policy rule matching (deterministic) | O(1) to O(k) | k = rule count; compiled trie or hash map |
| Taint label propagation | O(n) | n = fields in the call graph; no nested full rescans |
| Hash chain verification | O(n) | single forward pass |
| Embedding similarity (intent drift) | O(d) per comparison | d = embedding dim; cache the session intent vector |
| Session trajectory lookup | O(log n) or O(1) | ordered dict or indexed ring buffer, never full scan |
| Audit log append | O(1) amortized | append-only with WAL mode in SQLite |

### Space Complexity

- Do not buffer full scraped page content in memory. Use streaming reads with chunked processing.
- Session trajectory state is bounded. Define `MAX_TRAJECTORY_DEPTH` (default 50) and evict oldest entries.
- Taint labels propagate lazily. Copy provenance metadata only, never full data blobs.

### Prohibited Patterns

```python
# NEVER: O(n) list scan for membership test
if tool_name in ["read_file", "list_dir", "get_secret"]:
    ...
# CORRECT: O(1) set lookup
if tool_name in DENYLIST_TOOLS:  # frozenset in settings
    ...

# NEVER: recompute embedding on every call
similarity = cosine(embed(user_prompt), embed(tool_arg))
# CORRECT: cache the session intent vector at session start
similarity = cosine(session.intent_vector, embed(tool_arg))

# NEVER: full audit log scan to get latest hash
prev_hash = db.query("SELECT curr_hash FROM audit_log ORDER BY created_at DESC LIMIT 1")
# CORRECT: keep a pointer to the tail
prev_hash = db.get_chain_tail()

# NEVER: a for loop over a numpy array
risk = [score(x) for x in arr]
# CORRECT: vectorized
risk = score_vectorized(arr)
```

---

## 3. Goal-Driven Execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals before writing code:
- "Add validation" becomes "Write tests for invalid inputs, then make them pass"
- "Fix the bug" becomes "Write a test that reproduces it, then make it pass"
- "Refactor X" becomes "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
3. [Step] -> verify: [check]
```

Strong success criteria let Claude Code loop independently. Weak criteria like "make it work" force constant clarification, so define the check up front.

### Search and Test First

Thoroughly understand the existing codebase before modifying or building. Write comprehensive tests and verify execution before presenting the final changes.

---

## 4. Surgical Changes

Touch only what you must. Clean up only your own mess.

When editing existing code:
- Do not improve adjacent code, comments, or formatting.
- Do not refactor things that are not broken.
- Match existing style even where you would do it differently.
- If you notice unrelated dead code, mention it. Do not delete it.

When your changes create orphans:
- Remove imports, variables, or functions that your changes made unused.
- Do not remove pre-existing dead code unless asked.
- Never rename variables or reformat in the same commit as a logic change.

The test: every changed line traces directly to the request.

### Git Attribution

Do not add AI attribution trailers to commits. No `Co-authored-by: Claude`, no "Generated with Claude Code" lines, no attribution in commit bodies or PR descriptions.

---

## 5. Code Style

### Python Version

Python 3.12+. Use modern features: `match` for verdict dispatch, `TypeAlias`, `Self`, `type X = ...` syntax.

### Type Annotations

Every function has full type annotations. No `Any` except where genuinely unavoidable, and when used it carries a `# type: ignore[...]  # reason: ...` comment.

```python
# WRONG
def evaluate(call, context): ...

# CORRECT
async def evaluate(
    call: ToolCallSchema,
    context: SessionContext,
) -> PolicyVerdict: ...
```

### Docstrings

Every public function, class, and module has a docstring with a complexity note.

```python
def compute_hash_chain(prev_hash: str, payload: bytes) -> str:
    """Compute the next link in the audit hash chain.

    Args:
        prev_hash: SHA-256 hex digest of the previous log entry.
        payload: Serialized bytes of the current transaction record.

    Returns:
        SHA-256 hex digest of (prev_hash + payload).

    Time complexity: O(n) where n = len(payload).
    Space complexity: O(1).
    """
```

### Async Rules

- All I/O-bound operations (DB writes, HTTP, model inference) are `async`.
- Never call a blocking function inside an async context. Use `asyncio.to_thread()` for CPU-bound work.
- No `asyncio.sleep(0)` yielding hacks. Use proper task scheduling.

### Error Handling

Define typed exceptions in `secureSG/exceptions.py`. Never raise bare `Exception`.

```python
class PolicyViolationError(SecurityError): ...
class ChainIntegrityError(AuditError): ...
class TaintPropagationError(SecurityError): ...
```

---

## 6. Security-Specific Rules

This is a security product and you are a security senior engineer working for top security firms in the world. These rules are stricter than standard Python practice. There is no room for sloppiness or your juniors will learn bad habits.

### Input Validation

- Every inbound JSON-RPC call is validated against a Pydantic schema before any logic runs.
- Schema validation failures are logged as `BLOCK` verdicts, not Python exceptions that bubble to the client.
- Never trust field names or values from external input to select execution paths. Allowlist all valid field values.

### Hash Chain Integrity

- SHA-256 only. Never MD5, never SHA-1.
- `curr_hash = sha256(prev_hash.encode() + payload).hexdigest()`
- The chain tail pointer updates atomically in the same SQLite transaction as the log insert. Never split these into two operations.
- Chain verification runs on startup and on dashboard trigger. It is a single forward pass, O(n).

### Taint Tracking

- Taint labels attach at the field level, not the call level.
- A field is labeled with its source tool and risk tier on ingestion.
- Taint propagation follows data flow through the call graph. A derived field inherits the highest risk tier of its sources.
- Sending any field with taint tier `HIGH` to an external communication tool is an automatic `BLOCK` before the semantic check runs.

### Model Inference (GuardFormer)

- Model weights load once at startup. Never reload per request.
- Inference runs in a dedicated thread pool via `asyncio.to_thread()`.
- The model does not receive raw user PII. Strip identifying fields before inference if the policy tier is `REDACT`.
- Model output is a probability vector. The ALLOW / HUMAN_APPROVAL_REQUIRED / BLOCK thresholds live in `settings.py`, not in the inference function.

### Fail-Closed Default

```python
DEFAULT_FAIL_MODE = Verdict.BLOCK  # per-tier, in settings.py

TOOL_FAIL_MODES: dict[str, Verdict] = {
    "read_secret": Verdict.BLOCK,
    "send_email": Verdict.BLOCK,
    "execute_shell": Verdict.BLOCK,
    "read_file": Verdict.ALLOW,   # read-only, low-impact
}
```

---

## 7. File Structure

```
secureSG/
    guard/
        proxy.py           # FastAPI proxy server
        interceptor.py     # JSON-RPC capture and dispatch
        enforcer.py        # Policy verdict engine
        taint.py           # Field-level taint tracking
        trajectory.py      # Session-level sequence analysis
    warden/
        discovery.py       # MCP tool schema risk analysis
        scope.py           # Denylist generation
        intent.py          # Intent-to-action drift detector
        embeddings.py      # Embedding cache and similarity
    audit/
        chain.py           # Hash chain implementation
        logger.py          # Append-only audit log writer
        verifier.py        # Chain integrity checker
    models/
        guardformer.py     # Qwen3-0.8B q4_K_M inference wrapper
        loader.py          # One-time model loader on startup
    schemas/
        tool_call.py       # Pydantic schemas for JSON-RPC
        verdict.py         # Pydantic schemas for policy verdicts
        audit.py           # Pydantic schemas for log entries
    policies/
        default.yaml
        high_risk_tools.yaml
    config/
        settings.py        # All config via Pydantic BaseSettings
    dashboard/
        api.py             # FastAPI routes
        ws.py              # WebSocket live feed
    exceptions.py
    main.py
tests/
    unit/
    integration/
    e2e/
config/
    .env.example
CLAUDE.md
README.md
```

---

## 8. Testing Requirements

Tests are not optional. Every PR maintains or improves coverage.

### Unit Tests

- Every public function in `guard/`, `warden/`, and `audit/` has a unit test.
- Hash chain tests cover: correct chain, single tampered entry, tampered first entry, tampered last entry.
- Taint propagation tests cover: clean data, single tainted field, multi-hop propagation, cross-tool taint.

### Integration Tests

- Full proxy intercept cycle: inject a call, verify verdict, verify audit entry, verify chain integrity.
- Trajectory test: simulate `read_secret` then `send_email` in one session, verify BLOCK.

### E2E Demo Scenario (must pass as a test)

1. Agent scrapes a page containing a prompt injection payload.
2. Guard detects and blocks the injection.
3. Agent reads a secret via `read_secret`.
4. Agent attempts to exfiltrate via `send_email` with the secret in the body.
5. Taint tracking triggers `BLOCK` before model inference.
6. A past log entry is tampered in SQLite.
7. The chain verifier returns `CHAIN_BROKEN` with the index of the first invalid link.

This runs as a pytest fixture, not a manual demo step.

### Test Tooling

```
pytest
pytest-asyncio
pytest-cov
hypothesis  # property-based tests for hash chain and taint propagation
```

Coverage threshold: 85% minimum, enforced in CI.

---

## 9. Development Workflow

### Before Writing Any Code

1. Read the relevant spec section.
2. State assumptions and a brief verifiable plan (Section 3).
3. Write the function signature and docstring first, with complexity annotation.
4. Write the test before the implementation.
5. Implement, then run tests locally before committing.

### Commit Discipline

- One logical change per commit.
- Format: `[component] verb: short description`
  - `[guard] feat: add field-level taint propagation for HIGH risk tools`
  - `[audit] fix: atomic chain tail update in SQLite transaction`
- Never commit a broken test. Never commit with a `# TODO` in a critical path.
- No AI attribution trailers (Section 4).

### What Claude Code Should Not Do

- Do not create helper utilities and leave them unused.
- Do not add dependencies without updating `requirements.txt` and documenting the reason in the commit.
- Do not generate placeholder data or mock responses inside production paths.
- Do not add `print()` for debugging. Use the structured logger.

---

## 10. Environment Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/.env.example .env

pytest --cov=secureSG --cov-fail-under=85
python -m secureSG.main
```

Qwen3-0.8B q4_K_M weights load from the `MODEL_PATH` env var. They are never committed.

---

## 11. Dashboard Spec Summary

Four panels, served via the FastAPI dashboard routes:

1. **Alert Feed**: real-time injection alerts with report generation on flag.
2. **Monthly Summary**: counts of BLOCK / HUMAN_APPROVAL_REQUIRED / ALLOW verdicts, grouped by attack category.
3. **Safe Content Registry**: list of verified-clean content after redaction, showing sanitized output.
4. **LLM Status Bar**: WebSocket feed showing model state and live token stream of scraped content being processed.

---

## These Guidelines Are Working If

Diffs contain fewer unnecessary changes, fewer rewrites happen due to overcomplication, and clarifying questions arrive before implementation rather than after mistakes.