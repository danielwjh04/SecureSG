# CLAUDE.md: SecureAI

## What This File Is

Single source of truth for how code is written, reasoned about, and reviewed in this repo. Every session starts here. Read it fully before touching anything.

## Project Identity

**SecureAI** is an antivirus, a "VirusTotal," for AI coding agents. It inspects the skills, tools, and links an agent is about to trust, returns an **ALLOW / REVIEW / BLOCK** verdict in milliseconds, blocks dangerous actions inline and fail-closed, and seals every decision in a tamper-evident cryptographic proof anyone can re-verify.

Two surfaces, one engine:
- **Scanner**: hosted web app plus API. Submit a skill, tool, or link, get a verdict with findings and a proof.
- **Guard**: a single config file the developer drops into their agent (Claude Code first, Cursor next). It routes the agent's actions through SecureAI before they execute. Known-bad destinations or injection payloads are blocked automatically. Fail-closed: if the check cannot run, the action is denied.

The moat is **verifiable enforcement**. Each decision is a SHA-256 hash-chained record. A public `verify` endpoint returns `CHAIN_OK` or `CHAIN_BROKEN`. The line is "Don't trust us, verify."

Stack: TypeScript on Cloudflare Workers, D1 (edge SQLite), Workers AI (small open-weight model for injection detection), Zod for schemas, Stripe for billing. Live at `secureai.zurielst.com`.

Repo: https://github.com/danielwjh04/SecureSG (starts empty, fresh build). Stack is TypeScript on Cloudflare Workers per the proposal.

## Build Context & MVP Targets

SecureAI ships as a product, not a research demo. Weigh every feature against shipping demonstrable, sellable value. The engineering rules below still hold; this section sets what to build toward.

**MVP (about 3 weeks):** public scanner plus Claude Code guard live, free tier open, Stripe wired for Pro at $12/mo. Success is a real agent action blocked live plus the first paying subscriber.

Priorities, in order:
- **Real inline blocking, not advisory.** The Claude Code guard must use PreToolUse hooks to return a real `deny` and fail closed. A flagged-but-allowed action is a failed build.
- **Verifiable proof.** The hash chain and `verify` endpoint are the differentiator. They ship in the MVP, not later.
- **The self-serve wedge.** A developer signs up and is protected in five minutes. Protect that flow above feature breadth.
- **Cost discipline.** Free tier uses no AI: link-tracing, structural rules, and indicator lookups only. AI injection detection runs only when earlier layers are ambiguous, and only for paid usage.

## Codebase Navigation: Graphify First

Read the graphify output before reading source files. It is the generated code-graph of this repo: modules, exported symbols, and call edges. Treat it as the index. Resolve a function, class, or module through the graph, then open only the specific files the task touches. Do not crawl the tree file by file when the graph already answers the question. This saves tokens and keeps context on the task.

If the graphify output is missing or stale, stop and ask the user to regenerate or download it before proceeding. Do not silently fall back to reading the whole repo. Its location is read from config, never hardcoded inline.

## 0. Think Before Coding

Do not assume. Do not hide confusion. Surface tradeoffs.

Before implementing:
- State assumptions explicitly. If uncertain, ask in the session rather than guessing.
- If multiple interpretations exist, present them. Never pick one silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop, name what is confusing, ask.

This rule sits above all others. In a security product, a wrong primitive built confidently is worse than a missing one flagged early.

## 1. Core Engineering Philosophy

Non-negotiable. Every file, every function, every PR.

**No shortcuts, ever.** If there is a correct way and a shortcut that approximates it, take the correct way. This is a security system, so approximations are vulnerabilities. Never stub a validation step with a TODO in a live path. Never use a regex where a real parser is required. Never skip a hash verification because it probably has not changed. Never trust input from any external source without passing it through schema validation.

**Zero placeholders, full completeness.** Deliver the finished product, not a plan. No dangling endpoints, stubbed returns, or "implement later" in a delivered path. Edge cases, docs, and tests ship with the feature. Time pressure is never a reason to compromise depth.

**No hardcoding.** Zero hardcoded values. Every configurable value lives in one of three places:

| Type | Location |
|---|---|
| Runtime config (thresholds, limits, model name, hop caps) | `wrangler.jsonc` vars, read via a typed `Env` |
| Structural and policy rules | `rules/` module, loaded at startup |
| Secrets (Stripe, feed API keys) | Cloudflare secrets and `.dev.vars`, never in code |

If you type a literal like a port, a verdict threshold, a model name, or `"169.254.169.254"` inline, stop. It belongs in config.

**Code dynamically. No static code.** Values are configured, derived, or discovered at runtime, never baked into the source. A magic number, a fixed path, a hardcoded model name, an inline threshold, a pinned URL, or a static list that should be loaded data are all defects. Rules, indicators, and policies load from their source at startup so they change without a code edit. If a value could differ across environments, inputs, or runs, it is config or it is computed. The test: a non-code person can retune behavior by editing config and rule files alone, touching no `.ts`.

**Simplicity first.** Minimum code that solves the problem, nothing speculative. No features beyond what was asked, no abstractions for single-use code, no error handling for impossible cases. If 200 lines could be 50, rewrite it. Would a senior engineer call this overcomplicated? If yes, simplify.

**Explicit over implicit.** No hidden side effects. If a function mutates state, the name and signature make that obvious. Prefer descriptive names over short ambiguous ones. No wildcard re-exports.

**Fail loudly, then fail closed.** Raise a typed error with a clear message instead of returning `null` on failure. Never swallow errors with an empty `catch`. On any I/O or AI-inference error, log the exact error class. High-risk actions are fail-closed: if a verdict cannot be computed, the action is BLOCK.

## 2. Algorithmic Standards

**Correctness before cleverness.** Implement correctly per spec first, document time and space complexity in the doc comment, optimize only if a profile shows a bottleneck. Suboptimal-but-correct beats clever-but-wrong.

**Idempotency.** Scanning, verdict, and audit append must be idempotent. Replaying the same scan request or the same chain append must not corrupt state or double-write the chain.

**Complexity targets.** Runtime operations target O(1) or O(log n). This table is the contract.

| Operation | Target | Notes |
|---|---|---|
| Known-bad indicator lookup | O(1) | hash set or indexed table, never a list scan |
| Structural rule matching | O(1) to O(k) | k = rule count |
| Redirect trace | O(h) bounded | h capped by `MAX_REDIRECT_HOPS`, no unbounded chains |
| Hash chain append | O(1) | append-only, pointer to tail |
| Hash chain verification | O(n) | single forward pass |
| Verdict cache lookup | O(1) | cache repeat scans of identical content |

**Space.** Never buffer a full fetched page in memory. Stream and process in chunks, with a hard byte cap. Audit chain reads are bounded per query window. Keep only the content hash and findings in the proof, never the full payload.

## 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

- Do not improve adjacent code, comments, or formatting.
- Do not refactor what is not broken. Match existing style even where you would do it differently.
- If you notice unrelated dead code, mention it, do not delete it.
- Remove imports or symbols your own change orphaned. Never rename or reformat in the same commit as a logic change.

The test: every changed line traces to the request.

**Git attribution.** Do not add AI attribution to commits. No `Co-authored-by` trailer, no "Generated with" line, no attribution in commit bodies or PR descriptions.

## 4. Code Style

**TypeScript, strict.** `strict: true`, `noUncheckedIndexedAccess: true`. No `any` except where genuinely unavoidable, then with a `// reason:` comment. Prefer `unknown` plus a Zod parse at every boundary.

**Validation at the edge.** Every inbound request body, hook payload, and external response is parsed with a Zod schema before any logic runs. A parse failure is a `BLOCK` verdict, not an unhandled throw.

**Types and docs.** Full type annotations on every exported function. A doc comment on every exported function, class, and module, with a complexity note where non-trivial.

**Async I/O.** All DB, fetch, and AI calls are `async`. Never block the event loop. Put an `AbortSignal` timeout on every outbound fetch.

**Typed errors.** Define error classes in `errors.ts`. Never throw a bare `Error`. Examples: `RedirectGuardError`, `ChainIntegrityError`, `InferenceError`.

## 5. Security-Specific Rules

This is a security product. These rules are stricter than ordinary practice.

**SSRF guard on redirect tracing.** The scanner follows untrusted links, so the tracer is the highest-risk surface. Before every hop: resolve the host, reject loopback, private, link-local, and reserved ranges, reject the cloud metadata address `169.254.169.254`. Re-check after each redirect, never trust the prior hop. Cap hops at `MAX_REDIRECT_HOPS`. The scanner must never be usable to reach internal infrastructure.

**Hash chain integrity.** SHA-256 only, never MD5 or SHA-1, via Web Crypto `crypto.subtle`. `curr_hash = sha256(prev_hash + canonical(payload))`. The tail pointer updates in the same D1 transaction as the log insert, never split. Verification is a single forward pass returning `CHAIN_OK` or `CHAIN_BROKEN` with the index of the first broken link.

**Scan pipeline order.** Cheapest and most certain first, AI last and rarest. Never reorder to call AI before the deterministic layers.
1. Parse content for links and download-and-run patterns (for example `curl | bash`).
2. Trace redirects hop by hop behind the SSRF guard.
3. Deterministic structural rules: raw-IP hosts, punycode and look-alike domains, shorteners, cross-origin hops, excessive chains, embedded execution.
4. Known-bad indicator match against commercially-cleared feeds.
5. AI injection detection, only when earlier layers are ambiguous and only for paid usage.
6. Seal every step into the proof chain and return the verdict.

**AI inference (Workers AI).** Call the model through the `env.AI` binding, never a hardcoded endpoint. On any inference error, raise `InferenceError` so the scan fails closed. Strip identifying fields before inference. Model output is a probability of unsafe content; the ALLOW / REVIEW / BLOCK thresholds live in config, not in the inference function.

**Fail-closed default.** If any required check cannot run, the verdict is BLOCK. High-impact agent actions (shell execution, secret reads, outbound network) default to BLOCK on uncertainty; read-only low-impact actions may default to ALLOW.

## 6. File Structure

```
secureai/
  src/
    scanner/        # pipeline orchestration, verdict assembly
    pipeline/
      parse.ts      # link and exec-pattern extraction
      redirects.ts  # hop-by-hop tracer with SSRF guard
      rules.ts      # deterministic structural rules
      indicators.ts # known-bad feed lookup
      inference.ts  # Workers AI injection detection
    audit/
      chain.ts      # SHA-256 hash chain
      verify.ts     # chain verifier
    guard/          # Claude Code / Cursor hook handlers
    routes/         # scanner API, verify endpoint, billing webhooks
    schemas/        # Zod schemas
    config/         # typed Env, thresholds, rule loading
    errors.ts
    index.ts        # Worker entry
  test/
  wrangler.jsonc
  CLAUDE.md
  README.md
```

## 7. Testing

Tests are not optional. Every PR maintains or improves coverage. Use Vitest with the Cloudflare Workers pool.

- Every exported function in `pipeline/`, `audit/`, and `guard/` has a unit test.
- Hash chain tests cover a correct chain plus a tampered first, middle, and last entry.
- SSRF guard tests cover loopback, private ranges, link-local, the metadata IP, and a redirect that hops from a public host to a private one.

**E2E scan scenario (runs as a test, not a manual demo):**
1. Agent reads content carrying a prompt-injection payload.
2. Pipeline flags it and returns BLOCK.
3. Agent attempts a `curl | bash` install from a look-alike domain.
4. Structural rules return BLOCK before any AI call.
5. A past audit row is tampered in D1.
6. The verifier returns `CHAIN_BROKEN` with the first invalid index.

Coverage threshold: 85% minimum, enforced in CI.

## 8. Development Workflow

Before writing code: read the relevant section, state assumptions and a short verifiable plan, write the signature and doc comment first, write the test before the implementation, then run tests locally before committing.

**Commit discipline.** One logical change per commit. Format `[component] verb: short description`, for example `[redirects] feat: reject metadata IP on every hop`. Never commit a broken test or a TODO in a critical path. No AI attribution trailers.

**Do not:** create helpers and leave them unused, add a dependency without recording the reason in the commit, generate mock data inside production paths, or use `console.log` for debugging in place of the structured logger.

## 9. Environment Setup

```bash
npm install
cp .dev.vars.example .dev.vars   # local secrets, never committed
npx wrangler dev                 # local Worker with D1 and AI bindings
npx vitest run --coverage
```

Set Stripe and feed API keys with `wrangler secret put`. With no AI binding available, the scanner runs deterministic-only: structural rules and indicators, no injection model. Secrets are never committed.

## These Guidelines Are Working If

Diffs carry fewer unnecessary changes, fewer rewrites happen from overcomplication, and clarifying questions arrive before implementation rather than after mistakes.
