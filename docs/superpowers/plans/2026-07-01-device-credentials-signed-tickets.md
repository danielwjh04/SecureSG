# Device Credentials and Signed Decision Tickets Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing device-scoped guard credentials (issue #9) and signed decision tickets (issue #11) so device identity is authenticated, tickets are a device-only feature bound to the live threat-feed revision, signing keys rotate with an overlap window, the credential lifecycle is safe (unique active credential per device+integration, rotation on re-register, per-account cap, expiry purge), and the full negative-path test matrix the issues mandate exists.

**Architecture:** All changes are server-side in the Cloudflare Worker. The scan pipeline order is unchanged. Decision tickets become an authenticated-device-only fast path: only a `guard_device` caller can be issued or have honored a ticket, and the ticket binds the caller's authenticated device identity plus the live `feed_meta.current_version`. Client-side ticket verification (issue #11 G4) and one-time pairing codes (issue #9 G11) are explicitly OUT OF SCOPE here and tracked as follow-ups.

**Tech Stack:** TypeScript (strict) on Cloudflare Workers, D1 (edge SQLite), KV, Web Crypto (`crypto.subtle`, HS256 + ES256), Zod, Vitest with the Cloudflare Workers pool.

## Global Constraints

- No em-dashes or en-dashes anywhere (code, comments, docs, JSON). Rephrase instead.
- No hardcoding: every threshold, limit, TTL, byte length, and grace window is a `SCANNER_GUARD_*` var in `wrangler.jsonc` read through the typed `ScannerConfig` in `config/env.ts`. Secrets (previous signing key material) go in `.dev.vars.example` and `wrangler secret`, never in `wrangler.jsonc` or source. Protocol identifiers that are not operator-tunable (the `guard:decision` scope string, the credential prefix) live in exactly ONE exported constant, never duplicated.
- Fail-closed: an uncomputable verdict is BLOCK; authentication failure never becomes an anonymous ALLOW; a presented ticket is honored ONLY for an authenticated `guard_device` caller and ONLY when every binding matches, otherwise the request falls through to a full scan.
- SHA-256 only via Web Crypto. Ticket signatures via `crypto.subtle` (HS256 or ES256). Never MD5/SHA-1.
- Zod parse at every inbound boundary; a parse failure is a typed `ParseError`, never an unhandled throw.
- Typed errors from `errors.ts`; never throw a bare `Error`; never an empty `catch`.
- No `console.*` in `secureai/src/**`. Use the structured logger (`log.<level>('<module>', '<static msg>', { errorClass: errorClassOf(error), ...scalarFields })`), scalar fields only, errors by class, never PII/content/secrets. Low-cardinality counters via `metrics.count('<name>', { labels: [...] })`.
- Idempotency: re-registering the same device+integration rotates (revokes the old active credential and issues a new one) and never leaves two active credentials; ticket issue and verify are deterministic.
- Surgical changes only. One logical change per commit. Commit format `[component] verb: short description`. No AI attribution trailers.
- Verification per task: `npm --prefix secureai run test:run`, `npm --prefix secureai run typecheck`, `npm --prefix secureai run lint`. Coverage gate (enforced at the end): lines/functions/statements >= 85, branches >= 80. TDD: write the failing test first, watch it fail, then implement.

---

### Task 1: Make decision tickets an authenticated-device-only feature

Closes G2, G3, G8, G16. Today a presented ticket is honored on any path (including anonymous and `db===null`), the issued/honored ticket carries a client-asserted `device_id` for non-device callers, and there is no explicit device cross-check on redemption (device callers are only protected incidentally by the action-hash). Make tickets a device-only feature: only a `guard_device` caller may have a ticket issued or honored, the bound device identity comes from the authenticated credential, and redemption requires an explicit device match.

**Files:**
- Modify: `secureai/src/routes/guard.ts` (the identity binding around lines 161-168, the ticket-honor block 170-185, and the ticket-issue block 242-251)
- Test: `secureai/src/routes/guard.test.ts`

**Interfaces:**
- Consumes: `GuardAuthContext` from `middleware/guardAuth.ts` (`credentialKind: 'guard_device' | 'account' | 'anonymous'`, `deviceId?`, `integration?`); `parseGuardDecisionTicket`, `verifyGuardDecisionTicket`, `signGuardDecisionTicket` from `guard/decisionTicket.ts` (unchanged signatures).
- Produces: a private helper `bindGuardIdentity(payload, ctx, dbBound)` in `guard.ts` that returns the `PreToolUsePayload` used for ALL binding (action hash, cache key, ticket). For a `guard_device` caller it sets `device_id` and `integration_version` from the credential; for every other caller it DELETES any client-asserted `device_id` and `integration_version`. This replaces the inline ternary at lines 161-168.

- [ ] **Step 1: Write failing tests** in `guard.test.ts`:
  - `honors a valid own-device ticket for a guard_device caller` (scan/compute is skipped; response decision reason is the signed-ticket reason). Use a test seam that makes the caller resolve as `guard_device` with a known `deviceId` and a ticket signed for that device+payload.
  - `does not honor a ticket whose device_id differs from the authenticated device` (a full scan runs instead; assert the decision did NOT come from the ticket).
  - `does not honor a ticket for an account-fallback caller` (set `guardAllowAccountCredentials=true`, caller authenticates as `account`; a presented valid-looking ticket is ignored and a scan runs).
  - `does not honor a ticket on the anonymous / db===null path` (no credential; ticket ignored; scan runs).
  - `does not issue a ticket to a non-device caller` (account-fallback ALLOW response has no `ticket`).
  - `issues a ticket only on an ALLOW for a guard_device caller` (ALLOW -> `ticket` present; a REVIEW/BLOCK -> no `ticket`).
- [ ] **Step 2: Run the tests, watch them fail.**
- [ ] **Step 3: Implement.**
  - Add `bindGuardIdentity`. For `dbBound && ctx.credentialKind === 'guard_device'`: shallow-copy payload, set `device_id = ctx.deviceId`, `integration_version = ctx.integration`, and `provider = payload.provider ?? ctx.integration`. Otherwise: shallow-copy and `delete` `device_id` and `integration_version`. Use it to produce `guardPayload`.
  - Gate the honor block: only run ticket verification when `ctx.credentialKind === 'guard_device'`. Inside, after `verifyGuardDecisionTicket(...).ok && presentedTicket.decision === 'allow'`, also require `presentedTicket.device_id === ctx.deviceId`; only then set `decision`.
  - Gate the issue block (lines 242-251): only sign a ticket when `ctx.credentialKind === 'guard_device'` (in addition to the existing `decision.decision === 'allow' && decision.ticket === undefined && ticketContext !== null`).
- [ ] **Step 4: Run the tests, watch them pass; run the full `guard.test.ts`.**
- [ ] **Step 5: Commit** `[guard] fix: make decision tickets an authenticated-device-only feature`.

---

### Task 2: Require project scope and bind the live threat-feed revision

Closes G6 and G1. A ticket currently collapses to a hardcoded `'project:unknown'` scope when `cwd` is absent (two projects then share a ticket), and binds only the manual `trust_revision`, so a newly ingested bad indicator is masked for the ticket lifetime. Refuse to issue a ticket without a project scope, and fold `feed_meta.current_version` into the effective trust revision used for BOTH the ticket and the decision cache so any feed refresh auto-invalidates them.

**Files:**
- Modify: `secureai/src/guard/decisionTicket.ts` (`unsignedTicket` scope handling; `signGuardDecisionTicket` returns `null` when no scope)
- Modify: `secureai/src/db/feed.ts` (add `currentFeedVersion`)
- Modify: `secureai/src/routes/guard.ts` (compute the effective trust revision once; pass it to the ticket context and to `resolveCachedDecision`)
- Test: `secureai/src/guard/decisionTicket.test.ts`, `secureai/src/db/feed.test.ts` (or the existing feed test file), `secureai/src/routes/guard.test.ts`

**Interfaces:**
- Produces: `currentFeedVersion(db: Database): Promise<string | null>` in `db/feed.ts` (lowercase, `SELECT current_version FROM feed_meta WHERE id = 1`, returns the value as a string or `null` when unset). Consumed by `guard.ts`.
- Changes: `signGuardDecisionTicket` now returns `null` when the payload has no non-empty `cwd` (no scope -> no ticket). `unsignedTicket` no longer references the `'project:unknown'` sentinel; the scope is the required `cwd`.
- `guardTicketContextFromEnv(env, config, now, trustRevision)` gains a `trustRevision` parameter instead of reading `config.guardTrustRevision` internally; `resolveCachedDecision(..., effectiveTrustRevision)` receives the same value.

- [ ] **Step 1: Write failing tests.**
  - `decisionTicket.test.ts`: `signGuardDecisionTicket returns null when cwd is absent`; `a ticket signed with one scope fails to verify against a different scope` (already enforced by signature, add the explicit case); keep the existing happy-path green.
  - feed test: `currentFeedVersion returns the current_version as a string` and `returns null when feed_meta has no row`.
  - `guard.test.ts`: `a ticket stops being honored after the feed version changes` (issue a ticket at feed version A, bump `feed_meta.current_version` to B, present the ticket -> not honored, scan runs); `a cached decision is not reused after the feed version changes`.
- [ ] **Step 2: Run, watch fail.**
- [ ] **Step 3: Implement.**
  - `currentFeedVersion` in `db/feed.ts`.
  - In `decisionTicket.ts`: in `unsignedTicket`, set `scope` from `stringOrNull(payload.cwd)`; in `signGuardDecisionTicket`, return `null` when `stringOrNull(payload.cwd) === null`.
  - In `guard.ts`: after resolving `db`, compute `const feedVersion = config.feedEnabled && db !== null ? await currentFeedVersion(db) : null` and `const effectiveTrustRevision = feedVersion !== null ? config.guardTrustRevision + ':feed:' + feedVersion : config.guardTrustRevision`. Pass `effectiveTrustRevision` to `guardTicketContextFromEnv(env, config, now, effectiveTrustRevision)` and as the `trustRevision` argument of `resolveCachedDecision`.
- [ ] **Step 4: Run, watch pass; run `guard.test.ts` and the feed test file.**
- [ ] **Step 5: Commit** `[guard] fix: require project scope and bind live threat-feed revision into tickets and cache`.

---

### Task 3: Signing-key rotation overlap window and verify-failure metric

Closes G5. `verifiers` is always a single element built from the one current key id, so rotating the signing key silently invalidates every outstanding ticket, and a verification failure emits no signal. Support a previous verifier (verify-only) for an overlap window and emit a low-cardinality metric on every ticket rejection.

**Files:**
- Modify: `secureai/src/config/env.ts` (read previous key id + previous verify key material)
- Modify: `secureai/wrangler.jsonc` (`SCANNER_GUARD_TICKET_KEY_ID_PREVIOUS` var; document the matching previous secrets)
- Modify: `secureai/.dev.vars.example` (`GUARD_TICKET_SECRET_PREVIOUS`, `GUARD_TICKET_PUBLIC_JWK_PREVIOUS`)
- Modify: `secureai/src/routes/guard.ts` (`guardTicketContextFromEnv` builds the verifiers list; emit the reject metric)
- Test: `secureai/src/guard/decisionTicket.test.ts`, `secureai/src/routes/guard.test.ts`

**Interfaces:**
- Consumes: `config.guardTicketKeyId` (current) and new `config.guardTicketKeyIdPrevious: string | null`. The signer is always the current key; verifiers are `[current, ...(previous configured ? [previous] : [])]`. The previous verifier needs only the verify side: for ES256 the previous PUBLIC JWK, for HS256 the previous shared secret. Sign mode (HS256 vs ES256) is whichever the current key uses; the previous verifier must use the same algorithm family.
- Produces: a reject metric `metrics.count('guard.ticket.reject', { labels: [verification.reason] })` (reasons are the fixed set already returned by `verifyGuardDecisionTicket`: `ticket expired`, `policy version mismatch`, `trust revision mismatch`, `ticket key mismatch`, `missing ticket secret`, `action hash mismatch`, `signature mismatch`).

- [ ] **Step 1: Write failing tests.**
  - `decisionTicket.test.ts`: `verifies a ticket signed under the previous key id when a previous verifier is present`; `rejects a ticket whose kid matches no verifier` (reason `ticket key mismatch`); cover both the HS256 and the ES256 previous-key paths (the ES256 previous path verifies with the previous public JWK).
  - `guard.test.ts`: `emits guard.ticket.reject with the reason when a presented ticket fails verification` (inject a metrics seam or assert via the existing metrics test approach).
- [ ] **Step 2: Run, watch fail.**
- [ ] **Step 3: Implement.** Add the previous-key reads to `env.ts` and `ScannerConfig`; build the verifiers list in `guardTicketContextFromEnv`; in the honor block in `guard.ts`, when `!verification.ok`, call the reject metric before falling through.
- [ ] **Step 4: Run, watch pass.**
- [ ] **Step 5: Commit** `[guard] feat: support signing-key rotation overlap and emit ticket-reject metric`.

---

### Task 4: Move the last-seen write off the hot path

Closes G9. `touchGuardDeviceCredential` is awaited inline, unguarded, on every authenticated guard call, adding a serial D1 write to the latency-critical path and turning a transient write failure into a 500. Throttle it (skip when the credential was seen recently) and tolerate its failure, matching the codebase's documented inline-but-cheap pattern (`resilience/circuitBreaker.ts:17-18`).

**Files:**
- Modify: `secureai/src/db/guardDevices.ts` (return `lastSeenAt` from `findGuardDeviceByCredential`)
- Modify: `secureai/src/middleware/guardAuth.ts` (throttle + tolerate the touch)
- Modify: `secureai/src/config/env.ts` and `secureai/wrangler.jsonc` (`SCANNER_GUARD_LAST_SEEN_THROTTLE_S`)
- Test: `secureai/src/middleware/guardAuth.test.ts`, `secureai/src/db/guardDevices.test.ts`

**Interfaces:**
- Changes: `ResolvedGuardDeviceCredential` gains `lastSeenAt: string | null`; `findGuardDeviceByCredential` selects `g.last_seen_at`.
- Consumes: `config.guardLastSeenThrottleSeconds: number` (default 300). `authenticateGuard` writes `last_seen_at` only when `lastSeenAt === null` or `now - lastSeenAt >= throttle`, inside a `try/catch` that logs `log.warn('guardAuth', 'last-seen update failed', { errorClass: errorClassOf(error) })` and continues.

- [ ] **Step 1: Write failing tests.**
  - `guardAuth.test.ts`: `does not write last_seen when the credential was seen within the throttle window`; `writes last_seen when last seen is null or older than the throttle window`; `returns the device context even when the last-seen write throws` (inject a db whose `execute` rejects -> auth still resolves the `guard_device` context).
  - `guardDevices.test.ts`: `findGuardDeviceByCredential returns lastSeenAt`.
- [ ] **Step 2: Run, watch fail.**
- [ ] **Step 3: Implement** the SELECT change, the config var, and the throttled/tolerant touch.
- [ ] **Step 4: Run, watch pass.**
- [ ] **Step 5: Commit** `[guard] fix: throttle and tolerate the device last-seen write off the hot path`.

---

### Task 5: Device lifecycle - one active credential per device+integration, rotation on re-register, per-account cap

Closes G10 (uniqueness + cap) and G12 (rotation). Today re-registering the same device silently creates a second active credential, there is no per-account cap, and there is no rotation path. Add a partial unique index, make registration rotate the prior active credential for the same device+integration, and enforce a configurable active-device cap.

**Files:**
- Create: `secureai/migrations/0013_guard_device_active_unique.sql`
- Modify: `secureai/src/db/guardDevices.ts` (`createGuardDeviceCredential` rotates; add `countActiveGuardDevices`)
- Modify: `secureai/src/routes/guardDevices.ts` (enforce the cap; map the limit error)
- Modify: `secureai/src/errors.ts` (add `GuardDeviceLimitError`)
- Modify: `secureai/src/config/env.ts` and `secureai/wrangler.jsonc` (`SCANNER_GUARD_MAX_DEVICES_PER_ACCOUNT`)
- Test: `secureai/src/db/guardDevices.test.ts`, `secureai/src/routes/guardDevices.test.ts`

**Interfaces:**
- Migration `0013`: `CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_devices_active_unique ON guard_device_credentials (user_id, device_id, integration) WHERE status = 'active';` (partial index: many revoked rows allowed, at most one active per tuple).
- Produces: `countActiveGuardDevices(db, userId): Promise<number>`. `createGuardDeviceCredential` now, in one `db.batch` transaction, runs the revoke of any existing active row for `(user_id, device_id, integration)` THEN the insert, so re-register rotates atomically. A new `GuardDeviceLimitError extends ScannerError` in `errors.ts`.
- Cap: the route counts active devices; if the requested `(device_id, integration)` is NOT already active (a genuinely new device) and the active count is `>= config.guardMaxDevicesPerAccount`, throw `GuardDeviceLimitError`. Re-registering an existing device+integration does not count against the cap (it rotates). Map `GuardDeviceLimitError` to HTTP 429 in `routes/guardDevices.ts` `errorResponse`.

- [ ] **Step 1: Write failing tests.**
  - `guardDevices.test.ts`: `re-registering the same device and integration revokes the prior active credential and leaves exactly one active`; `the same device with a different integration keeps both active`; `revoked rows are preserved across rotation`; `countActiveGuardDevices counts only active rows`.
  - `routes/guardDevices.test.ts`: `rejects registration of a new device when the active cap is reached (429)`; `re-registering an existing device at the cap still succeeds (rotation, not a new device)`.
- [ ] **Step 2: Run, watch fail.**
- [ ] **Step 3: Implement** the migration, `countActiveGuardDevices`, the atomic rotate in `createGuardDeviceCredential`, the error class, the cap check, and the 429 mapping.
- [ ] **Step 4: Run, watch pass.**
- [ ] **Step 5: Commit** `[guard] feat: rotate device credentials on re-register and cap active devices per account`.

---

### Task 6: Purge expired device credentials in the cron

Closes the purge half of G10. Expired credentials accumulate forever. Add a bounded purge to the existing `scheduled()` handler, tolerant of failure so it never breaks the feed refresh.

**Files:**
- Modify: `secureai/src/db/guardDevices.ts` (`purgeExpiredGuardDevices`)
- Modify: `secureai/src/index.ts` (call the purge from `scheduled()` after the feed refresh, inside its own try/catch)
- Modify: `secureai/src/config/env.ts` and `secureai/wrangler.jsonc` (`SCANNER_GUARD_DEVICE_PURGE_GRACE_DAYS`)
- Test: `secureai/src/db/guardDevices.test.ts`, `secureai/src/index.scheduled.test.ts`

**Interfaces:**
- Produces: `purgeExpiredGuardDevices(db, cutoffIso): Promise<number>` -> `DELETE FROM guard_device_credentials WHERE expires_at < ?`, returns rows removed. The route/cron computes `cutoffIso = now - guardDevicePurgeGraceDays` so recently-expired rows stay listable in the dashboard for the grace window.
- `scheduled()` computes the cutoff from `controller.scheduledTime` and `config.guardDevicePurgeGraceDays`, calls the purge in a `try/catch` that logs the error class and continues.

- [ ] **Step 1: Write failing tests.**
  - `guardDevices.test.ts`: `purgeExpiredGuardDevices deletes rows expired before the cutoff and keeps active and recently-expired rows`.
  - `index.scheduled.test.ts`: `the cron purges expired guard credentials past the grace window`; `a purge failure does not fail the scheduled run`.
- [ ] **Step 2: Run, watch fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, watch pass.**
- [ ] **Step 5: Commit** `[guard] feat: purge expired device credentials on the feed cron`.

---

### Task 7: Config-ify the credential byte length, dedup protocol constants, and add a Zod ticket schema

Closes G13 and G15. The credential byte length, prefix, and `guard:decision` scope are inline (the scope literal is duplicated in three places), and the inbound `decision_ticket` is hand-validated instead of Zod-parsed.

**Files:**
- Modify: `secureai/src/config/env.ts` and `secureai/wrangler.jsonc` (`SCANNER_GUARD_DEVICE_CREDENTIAL_BYTES`, default 32, range 16..64)
- Modify: `secureai/src/db/guardDevices.ts` (export `GUARD_DECISION_SCOPE` and `DEVICE_CREDENTIAL_PREFIX` as the single source; take the credential byte length from config)
- Modify: `secureai/src/routes/guardDevices.ts` (use `GUARD_DECISION_SCOPE` for the default scopes; thread the byte length)
- Modify: `secureai/src/schemas/validate.ts` (use `GUARD_DECISION_SCOPE` in the register enum; add `guardDecisionTicketSchema`)
- Modify: `secureai/src/guard/decisionTicket.ts` (`parseGuardDecisionTicket` delegates to `guardDecisionTicketSchema`)
- Test: `secureai/src/guard/decisionTicket.test.ts`, `secureai/src/db/guardDevices.test.ts`

**Interfaces:**
- Produces: `GUARD_DECISION_SCOPE = 'guard:decision' as const` and `DEVICE_CREDENTIAL_PREFIX` exported from `db/guardDevices.ts`; imported by `validate.ts` (`z.enum([GUARD_DECISION_SCOPE])`), `routes/guardDevices.ts`, and any other current user of the literal. `config.guardDeviceCredentialBytes: number` consumed by `createGuardDeviceCredential` (add `credentialBytes` to `CreateGuardDeviceInput` or pass as an explicit argument from the route, which holds `config`).
- `guardDecisionTicketSchema` in `validate.ts` mirrors `GuardDecisionTicket` (alg enum `HS256|ES256`, non-empty `kid`, string `action_hash/scope/policy_version/trust_revision/expires_at/signature`, decision enum, optional non-empty `device_id`/`integration_version`). `parseGuardDecisionTicket(value)` returns `schema.safeParse(value).success ? data : null`, preserving its current `null`-on-miss contract and callers.

- [ ] **Step 1: Write failing tests.**
  - `decisionTicket.test.ts`: `parseGuardDecisionTicket rejects a ticket missing a required field / with a wrong-typed field / with an invalid alg / with an invalid decision` and `accepts a fully valid ticket`.
  - `guardDevices.test.ts`: `the minted credential length reflects the configured byte count` (configure a non-default byte count and assert the raw credential hex length is `prefix + 2 * bytes`).
- [ ] **Step 2: Run, watch fail.**
- [ ] **Step 3: Implement** the config var, the shared constants (remove the duplicate literals), and the Zod-backed parser.
- [ ] **Step 4: Run, watch pass.**
- [ ] **Step 5: Commit** `[guard] refactor: config-ify credential byte length, dedup scope constant, Zod-parse decision tickets`.

---

### Task 8: Negative-path test matrix, coverage gate, and docs

Backfill the mandated tests not already covered by Tasks 1-7, confirm the coverage gate, and update the README. No behavior change.

**Files:**
- Modify: `secureai/src/routes/guard.test.ts`, `secureai/src/middleware/guardAuth.test.ts` (live-route credential matrix)
- Modify: `README.md` (guard device-credential and ticket behavior; no em-dashes)
- Test: the above

**Interfaces:** none new.

- [ ] **Step 1: Add the remaining mandated tests** (any not already written by Tasks 1-7):
  - `a malformed credential under strict auth is rejected (401), not treated as anonymous` (`guardAuth` resolves anonymous for garbage, the route 401s under `guardRequireAuth`).
  - `an expired credential at the live guard route is rejected (401)`.
  - `a missing credential under strict auth is rejected (401)`.
  - `a benign would-be-ALLOW action with a bad credential under strict auth is denied (401), never an anonymous ALLOW`.
  - the ES256 sign-and-verify round trip for tickets (if Task 3 did not already cover it).
  - `a ticket carrying decision 'deny' or 'ask' is never honored as ALLOW`.
- [ ] **Step 2: Run** `npm --prefix secureai run test:run`, `typecheck`, `lint`; then `npm --prefix secureai run coverage` (or the project's coverage script) and confirm lines/functions/statements >= 85 and branches >= 80. If a number is short, add the specific missing-branch test, do not lower the threshold.
- [ ] **Step 3: Update `README.md`** to describe device-only tickets, feed-revision binding, rotation on re-register, the per-account cap, and the expiry purge. No em-dashes. Verify CLAUDE.md and AGENTS.md need no change (no rule changed); if either does, mirror the edit into the other.
- [ ] **Step 4: Confirm the whole gate is green and `git diff --check` is clean.**
- [ ] **Step 5: Commit** `[guard] test: device-credential and ticket negative-path matrix; docs`.
