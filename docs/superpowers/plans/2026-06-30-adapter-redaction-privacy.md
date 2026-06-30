# Adapter Redaction, Privacy, and Content Hashing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the guard adapters so local secrets are actually redacted before any upload, a deterministic `content_hash` is sent, and `maximum` privacy sends metadata plus hash only. Author the logic once and keep the four standalone adapter files in sync.

**Architecture:** A single source-of-truth module `integrations/shared/secureai-redact.mjs` holds the corrected redaction patterns, `redactSecrets`, `computeContentHash`, and a generic `applyPrivacyMode`. Because each adapter is distributed as ONE downloaded file (the installer curls each individually, so an ESM import is not viable), a generation script inlines that module between marker comments into all four adapters, and a check-mode test fails the build on drift. The adapters keep their own provider-specific mapping and emit shape.

**Tech Stack:** Dependency-free Node `.mjs` (uses `node:crypto`), tested with Node's built-in `node:test` runner (NOT vitest). The Worker Vitest suite is unaffected.

This is subsystem 2 of 6. It is independently mergeable: it touches only the adapters, a new shared module, a generation script, their tests, and adapter docs.

## Global Constraints

- TDD: no production code without a failing test first. For each secret type that currently leaks, write a test asserting it is redacted, watch it fail against the current pattern, then fix.
- Fail closed and security-first: redaction must never let a known secret format through. Over-redaction (a false positive) is acceptable; under-redaction (a leak) is a defect.
- Single source of truth: the redaction/hash/privacy logic is authored ONLY in `integrations/shared/secureai-redact.mjs`. The four adapters carry a generated, marker-delimited copy. A drift-check test must fail if any adapter's copy differs from the generated output.
- Single-file distribution preserved: each adapter must remain a self-contained `.mjs` that runs with `node adapter.mjs` and no sibling imports (verify with `node --check`).
- No em-dashes anywhere (code, comments, docs). README must be updated and stay accurate.
- No new runtime dependencies (the adapters are dependency-free; `node:crypto` is built in).
- Tests run with `node --test` from the repo root.

---

## File Structure

- `integrations/shared/secureai-redact.mjs` (create): source of truth. Exports `REDACTED`, `DEFAULT_PRIVACY_MODE`, `PRIVACY_MODES`, `redactSecrets(value)`, `redactString(s)`, `computeContentHash(payload)`, `applyPrivacyMode(payload, mode)`. Pure, no process/env access.
- `integrations/shared/secureai-redact.test.mjs` (create): exhaustive `node:test` unit tests for every secret type and each privacy mode.
- `scripts/sync-adapter-redaction.mjs` (create): inlines the shared module's body (export keywords stripped) between `// SECUREAI-REDACT:BEGIN (generated, do not edit)` and `// SECUREAI-REDACT:END` markers in each adapter. Supports `--check` (exit non-zero on drift) and default `--write`.
- `scripts/sync-adapter-redaction.test.mjs` (create): runs the script in `--check` mode and asserts the four adapters are in sync; asserts `node --check` passes on each adapter.
- `integrations/claude-code/secureai-guard.mjs`, `integrations/codex/secureai-guard.mjs`, `integrations/cursor/secureai-guard.mjs`, `scanner/public/secureai-guard.mjs` (modify): replace the inline redaction block with the marked generated block; compute and attach `content_hash`; use the shared `applyPrivacyMode`.
- `integrations/claude-code/secureai-guard.test.mjs`, `scanner/public/secureai-guard.test.mjs` (create): these adapters currently have NO tests; add redaction/hash/fail-closed tests.
- `integrations/codex/secureai-guard.test.mjs`, `integrations/cursor/secureai-guard.test.mjs` (modify): extend with the new secret types, `content_hash`, and `maximum` mode.
- `README.md`, `integrations/*/README.md` (modify): correct the redaction/privacy/content-hash claims.

**Interfaces produced (used across tasks):**
- `redactSecrets(value: unknown): unknown` (deep: strings via `redactString`, object values whose KEY looks secret to `REDACTED`, recurses arrays/objects)
- `redactString(s: string): string`
- `computeContentHash(payload: { tool_name?, tool_input? }): string` (lowercase hex sha256 over canonical JSON of `{ tool_name, tool_input }` AFTER redaction; deterministic via sorted keys)
- `applyPrivacyMode(payload, mode): object` (always redacts; `maximum` removes `session_id`, `transcript_path`, `cwd`, and `tool_input`, keeping `tool_name`, `content_hash`, `provider`, `device_id`, `integration_version`)

---

## Task 1: Shared redaction module with corrected patterns (security core)

**Files:**
- Create: `integrations/shared/secureai-redact.mjs`
- Test: `integrations/shared/secureai-redact.test.mjs`

**Interfaces:** Produces all four functions above.

- [ ] **Step 1: Write the failing tests** (`secureai-redact.test.mjs`)

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { redactString, redactSecrets, computeContentHash, applyPrivacyMode, REDACTED } from './secureai-redact.mjs'

test('redacts a hyphenated Slack bot token', () => {
  assert.doesNotMatch(redactString('use xoxb-12345678901-abcdefABCDEF as token'), /xoxb-12345678901-abcdefABCDEF/)
})
test('redacts an AWS access key id with no separator', () => {
  assert.doesNotMatch(redactString('AKIAIOSFODNN7EXAMPLE in config'), /AKIAIOSFODNN7EXAMPLE/)
})
test('redacts a PEM private key block', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkq\n-----END RSA PRIVATE KEY-----'
  const out = redactString(pem)
  assert.doesNotMatch(out, /MIIBVAIBADANBgkq/)
})
test('redacts the password in a connection string but keeps scheme and host shape', () => {
  const out = redactString('DATABASE_URL=postgres://user:p4ssw0rd@db.example.com:5432/app')
  assert.doesNotMatch(out, /p4ssw0rd/)
})
test('redacts a JWT', () => {
  assert.doesNotMatch(redactString('auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123'), /eyJzdWIiOiIxIn0/)
})
test('does not over-redact ordinary prose', () => {
  assert.equal(redactString('the quick brown fox jumps over the lazy dog'), 'the quick brown fox jumps over the lazy dog')
})
test('redactSecrets redacts an object value whose key looks secret', () => {
  assert.equal(redactSecrets({ api_key: 'live123', note: 'ok' }).api_key, REDACTED)
})
test('computeContentHash is deterministic and key-order independent', () => {
  const a = computeContentHash({ tool_name: 'Bash', tool_input: { command: 'ls', cwd: '/p' } })
  const b = computeContentHash({ tool_name: 'Bash', tool_input: { cwd: '/p', command: 'ls' } })
  assert.equal(a, b)
  assert.match(a, /^[0-9a-f]{64}$/)
})
test('maximum mode drops content but keeps tool_name and content_hash', () => {
  const out = applyPrivacyMode({ tool_name: 'Bash', tool_input: { command: 'ls' }, content_hash: 'h', session_id: 's', cwd: '/p' }, 'maximum')
  assert.equal(out.tool_input, undefined)
  assert.equal(out.session_id, undefined)
  assert.equal(out.cwd, undefined)
  assert.equal(out.tool_name, 'Bash')
  assert.equal(out.content_hash, 'h')
})
test('balanced mode keeps redacted content and hash', () => {
  const out = applyPrivacyMode({ tool_name: 'Bash', tool_input: { command: 'GITHUB_TOKEN=ghp_abcdefghijklmno ls' }, content_hash: 'h' }, 'balanced')
  assert.doesNotMatch(JSON.stringify(out), /ghp_abcdefghijklmno/)
  assert.equal(out.content_hash, 'h')
})
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test integrations/shared/secureai-redact.test.mjs`
Expected: FAIL (module does not exist yet).

- [ ] **Step 3: Implement `secureai-redact.mjs`**

```js
/**
 * Source of truth for guard-adapter secret redaction, content hashing, and
 * privacy modes. Inlined into each standalone adapter by
 * scripts/sync-adapter-redaction.mjs (the adapters cannot import it because
 * each is distributed as a single downloaded file). Pure: no process or env
 * access. Security rule: never let a known secret format through; over
 * redaction is acceptable, under redaction is a defect.
 */
import { createHash } from 'node:crypto'

export const REDACTED = '[REDACTED]'
export const DEFAULT_PRIVACY_MODE = 'balanced'
export const PRIVACY_MODES = new Set(['maximum', 'balanced', 'investigation'])

const SECRET_KEY_PATTERN = /(token|secret|password|passwd|pwd|credential|authorization|cookie|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)/i
const SECRET_ASSIGNMENT_PATTERN = /\b([A-Za-z_][A-Za-z0-9_-]*(?:token|secret|password|passwd|pwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[A-Za-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;&|]+)/gi
const BEARER_PATTERN = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi
const BASIC_PATTERN = /\b(Basic\s+)[A-Za-z0-9._~+/=-]+/gi
const SLACK_TOKEN_PATTERN = /\bxox[baprs]-[A-Za-z0-9-]{8,}/g
const AWS_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/g
const PREFIX_TOKEN_PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|sk_live|sk_test|sk|pk_live|pk_test|xkeysib|shpat)[_-][A-Za-z0-9_-]{8,}/g
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
const CONNECTION_CRED_PATTERN = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+):([^\s:@/]+)@/gi
const QUERY_SECRET_PATTERN = /([?&][^=]*(?:token|secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[^=]*=)[^&#\s]+/gi

/**
 * Redact likely secrets from a string. Order matters: structured blocks (PEM)
 * and assignments first, then token shapes, then connection credentials and
 * query secrets.
 *
 * Time complexity: O(n) in string length across a fixed pattern set.
 */
export function redactString(value) {
  return value
    .replace(PEM_PRIVATE_KEY_PATTERN, REDACTED)
    .replace(SECRET_ASSIGNMENT_PATTERN, (_m, key) => `${key}=${REDACTED}`)
    .replace(BEARER_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
    .replace(BASIC_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
    .replace(CONNECTION_CRED_PATTERN, (_m, head) => `${head}:${REDACTED}@`)
    .replace(SLACK_TOKEN_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_PATTERN, REDACTED)
    .replace(PREFIX_TOKEN_PATTERN, REDACTED)
    .replace(JWT_PATTERN, REDACTED)
    .replace(QUERY_SECRET_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
}

/** Deep-redact a value: strings, arrays, and objects (secret-named keys fully redacted). */
export function redactSecrets(value) {
  if (typeof value === 'string') {
    return redactString(value)
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item))
  }
  if (value !== null && typeof value === 'object') {
    const output = {}
    for (const [key, item] of Object.entries(value)) {
      output[key] = SECRET_KEY_PATTERN.test(key) ? REDACTED : redactSecrets(item)
    }
    return output
  }
  return value
}

function canonical(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(',')}]`
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
  }
  return JSON.stringify(value === undefined ? null : value)
}

/** Lowercase-hex sha256 over the canonical JSON of the redacted {tool_name, tool_input}. */
export function computeContentHash(payload) {
  const redacted = redactSecrets({ tool_name: payload.tool_name ?? null, tool_input: payload.tool_input ?? null })
  return createHash('sha256').update(canonical(redacted)).digest('hex')
}

/**
 * Redact, then apply the privacy mode. `maximum` sends metadata plus the content
 * hash only (no raw content); `balanced` and `investigation` keep the redacted
 * content. The caller must set `content_hash` before calling so `maximum` still
 * carries it.
 */
export function applyPrivacyMode(payload, mode) {
  const output = redactSecrets(payload)
  if (mode === 'maximum' && output !== null && typeof output === 'object' && !Array.isArray(output)) {
    delete output.session_id
    delete output.transcript_path
    delete output.cwd
    delete output.tool_input
  }
  return output
}
```

- [ ] **Step 4: Run to verify pass**

Run: `node --test integrations/shared/secureai-redact.test.mjs`
Expected: PASS (all secret types redacted, hash deterministic, modes correct).

- [ ] **Step 5: Commit**

```bash
git add integrations/shared/secureai-redact.mjs integrations/shared/secureai-redact.test.mjs
git commit -m "[guard] feat: shared adapter redaction module with corrected secret patterns"
```

---

## Task 2: Generation script and drift check; inline the shared block into all four adapters

**Files:**
- Create: `scripts/sync-adapter-redaction.mjs`, `scripts/sync-adapter-redaction.test.mjs`
- Modify: the four adapter `.mjs` files (replace inline redaction with the marked generated block; remove their now-duplicate constants/functions)

**Interfaces:** Consumes Task 1's module. Produces the marker contract `// SECUREAI-REDACT:BEGIN (generated, do not edit)` ... `// SECUREAI-REDACT:END`.

- [ ] **Step 1: Write the failing test** (`scripts/sync-adapter-redaction.test.mjs`)

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { execFileSync } from 'node:child_process'

test('all adapters are in sync with the shared redaction source', () => {
  // --check exits 0 when in sync, non-zero otherwise.
  execFileSync('node', ['scripts/sync-adapter-redaction.mjs', '--check'], { stdio: 'pipe' })
})

test('every adapter parses as valid JS', () => {
  for (const f of [
    'integrations/claude-code/secureai-guard.mjs',
    'integrations/codex/secureai-guard.mjs',
    'integrations/cursor/secureai-guard.mjs',
    'scanner/public/secureai-guard.mjs',
  ]) {
    execFileSync('node', ['--check', f], { stdio: 'pipe' })
  }
})
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test scripts/sync-adapter-redaction.test.mjs`
Expected: FAIL (script does not exist; adapters not yet markered).

- [ ] **Step 3: Implement the generator** (`scripts/sync-adapter-redaction.mjs`)

```js
/**
 * Inline integrations/shared/secureai-redact.mjs into each standalone adapter
 * between the SECUREAI-REDACT markers, with export keywords and the import
 * line stripped (the adapters cannot import; each is one downloaded file).
 * Usage: node scripts/sync-adapter-redaction.mjs [--check]
 * --check exits non-zero if any adapter is out of sync (for CI), default writes.
 */
import { readFileSync, writeFileSync } from 'node:fs'

const BEGIN = '// SECUREAI-REDACT:BEGIN (generated, do not edit)'
const END = '// SECUREAI-REDACT:END'
const ADAPTERS = [
  'integrations/claude-code/secureai-guard.mjs',
  'integrations/codex/secureai-guard.mjs',
  'integrations/cursor/secureai-guard.mjs',
  'scanner/public/secureai-guard.mjs',
]

function sharedBlock() {
  const src = readFileSync('integrations/shared/secureai-redact.mjs', 'utf8')
  const body = src
    .replace(/^import .*$/gm, "import { createHash } from 'node:crypto'")
    .replace(/^export (const|function) /gm, '$1 ')
  return `${BEGIN}\n${body.trim()}\n${END}`
}

function apply(file, block, check) {
  const text = readFileSync(file, 'utf8')
  const start = text.indexOf(BEGIN)
  const stop = text.indexOf(END)
  if (start === -1 || stop === -1) {
    throw new Error(`missing markers in ${file}`)
  }
  const next = `${text.slice(0, start)}${block}${text.slice(stop + END.length)}`
  if (check) {
    return next === text
  }
  if (next !== text) {
    writeFileSync(file, next)
  }
  return true
}

const check = process.argv.includes('--check')
const block = sharedBlock()
let ok = true
for (const file of ADAPTERS) {
  if (!apply(file, block, check)) {
    ok = false
    process.stderr.write(`out of sync: ${file}\n`)
  }
}
if (check && !ok) {
  process.exit(1)
}
```

- [ ] **Step 4: Add the markers to each adapter and remove the duplicate inline definitions**

In each of the four adapters: replace the existing redaction constants/`redactString`/`redactSecrets`/`applyPrivacyMode` block with the two marker lines (BEGIN/END on adjacent lines), keep the single `import { createHash } ...` only inside the generated block (remove any other copy), and ensure the adapter still references `redactSecrets`/`applyPrivacyMode`/`computeContentHash` (now provided by the inlined block). Then run the generator to fill the block:

```bash
node scripts/sync-adapter-redaction.mjs
```

- [ ] **Step 5: Run to verify pass**

Run: `node --test scripts/sync-adapter-redaction.test.mjs`
Expected: PASS (`--check` clean, every adapter `node --check` valid).
Also run the existing adapter suites to confirm no behavior regressed: `node --test integrations/codex/secureai-guard.test.mjs integrations/cursor/secureai-guard.test.mjs`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/sync-adapter-redaction.mjs scripts/sync-adapter-redaction.test.mjs integrations scanner/public/secureai-guard.mjs
git commit -m "[guard] refactor: generate inlined redaction block into adapters from one source"
```

---

## Task 3: Compute and attach content_hash; tighten privacy; cover all four adapters

**Files:**
- Modify: the four adapters (compute `content_hash` from the normalized payload before `applyPrivacyMode`, attach it, so `maximum` still carries it)
- Create: `integrations/claude-code/secureai-guard.test.mjs`, `scanner/public/secureai-guard.test.mjs`
- Modify: `integrations/codex/secureai-guard.test.mjs`, `integrations/cursor/secureai-guard.test.mjs`

- [ ] **Step 1: Write the failing tests** for each adapter. Codex example (mirror for cursor; for claude-code/scanner-public, drive `main` via a small `runGuard`-style harness if exported, else assert via the generated functions and a spawned process). Add to `integrations/codex/secureai-guard.test.mjs`:

```js
test('attaches a content_hash and redacts new secret formats before upload', async () => {
  const calls = []
  await runCodexGuard(
    JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'aws configure; echo AKIAIOSFODNN7EXAMPLE; export SLACK=xoxb-1-2-abcdefghijkl' } }),
    { env: { SECUREAI_API_KEY: 'sk_secureai_test' }, fetchImpl: async (u, init) => { calls.push({ u, init }); return new Response(JSON.stringify({ decision: 'ask', reason: 'r', verdict: 'BLOCK' }), { status: 200, headers: { 'content-type': 'application/json' } }) } },
  )
  const body = JSON.parse(calls[0].init.body)
  assert.match(body.content_hash, /^[0-9a-f]{64}$/)
  assert.doesNotMatch(calls[0].init.body, /AKIAIOSFODNN7EXAMPLE/)
  assert.doesNotMatch(calls[0].init.body, /xoxb-1-2-abcdefghijkl/)
})

test('maximum privacy sends metadata and hash but not raw content', async () => {
  const calls = []
  await runCodexGuard(
    JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls /secret' } }),
    { env: { SECUREAI_API_KEY: 'sk_secureai_test', SECUREAI_PRIVACY_MODE: 'maximum' }, fetchImpl: async (u, init) => { calls.push({ u, init }); return new Response(JSON.stringify({ decision: 'allow', reason: 'r', verdict: null }), { status: 200, headers: { 'content-type': 'application/json' } }) } },
  )
  const body = JSON.parse(calls[0].init.body)
  assert.equal(body.tool_input, undefined)
  assert.match(body.content_hash, /^[0-9a-f]{64}$/)
  assert.equal(body.tool_name, 'Bash')
})
```

For claude-code and scanner/public (no exported `runGuard` today): the simplest testable path is to spawn the adapter as a child process feeding stdin and a stubbed endpoint is not available, so instead refactor the adapter's core into an exported `runGuard(input, { env, fetchImpl })` mirroring codex (keeps `main` calling it), and test it the same way. This refactor is in scope for this task.

- [ ] **Step 2: Run to verify failure**

Run: `node --test integrations/codex/secureai-guard.test.mjs integrations/cursor/secureai-guard.test.mjs integrations/claude-code/secureai-guard.test.mjs scanner/public/secureai-guard.test.mjs`
Expected: FAIL (no `content_hash` attached; maximum still carries `tool_input`; claude-code/scanner-public not yet testable).

- [ ] **Step 3: Implement** in each adapter: after building the normalized payload and before `applyPrivacyMode`, set `payload.content_hash = computeContentHash(payload)`, then `applyPrivacyMode(payload, privacyMode)`. For claude-code and scanner/public, extract `runGuard(input, { env, fetchImpl })` and export it; `main()` calls it with real `process`/`fetch`. Re-run `node scripts/sync-adapter-redaction.mjs` so the generated block stays in sync.

- [ ] **Step 4: Run to verify pass**

Run: `node --test integrations/codex/secureai-guard.test.mjs integrations/cursor/secureai-guard.test.mjs integrations/claude-code/secureai-guard.test.mjs scanner/public/secureai-guard.test.mjs scripts/sync-adapter-redaction.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add integrations scanner/public/secureai-guard.mjs
git commit -m "[guard] feat: attach content_hash and enforce metadata-only maximum privacy in adapters"
```

---

## Task 4: Correct the documentation

**Files:** Modify `README.md`, `integrations/claude-code/README.md`, `integrations/codex/README.md`, `integrations/cursor/README.md`.

- [ ] **Step 1: Update the redaction/privacy copy** to state accurately: which secret formats are redacted (token-like fields, assignments, bearer/basic, Slack tokens, AWS access keys, PEM private keys, connection-string credentials, JWTs, query-string credentials), that a `content_hash` is computed and sent, and that `maximum` privacy sends metadata and the content hash only (no raw content) while `balanced` and `investigation` send redacted content (investigation differs only in server-side retention). No em-dashes. Keep the language simple.

- [ ] **Step 2: Verify no em-dashes** in the changed docs.

Run: `git diff --staged -U0 -- '*.md' | rg "[\x{2013}\x{2014}]" && echo FOUND || echo CLEAN` (expect CLEAN; use the Grep tool if rg locale errors)

- [ ] **Step 3: Commit**

```bash
git add README.md integrations/claude-code/README.md integrations/codex/README.md integrations/cursor/README.md
git commit -m "[docs] update adapter redaction, privacy, and content-hash description"
```

---

## Task 5: Verification gate

**Files:** none new; verification only.

- [ ] **Step 1: Run every adapter and shared test**

Run: `node --test integrations/shared/secureai-redact.test.mjs integrations/codex/secureai-guard.test.mjs integrations/cursor/secureai-guard.test.mjs integrations/claude-code/secureai-guard.test.mjs scanner/public/secureai-guard.test.mjs scripts/sync-adapter-redaction.test.mjs`
Expected: all pass.

- [ ] **Step 2: Confirm the Worker suite is unaffected and drift check passes**

Run: `node scripts/sync-adapter-redaction.mjs --check` (expect exit 0) then `npm --prefix secureai run test:run` (expect still green; this subsystem does not touch `secureai/src`).

- [ ] **Step 3: Em-dash scan over the subsystem diff**

Use the Grep tool for `[\x{2013}\x{2014}]` across `integrations/`, `scripts/`, `scanner/public/secureai-guard.mjs`, and the changed `*.md`. Expect no matches.

- [ ] **Step 4: Note the scanner/dist copy**

`scanner/dist/secureai-guard.mjs` is a build artifact copy of `scanner/public/secureai-guard.mjs`. Record in the report that it is regenerated by the scanner build (`npm --prefix scanner run build`) and must not be hand-edited; subsystem 3 (installers/release) owns ensuring the served/dist copy matches and is checksummed.

---

## Self-Review

- Spec coverage: broken redaction (Slack/AWS/PEM/connection-string/JWT) -> Task 1 patterns + Task 3 adapter tests; no content hash -> Task 1 `computeContentHash` + Task 3 wiring; maximum-mode leaks content -> Task 1 `applyPrivacyMode` + Task 3 test; 4-way duplication -> Task 2 single source + generator + drift check; doc accuracy -> Task 4.
- Placeholder scan: every step has concrete code or an exact command.
- Type/contract consistency: `redactSecrets`, `redactString`, `computeContentHash`, `applyPrivacyMode`, `REDACTED`, `DEFAULT_PRIVACY_MODE` defined in Task 1 and consumed by the generator (Task 2) and adapters (Task 3). Marker strings identical in the generator and the adapters.
- Decision to confirm at the checkpoint: the generate-and-inline approach (vs an imported shared module that would require the installer to fetch a second file, or vs four hand-kept-identical copies). Chosen to keep single-file distribution and one authored source. The reviewer should confirm the generator's export/import stripping produces valid, in-sync adapters (the `--check` test and `node --check` enforce this).
- Coverage note (carrying the user's directive): these `.mjs` adapters are not in the Vitest coverage surface (that is `secureai/src` only), so they do not affect the 80 percent branch gate; their correctness is enforced by the `node --test` suites instead. The Worker branch-coverage gate is unchanged by this subsystem.
