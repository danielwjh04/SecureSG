# Guard Capability-Policy Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four capability-policy holes in PR #24 so a no-URL agent action that reads a secret, runs a dangerous shell construct, writes a config file via the shell, or escapes the workspace can never return a silent ALLOW.

**Architecture:** Harden the deterministic policy in `secureai/src/guard/actionPolicy.ts` only. `safe_shell` becomes a narrow allowlist (no shell metacharacters + safelisted executable); command arguments and structured paths are scanned against sensitive-path markers (secrets escalate on any access, config paths escalate only on a write); and absolute paths outside the workspace root escalate. New marker entries are config (`wrangler.jsonc` + `env.ts`), not literals in source.

**Tech Stack:** TypeScript (strict, `noUncheckedIndexedAccess`) on Cloudflare Workers, Vitest (Node environment, `loadConfig({...})` fixtures), `oxlint`.

This is subsystem 1 of 6 (see `docs/superpowers/plans/README` roadmap in the PR description). It is independently mergeable: it changes only the policy module and its config defaults and ships with full tests.

## Global Constraints

- TDD: no production code without a failing test first. Watch each test fail for the right reason before implementing.
- No hardcoding: behavioral tunables (which paths are sensitive, which are config) live in `wrangler.jsonc` vars read through `loadConfig` in `secureai/src/config/env.ts`. Shell-grammar constants (the metacharacter set) are structural module constants with a `// reason:` style comment, consistent with the existing `TOOL_INPUT_PATH_FIELDS`.
- Fail closed: on uncertainty the verdict escalates (ALLOW -> HUMAN_APPROVAL_REQUIRED). Over-escalation is acceptable; a missed dangerous action is not.
- No em-dashes anywhere (code, comments, docs). Use commas, parentheses, or separate sentences.
- No `console.*` in `secureai/src/**`. Typed errors only (none needed here; policy returns findings, never throws on input).
- Max function length 50 lines, max file 200 lines (user-global rule). `actionPolicy.ts` is already 547 lines and over the limit; this plan does NOT add to the bloat and Task 6 extracts the command-content logic into a focused `secureai/src/guard/commandRisk.ts` so the net change keeps functions under 50 lines. A full file split is deferred to subsystem 6 (cleanup).
- Coverage thresholds stay green: lines/functions/statements 85, branches 80.
- Run from `secureai/`: `npx vitest run src/guard/actionPolicy.test.ts` for one file, `npm run test:run` for the suite, `npm run typecheck`, `npm run lint`.

---

## File Structure

- `secureai/src/config/env.ts` (modify): extend the default `SCANNER_GUARD_SENSITIVE_PATH_MARKERS` to include common absolute system secret paths; no signature change.
- `secureai/wrangler.jsonc` (modify): mirror the new default markers in the `SCANNER_GUARD_SENSITIVE_PATH_MARKERS` var (or add it if absent) with an explanatory comment.
- `secureai/src/guard/commandRisk.ts` (create): pure helpers `hasShellMetacharacters`, `tokenizeCommand`, `commandWritesToConfigPath`, `commandTouchesSensitivePath`. One responsibility (shell-command risk inspection), keeps `actionPolicy.ts` functions small.
- `secureai/src/guard/commandRisk.test.ts` (create): unit tests for the helpers.
- `secureai/src/guard/actionPolicy.ts` (modify): tighten `classifyCommand` (metacharacter guard), add a workspace-boundary check and a command-content scan in `evaluateGuardActionPolicy`, route both through the existing `record(...)` fold.
- `secureai/src/guard/actionPolicy.test.ts` (modify): add regression tests for each fixed hole; keep the existing five tests passing.

**Interfaces produced (used by later tasks in this plan):**
- `hasShellMetacharacters(command: string): boolean`
- `tokenizeCommand(command: string): string[]` (splits on whitespace, `|`, `;`, `&`)
- `commandWritesToConfigPath(command: string, configMarkers: ReadonlySet<string>): boolean`
- `commandTouchesSensitivePath(command: string, sensitiveMarkers: ReadonlySet<string>): boolean`
- New rule id: `guard.path_outside_workspace` (severity `HUMAN_APPROVAL_REQUIRED`).

---

## Task 1: Sensitive-path read via a safe shell command escalates (the BLOCKER)

**Files:**
- Test: `secureai/src/guard/actionPolicy.test.ts`
- Create: `secureai/src/guard/commandRisk.ts`
- Test: `secureai/src/guard/commandRisk.test.ts`
- Modify: `secureai/src/guard/actionPolicy.ts`

**Interfaces:**
- Produces: `commandTouchesSensitivePath(command, sensitiveMarkers)`.
- Consumes: `loadConfig`, `evaluateGuardActionPolicy`, `normalizeGuardAction` (existing).

- [ ] **Step 1: Write the failing test** (append to `actionPolicy.test.ts`)

```typescript
it('requires review for a secret file read via a safe shell reader (no URL)', () => {
  const action = normalizeGuardAction(
    payload('Bash', { command: 'cat ~/.ssh/id_rsa' }),
    config,
  )
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  expect(policy.findings).toContainEqual(
    expect.objectContaining({ ruleId: 'guard.sensitive_path_access' }),
  )
})

it('keeps a benign safe shell read as ALLOW', () => {
  const action = normalizeGuardAction(payload('Bash', { command: 'cat README.md' }), config)
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('ALLOW')
  expect(policy.findings).toEqual([])
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/guard/actionPolicy.test.ts -t "secret file read via a safe shell reader"`
Expected: FAIL, verdict is `ALLOW` (the current bug), expected `HUMAN_APPROVAL_REQUIRED`.

- [ ] **Step 3: Create `commandRisk.ts` with the sensitive-path scan**

```typescript
/**
 * Shell-command risk inspection for the guard capability policy. These helpers
 * read the RAW command text (not the executable-normalized tokens) so a secret
 * path passed as an argument is still seen, and decide write intent from shell
 * redirection so a config-file read is not over-flagged.
 */

/** Normalize a command for marker matching: backslashes to slashes, lowercased. */
function normalizeCommand(command: string): string {
  return command.replaceAll('\\', '/').toLowerCase()
}

/**
 * True when the raw command references any sensitive-path marker (a secret file
 * or directory), whether read or written. Reading a secret is itself the risk.
 *
 * Time complexity: O(m) in marker count. Space complexity: O(1).
 */
export function commandTouchesSensitivePath(
  command: string,
  sensitiveMarkers: ReadonlySet<string>,
): boolean {
  const normalized = normalizeCommand(command)
  for (const marker of sensitiveMarkers) {
    if (normalized.includes(marker)) {
      return true
    }
  }
  return false
}
```

- [ ] **Step 4: Wire it into `evaluateGuardActionPolicy`** (in `actionPolicy.ts`, inside the `if (action.commandStructure !== null)` block, before `recordCommandFinding`)

```typescript
  if (action.commandStructure !== null) {
    if (commandTouchesSensitivePath(action.commandStructure.command, config.guardSensitivePathMarkers)) {
      record({
        ruleId: 'guard.sensitive_path_access',
        severity: REVIEW,
        detail: `shell command accesses a sensitive path: ${action.commandStructure.command}`,
      })
    }
    recordCommandFinding(action.commandStructure, record)
  }
```

Add the import at the top of `actionPolicy.ts`:

```typescript
import { commandTouchesSensitivePath } from './commandRisk'
```

- [ ] **Step 5: Run both tests to verify pass**

Run: `npx vitest run src/guard/actionPolicy.test.ts`
Expected: PASS, including the existing five tests and the new benign-read ALLOW case.

- [ ] **Step 6: Commit**

```bash
git add secureai/src/guard/commandRisk.ts secureai/src/guard/actionPolicy.ts secureai/src/guard/actionPolicy.test.ts
git commit -m "[guard] fix: flag secret-path access in shell command arguments"
```

---

## Task 2: Shell metacharacters and substitution defeat the safe_shell short-circuit

**Files:**
- Test: `secureai/src/guard/commandRisk.test.ts`
- Modify: `secureai/src/guard/commandRisk.ts`, `secureai/src/guard/actionPolicy.ts`
- Test: `secureai/src/guard/actionPolicy.test.ts`

**Interfaces:**
- Produces: `hasShellMetacharacters(command)`, `tokenizeCommand(command)`.

- [ ] **Step 1: Write the failing tests** (`commandRisk.test.ts`, new file)

```typescript
import { describe, expect, it } from 'vitest'
import { hasShellMetacharacters, tokenizeCommand } from './commandRisk'

describe('hasShellMetacharacters', () => {
  it('detects command substitution, chaining, and redirection', () => {
    for (const cmd of ['echo $(chmod 777 /etc)', 'echo x&&rm -rf /', 'echo `id`', 'echo x > f', 'a || b', 'a | b']) {
      expect(hasShellMetacharacters(cmd)).toBe(true)
    }
  })
  it('treats a single simple command as metacharacter-free', () => {
    expect(hasShellMetacharacters('cat README.md')).toBe(false)
  })
})

describe('tokenizeCommand', () => {
  it('splits on whitespace and the separators space, pipe, semicolon, ampersand', () => {
    expect(tokenizeCommand('echo x&&rm -rf /')).toContain('rm')
  })
})
```

And the policy-level regressions (`actionPolicy.test.ts`):

```typescript
it('does not allow a destructive command hidden behind substitution', () => {
  const action = normalizeGuardAction(payload('Bash', { command: 'echo $(chmod -R 777 /etc)' }), config)
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
})

it('catches a destructive command chained without spaces', () => {
  const action = normalizeGuardAction(payload('Bash', { command: 'echo ok&&rm -rf /' }), config)
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
})
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/guard/commandRisk.test.ts src/guard/actionPolicy.test.ts -t "substitution"`
Expected: FAIL (`hasShellMetacharacters`/`tokenizeCommand` not exported; substitution case returns ALLOW today).

- [ ] **Step 3: Add the helpers to `commandRisk.ts`**

```typescript
/** Shell control and expansion characters that make a command non-simple. */
const SHELL_METACHARACTERS = ['&&', '||', '|', ';', '&', '$(', '${', '`', '>', '<']

/**
 * True when the command contains any shell control or expansion construct, so it
 * cannot be treated as a single safe command and must escalate to review.
 *
 * Time complexity: O(k) in metacharacter count. Space complexity: O(1).
 */
export function hasShellMetacharacters(command: string): boolean {
  return SHELL_METACHARACTERS.some((meta) => command.includes(meta))
}

/** Split a command into words on whitespace, pipe, semicolon, and ampersand. */
export function tokenizeCommand(command: string): string[] {
  return command.split(/[\s|;&]+/).filter((word) => word.length > 0)
}
```

- [ ] **Step 4: Tighten `classifyCommand` and widen `isShellSeparator`** in `actionPolicy.ts`

Pass the raw command into the safe-shell decision and reject metacharacters:

```typescript
function classifyCommand(
  command: string,
  words: readonly string[],
  config: GuardPolicyConfig,
): GuardCommandClass {
  if (hasCommand(words, config.guardDestructiveCommands)) {
    return 'destructive_file_change'
  }
  if (hasCommand(words, config.guardPermissionCommands)) {
    return 'permission_change'
  }
  if (hasPackageInstall(words, config)) {
    return 'package_install'
  }
  if (hasPackageScriptExecution(words, config)) {
    return 'package_script_execution'
  }
  const first = firstExecutableWord(words)
  if (!hasShellMetacharacters(command) && first !== null && config.guardSafeShellCommands.has(first)) {
    return 'safe_shell'
  }
  return 'unknown_shell'
}
```

Update `buildCommandStructure` to pass `command` to `classifyCommand`, and add `&` to `isShellSeparator` so chained verbs tokenize:

```typescript
function isShellSeparator(char: string): boolean {
  return (
    char === ' ' || char === '\t' || char === '\n' || char === '\r' ||
    char === '|' || char === ';' || char === '&'
  )
}
```

Add the import:

```typescript
import { commandTouchesSensitivePath, hasShellMetacharacters } from './commandRisk'
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/guard/commandRisk.test.ts src/guard/actionPolicy.test.ts`
Expected: PASS (all old and new cases).

- [ ] **Step 6: Commit**

```bash
git add secureai/src/guard/commandRisk.ts secureai/src/guard/commandRisk.test.ts secureai/src/guard/actionPolicy.ts secureai/src/guard/actionPolicy.test.ts
git commit -m "[guard] fix: deny safe_shell shortcut for compound or substituted commands"
```

---

## Task 3: System secret paths and out-of-workspace reads escalate

**Files:**
- Modify: `secureai/src/config/env.ts`, `secureai/wrangler.jsonc`, `secureai/src/guard/actionPolicy.ts`
- Test: `secureai/src/guard/actionPolicy.test.ts`, `secureai/src/config/env.test.ts`

**Interfaces:**
- Produces: rule id `guard.path_outside_workspace`.

- [ ] **Step 1: Write the failing tests** (`actionPolicy.test.ts`)

```typescript
it('requires review for a read of a system secret file', () => {
  const action = normalizeGuardAction(payload('Read', { file_path: '/etc/shadow' }), config)
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
})

it('requires review for an absolute read outside the workspace root', () => {
  const action = normalizeGuardAction(
    payload('Read', { file_path: '/var/secrets/key', cwd: '/home/me/project' }),
    config,
  )
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  expect(policy.findings).toContainEqual(
    expect.objectContaining({ ruleId: 'guard.path_outside_workspace' }),
  )
})
```

And in `env.test.ts`:

```typescript
it('includes system secret paths in the default sensitive markers', () => {
  const markers = loadConfig({}).guardSensitivePathMarkers
  expect(markers.has('/etc/shadow')).toBe(true)
  expect(markers.has('/etc/passwd')).toBe(true)
})
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/guard/actionPolicy.test.ts src/config/env.test.ts -t "system secret"`
Expected: FAIL (markers lack `/etc/shadow`; no workspace check).

- [ ] **Step 3: Extend the default markers** in `env.ts` (the `guardSensitivePathMarkers` default string)

```typescript
  const guardSensitivePathMarkers = readSet(
    env,
    'SCANNER_GUARD_SENSITIVE_PATH_MARKERS',
    '.env,.dev.vars,.npmrc,.pypirc,.netrc,.ssh/id_rsa,.ssh/id_ed25519,.aws/credentials,.config/gcloud,credentials,secret,secrets,token,kube/config,/etc/shadow,/etc/passwd,/etc/sudoers,/etc/ssh,/root/,/proc/self/environ',
  )
```

Mirror the same value in `secureai/wrangler.jsonc` under a `SCANNER_GUARD_SENSITIVE_PATH_MARKERS` var with a comment that it is the secret-path denylist for the guard policy.

- [ ] **Step 4: Add the workspace-boundary check** in `evaluateGuardActionPolicy` (inside the existing `for (const path of action.targetPaths)` loop)

```typescript
    if (isAbsolutePathOutsideWorkspace(path, action.workspaceRoot)) {
      record({
        ruleId: 'guard.path_outside_workspace',
        severity: REVIEW,
        detail: `tool call targets a path outside the workspace: ${path}`,
      })
    }
```

Add the helper near `matchesMarker`:

```typescript
/**
 * True when an absolute path is not contained within a known workspace root.
 * When no workspace root is known the check is skipped (returns false) to avoid
 * flagging every cwd-less call; system secret paths are still caught by the
 * sensitive-path markers, so this is a defense-in-depth layer, not the only one.
 */
function isAbsolutePathOutsideWorkspace(path: string, workspaceRoot: string | null): boolean {
  if (workspaceRoot === null) {
    return false
  }
  const normalized = path.replaceAll('\\', '/')
  const isAbsolute = normalized.startsWith('/') || normalized.startsWith('~') || /^[a-z]:\//i.test(normalized)
  if (!isAbsolute) {
    return false
  }
  const root = workspaceRoot.replaceAll('\\', '/').replace(/\/+$/, '')
  return normalized !== root && !normalized.startsWith(`${root}/`)
}
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/guard/actionPolicy.test.ts src/config/env.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add secureai/src/config/env.ts secureai/wrangler.jsonc secureai/src/guard/actionPolicy.ts secureai/src/guard/actionPolicy.test.ts secureai/src/config/env.test.ts
git commit -m "[guard] fix: escalate system-secret and out-of-workspace path access"
```

---

## Task 4: Config writes performed through the shell escalate

**Files:**
- Modify: `secureai/src/guard/commandRisk.ts`, `secureai/src/guard/actionPolicy.ts`
- Test: `secureai/src/guard/commandRisk.test.ts`, `secureai/src/guard/actionPolicy.test.ts`

**Interfaces:**
- Produces: `commandWritesToConfigPath(command, configMarkers)`.

- [ ] **Step 1: Write the failing tests**

`commandRisk.test.ts`:

```typescript
import { commandWritesToConfigPath } from './commandRisk'

describe('commandWritesToConfigPath', () => {
  const markers = new Set(['.claude', 'package.json'])
  it('flags a redirect into a config path', () => {
    expect(commandWritesToConfigPath('echo x >> .claude/settings.json', markers)).toBe(true)
  })
  it('does not flag a plain read of a config path', () => {
    expect(commandWritesToConfigPath('cat package.json', markers)).toBe(false)
  })
})
```

`actionPolicy.test.ts`:

```typescript
it('requires review for a config write performed through the shell', () => {
  const action = normalizeGuardAction(
    payload('Bash', { command: 'echo bad >> .claude/settings.json' }),
    config,
  )
  const policy = evaluateGuardActionPolicy(action, config)
  expect(policy.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  expect(policy.findings).toContainEqual(
    expect.objectContaining({ ruleId: 'guard.config_change' }),
  )
})
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/guard/commandRisk.test.ts src/guard/actionPolicy.test.ts -t "config"`
Expected: FAIL.

- [ ] **Step 3: Add `commandWritesToConfigPath`** to `commandRisk.ts`

```typescript
/** Redirection or copy operators that indicate the command writes a file. */
const WRITE_OPERATORS = ['>', '>>', 'tee ']

/**
 * True when the command writes (via redirection or tee) to a config-path marker.
 * A plain read of a config file is not flagged.
 *
 * Time complexity: O(m) in marker count. Space complexity: O(1).
 */
export function commandWritesToConfigPath(
  command: string,
  configMarkers: ReadonlySet<string>,
): boolean {
  const normalized = normalizeCommand(command)
  const writes = WRITE_OPERATORS.some((op) => normalized.includes(op))
  if (!writes) {
    return false
  }
  for (const marker of configMarkers) {
    if (normalized.includes(marker)) {
      return true
    }
  }
  return false
}
```

- [ ] **Step 4: Wire it in** (`actionPolicy.ts`, in the `commandStructure` block from Task 1)

```typescript
    if (commandWritesToConfigPath(action.commandStructure.command, config.guardConfigPathMarkers)) {
      record({
        ruleId: 'guard.config_change',
        severity: REVIEW,
        detail: `shell command writes a configuration path: ${action.commandStructure.command}`,
      })
    }
```

Extend the import to `import { commandTouchesSensitivePath, commandWritesToConfigPath, hasShellMetacharacters } from './commandRisk'`.

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run src/guard/commandRisk.test.ts src/guard/actionPolicy.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add secureai/src/guard/commandRisk.ts secureai/src/guard/commandRisk.test.ts secureai/src/guard/actionPolicy.ts secureai/src/guard/actionPolicy.test.ts
git commit -m "[guard] fix: flag config-file writes performed through the shell"
```

---

## Task 5: Full-suite gate (regression + coverage + lint + types)

**Files:** none new; verification only.

- [ ] **Step 1: Run the whole suite**

Run: `npm run test:run`
Expected: PASS, including the PR's pre-existing guard, route, and cache tests (no regression from the policy change).

- [ ] **Step 2: Type-check and lint**

Run: `npm run typecheck` then `npm run lint`
Expected: both clean, zero errors.

- [ ] **Step 3: Coverage**

Run: `npm run coverage`
Expected: lines/functions/statements >= 85, branches >= 80. `commandRisk.ts` is fully covered by `commandRisk.test.ts`.

- [ ] **Step 4: Confirm no em-dashes were introduced**

Run: `git diff main...HEAD -- secureai/ | grep -nP "[\x{2013}\x{2014}]" || echo "clean"`
Expected: `clean`.

- [ ] **Step 5: Commit any coverage-driven test additions, then stop for review**

```bash
git add -A
git commit -m "[guard] test: cover commandRisk edge cases to threshold"
```

---

## Self-Review

- Spec coverage: BLOCKER (secret read via shell) -> Task 1; HIGH shell-parser bypass -> Task 2; HIGH system path + workspace boundary -> Task 3; HIGH config-write-via-shell -> Task 4. All four findings have a task.
- Placeholder scan: every step has concrete code or an exact command. No TODO/TBD.
- Type consistency: `commandTouchesSensitivePath`, `commandWritesToConfigPath`, `hasShellMetacharacters`, `tokenizeCommand` are defined in Task 1/2/4 with the same signatures used by `actionPolicy.ts`. `isAbsolutePathOutsideWorkspace` is local to `actionPolicy.ts`. Rule id `guard.path_outside_workspace` is introduced once (Task 3).
- Resolved design choice: the workspace-boundary check is skipped when `workspaceRoot` is null (no `cwd`), to avoid flagging every cwd-less call; system secret paths are still caught by the markers. The `/var/secrets/key` test supplies `cwd`, so it exercises the boundary path.
