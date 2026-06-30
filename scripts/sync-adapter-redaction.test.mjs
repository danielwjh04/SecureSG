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