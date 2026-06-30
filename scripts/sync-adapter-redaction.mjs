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
    .replace(/^import .*$/gm, '')
    .replace(/^export \{[^}]*\}.*$/gm, '')
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
