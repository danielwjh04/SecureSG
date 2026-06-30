#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { copyFile, mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUTPUT_DIR = path.resolve(ROOT, process.argv[2] ?? 'release-assets')
const ASSETS = [
  ['scanner/public/install.sh', 'secureai-install.sh'],
  ['scanner/public/install.ps1', 'secureai-install.ps1'],
  ['scanner/public/secureai-guard.mjs', 'secureai-browser-guard.mjs'],
  ['integrations/claude-code/secureai-guard.mjs', 'secureai-claude-code-guard.mjs'],
  ['integrations/cursor/secureai-guard.mjs', 'secureai-cursor-guard.mjs'],
  ['integrations/codex/secureai-guard.mjs', 'secureai-codex-guard.mjs'],
]

async function sha256Hex(filePath) {
  return createHash('sha256').update(await readFile(filePath)).digest('hex')
}

await mkdir(OUTPUT_DIR, { recursive: true })
for (const [source, target] of ASSETS) {
  await copyFile(path.join(ROOT, source), path.join(OUTPUT_DIR, target))
}

const files = (await readdir(OUTPUT_DIR))
  .filter((file) => file !== 'SHA256SUMS.txt')
  .sort()
const lines = []
for (const file of files) {
  lines.push(`${await sha256Hex(path.join(OUTPUT_DIR, file))}  ${file}`)
}
await writeFile(path.join(OUTPUT_DIR, 'SHA256SUMS.txt'), `${lines.join('\n')}\n`)
process.stdout.write(`Wrote ${path.relative(ROOT, OUTPUT_DIR)} with SHA256SUMS.txt\n`)
