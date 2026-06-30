#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { copyFile, mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export const DEFAULT_OUTPUT_DIR = 'release-assets'
export const CHECKSUM_FILE = 'SHA256SUMS.txt'
export const RELEASE_ASSETS = Object.freeze([
  Object.freeze({
    sourcePath: 'scanner/dist/install.sh',
    releaseName: 'secureai-install.sh',
    parityPath: 'scanner/public/install.sh',
  }),
  Object.freeze({
    sourcePath: 'scanner/dist/install.ps1',
    releaseName: 'secureai-install.ps1',
    parityPath: 'scanner/public/install.ps1',
  }),
  Object.freeze({
    sourcePath: 'scanner/dist/secureai-guard.mjs',
    releaseName: 'secureai-browser-guard.mjs',
    parityPath: 'scanner/public/secureai-guard.mjs',
  }),
  Object.freeze({
    sourcePath: 'integrations/claude-code/secureai-guard.mjs',
    releaseName: 'secureai-claude-code-guard.mjs',
  }),
  Object.freeze({
    sourcePath: 'integrations/cursor/secureai-guard.mjs',
    releaseName: 'secureai-cursor-guard.mjs',
  }),
  Object.freeze({
    sourcePath: 'integrations/codex/secureai-guard.mjs',
    releaseName: 'secureai-codex-guard.mjs',
  }),
])

export class ReleaseBundleError extends Error {
  constructor(message) {
    super(message)
    this.name = 'ReleaseBundleError'
  }
}

export class StaleOutputError extends ReleaseBundleError {
  constructor(entryName) {
    super(`stale release output file: ${entryName}`)
    this.name = 'StaleOutputError'
  }
}

export class ReleaseAssetParityError extends ReleaseBundleError {
  constructor(sourcePath, parityPath) {
    super(`${sourcePath} does not match ${parityPath}`)
    this.name = 'ReleaseAssetParityError'
  }
}

export async function sha256Hex(filePath) {
  return createHash('sha256').update(await readFile(filePath)).digest('hex')
}

export function validateReleaseAssets(assets) {
  const releaseNames = new Set()
  for (const asset of assets) {
    if (
      path.basename(asset.releaseName) !== asset.releaseName ||
      asset.releaseName.includes('/') ||
      asset.releaseName.includes('\\')
    ) {
      throw new ReleaseBundleError(`release asset name must be flat: ${asset.releaseName}`)
    }
    if (releaseNames.has(asset.releaseName)) {
      throw new ReleaseBundleError(`duplicate release asset name: ${asset.releaseName}`)
    }
    releaseNames.add(asset.releaseName)
  }
  return [...assets]
}

export async function assertNoStaleOutput(outputDir, expectedFiles) {
  let entries
  try {
    entries = await readdir(outputDir, { withFileTypes: true })
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return
    }
    throw error
  }
  for (const entry of entries) {
    if (!entry.isFile() || !expectedFiles.has(entry.name)) {
      throw new StaleOutputError(entry.name)
    }
  }
}

export async function assertAssetParity(root, asset) {
  if (!asset.parityPath) {
    return
  }
  const [sourceBytes, parityBytes] = await Promise.all([
    readFile(path.resolve(root, asset.sourcePath)),
    readFile(path.resolve(root, asset.parityPath)),
  ])
  if (!sourceBytes.equals(parityBytes)) {
    throw new ReleaseAssetParityError(asset.sourcePath, asset.parityPath)
  }
}

export async function checksumLines(outputDir, files) {
  const sortedFiles = [...files].sort()
  const lines = []
  for (const file of sortedFiles) {
    lines.push(`${await sha256Hex(path.join(outputDir, file))}  ${file}`)
  }
  return { files: sortedFiles, lines }
}

export async function createReleaseBundle(options = {}) {
  const root = path.resolve(options.root ?? PROJECT_ROOT)
  const outputDir = path.resolve(root, options.outputDir ?? DEFAULT_OUTPUT_DIR)
  const assets = validateReleaseAssets(options.assets ?? RELEASE_ASSETS)
  const releaseFiles = assets.map((asset) => asset.releaseName)
  const expectedFiles = new Set([...releaseFiles, CHECKSUM_FILE])

  await assertNoStaleOutput(outputDir, expectedFiles)
  await Promise.all(assets.map((asset) => assertAssetParity(root, asset)))
  await mkdir(outputDir, { recursive: true })

  for (const asset of assets) {
    await copyFile(path.resolve(root, asset.sourcePath), path.join(outputDir, asset.releaseName))
  }

  const result = await checksumLines(outputDir, releaseFiles)
  const checksumPath = path.join(outputDir, CHECKSUM_FILE)
  await writeFile(checksumPath, `${result.lines.join('\n')}\n`)
  return { outputDir, checksumPath, files: result.files, lines: result.lines }
}

export async function main(argv = process.argv.slice(2)) {
  const outputDir = argv[0] ?? DEFAULT_OUTPUT_DIR
  const result = await createReleaseBundle({ outputDir })
  process.stdout.write(
    `Wrote ${path.relative(PROJECT_ROOT, result.outputDir)} with ${CHECKSUM_FILE}\n`,
  )
}

function isCliEntry() {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href
}

if (isCliEntry()) {
  main().catch((error) => {
    const name = error instanceof Error ? error.name : 'ReleaseBundleError'
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`${name}: ${message}\n`)
    process.exitCode = 1
  })
}
