import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'

import { RELEASE_ASSETS, createReleaseBundle } from './release-checksums.mjs'

const tempDirs = []

after(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })))
})

async function tempRoot() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secureai-release-'))
  tempDirs.push(dir)
  return dir
}

async function writeFixture(root, relativePath, content) {
  const filePath = path.join(root, relativePath)
  await mkdir(path.dirname(filePath), { recursive: true })
  await writeFile(filePath, content)
}

async function writeReleaseFixtures(root) {
  for (const asset of RELEASE_ASSETS) {
    const content = `asset bytes for ${asset.releaseName}\n`
    await writeFixture(root, asset.sourcePath, content)
    if (asset.parityPath) {
      await writeFixture(root, asset.parityPath, content)
    }
  }
}

test('writes stable sorted SHA256SUMS output from copied release files', async () => {
  const root = await tempRoot()
  await writeFixture(root, 'source-b.txt', 'bbb\n')
  await writeFixture(root, 'source-a.txt', 'aaa\n')

  const outputDir = path.join(root, 'release')
  const result = await createReleaseBundle({
    root,
    outputDir,
    assets: [
      { sourcePath: 'source-b.txt', releaseName: 'z-file.txt' },
      { sourcePath: 'source-a.txt', releaseName: 'a-file.txt' },
    ],
  })

  assert.deepEqual(result.files, ['a-file.txt', 'z-file.txt'])
  assert.equal(await readFile(path.join(outputDir, 'a-file.txt'), 'utf8'), 'aaa\n')
  assert.equal(await readFile(path.join(outputDir, 'z-file.txt'), 'utf8'), 'bbb\n')

  const lines = (await readFile(path.join(outputDir, 'SHA256SUMS.txt'), 'utf8'))
    .trimEnd()
    .split('\n')
  assert.match(lines[0], /^[0-9a-f]{64}  a-file\.txt$/)
  assert.match(lines[1], /^[0-9a-f]{64}  z-file\.txt$/)
})

test('rejects stale output files before writing a release bundle', async () => {
  const root = await tempRoot()
  await writeReleaseFixtures(root)
  const outputDir = path.join(root, 'release')
  await mkdir(outputDir, { recursive: true })
  await writeFile(path.join(outputDir, 'old-release.txt'), 'stale\n')

  await assert.rejects(
    createReleaseBundle({ root, outputDir }),
    /stale release output file: old-release\.txt/,
  )
})

test('fails when served scanner dist assets differ from scanner public assets', async () => {
  const paritySources = [
    'scanner/dist/install.sh',
    'scanner/dist/install.ps1',
    'scanner/dist/secureai-guard.mjs',
  ]

  for (const sourcePath of paritySources) {
    const root = await tempRoot()
    await writeReleaseFixtures(root)
    const asset = RELEASE_ASSETS.find((candidate) => candidate.sourcePath === sourcePath)
    assert.ok(asset?.parityPath)
    await writeFixture(root, asset.parityPath, `changed bytes for ${asset.releaseName}\n`)

    await assert.rejects(
      createReleaseBundle({ root, outputDir: path.join(root, 'release') }),
      /does not match/,
    )
  }
})

test('copies the browser guard release asset from scanner dist', async () => {
  const browserGuard = RELEASE_ASSETS.find(
    (asset) => asset.releaseName === 'secureai-browser-guard.mjs',
  )
  assert.equal(browserGuard?.sourcePath, 'scanner/dist/secureai-guard.mjs')
  assert.equal(browserGuard?.parityPath, 'scanner/public/secureai-guard.mjs')

  const root = await tempRoot()
  await writeReleaseFixtures(root)
  const outputDir = path.join(root, 'release')
  await createReleaseBundle({ root, outputDir })

  const copied = await readFile(path.join(outputDir, browserGuard.releaseName), 'utf8')
  const distSource = await readFile(path.join(root, browserGuard.sourcePath), 'utf8')
  assert.equal(copied, distSource)
})
