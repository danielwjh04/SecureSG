import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'
import { pathToFileURL } from 'node:url'

import { PROJECT_ROOT, RELEASE_ASSETS, createReleaseBundle } from './release-checksums.mjs'

const tempDirs = []
const bashPath = findUsableBash()
const powerShellPath = findUsablePowerShell()
const DEFAULT_RELEASE_BASE_URL = 'https://github.com/danielwjh04/SecureAI/releases/latest/download'

after(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })))
})

async function tempRoot() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secureai-release-'))
  tempDirs.push(dir)
  return dir
}

async function tempWorkspaceRoot() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'installer-test-'))
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

function sha256Text(value) {
  return createHash('sha256').update(value).digest('hex')
}

function shellPath(filePath) {
  const resolved = path.resolve(filePath)
  const relative = path.relative(PROJECT_ROOT, resolved)
  if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) {
    return relative.replace(/\\/g, '/')
  }
  return resolved.replace(/\\/g, '/')
}

function findUsableBash() {
  const candidates = [
    process.env.SECUREAI_TEST_BASH,
    'C:\\Program Files\\Git\\bin\\bash.exe',
    'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
    process.platform === 'win32' ? undefined : 'bash',
  ].filter(Boolean)

  for (const candidate of candidates) {
    const result = spawnSync(
      candidate,
      ['-lc', 'command -v node >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && printf ok'],
      { encoding: 'utf8', timeout: 5000 },
    )
    if (result.status === 0 && result.stdout === 'ok') {
      return candidate
    }
  }
  return null
}

function findUsablePowerShell() {
  const candidates = [
    process.env.SECUREAI_TEST_POWERSHELL,
    'powershell',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  ].filter(Boolean)

  for (const candidate of candidates) {
    const result = spawnSync(
      candidate,
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'Write-Output ok'],
      { encoding: 'utf8', timeout: 5000 },
    )
    if (result.status === 0 && result.stdout.trim() === 'ok') {
      return candidate
    }
  }
  return null
}

function powerShellLiteral(value) {
  return `'${value.replace(/'/g, "''")}'`
}

async function startDeviceRegistrationServer() {
  const requests = []
  const server = createServer((request, response) => {
    const chunks = []
    request.on('data', (chunk) => chunks.push(chunk))
    request.on('end', () => {
      requests.push({
        method: request.method,
        url: request.url,
        body: Buffer.concat(chunks).toString('utf8'),
      })
      if (request.method === 'POST' && request.url === '/api/guard/devices') {
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(JSON.stringify({ credential: 'guard_test_credential' }))
        return
      }
      response.writeHead(404, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ error: 'not found' }))
    })
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return {
    requests,
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  }
}

function installerEnv(root, overrides = {}) {
  const secureAiDir = path.join(root, 'secureai')
  return {
    ...process.env,
    HOME: shellPath(path.join(root, 'home')),
    SECUREAI_AGENTS: 'claude',
    SECUREAI_API_KEY: 'test_account_key',
    SECUREAI_NONINTERACTIVE: '1',
    SECUREAI_DIR: shellPath(secureAiDir),
    SECUREAI_CONFIG_PATH: shellPath(path.join(secureAiDir, 'config.json')),
    SECUREAI_CLAUDE_GUARD_PATH: shellPath(path.join(secureAiDir, 'secureai-guard.mjs')),
    SECUREAI_CLAUDE_SETTINGS_PATH: shellPath(path.join(root, 'hooks', 'claude-settings.json')),
    SECUREAI_CURSOR_HOOKS_PATH: shellPath(path.join(root, 'hooks', 'cursor-hooks.json')),
    SECUREAI_CODEX_HOOKS_PATH: shellPath(path.join(root, 'hooks', 'codex-hooks.json')),
    ...overrides,
  }
}

function powerShellInstallerEnv(root, overrides = {}) {
  const secureAiDir = path.join(root, 'secureai')
  const homeDir = path.join(root, 'home')
  return {
    ...process.env,
    HOME: homeDir,
    USERPROFILE: homeDir,
    SECUREAI_AGENTS: 'claude',
    SECUREAI_API_KEY: 'test_account_key',
    SECUREAI_NONINTERACTIVE: '1',
    SECUREAI_DIR: secureAiDir,
    SECUREAI_CONFIG_PATH: path.join(secureAiDir, 'config.json'),
    SECUREAI_CLAUDE_GUARD_PATH: path.join(secureAiDir, 'secureai-guard.mjs'),
    SECUREAI_CLAUDE_SETTINGS_PATH: path.join(root, 'hooks', 'claude-settings.json'),
    SECUREAI_CURSOR_HOOKS_PATH: path.join(root, 'hooks', 'cursor-hooks.json'),
    SECUREAI_CODEX_HOOKS_PATH: path.join(root, 'hooks', 'codex-hooks.json'),
    ...overrides,
  }
}

async function runBashInstaller(root, overrides = {}) {
  assert.ok(bashPath, 'usable Bash is required for this helper')
  return await new Promise((resolve) => {
    const child = spawn(bashPath, [shellPath(path.join(PROJECT_ROOT, 'scanner/public/install.sh'))], {
      cwd: PROJECT_ROOT,
      env: installerEnv(root, overrides),
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', (error) => {
      resolve({ status: null, stdout, stderr: `${stderr}${error.message}` })
    })
    child.on('close', (status) => {
      resolve({ status, stdout, stderr })
    })
  })
}

async function runPowerShellInstaller(root, overrides = {}) {
  assert.ok(powerShellPath, 'usable PowerShell is required for this helper')
  return await new Promise((resolve) => {
    const child = spawn(
      powerShellPath,
      [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        path.join(PROJECT_ROOT, 'scanner/public/install.ps1'),
      ],
      {
        cwd: PROJECT_ROOT,
        env: powerShellInstallerEnv(root, overrides),
        windowsHide: true,
      },
    )
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, 30000)
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      resolve({ status: null, stdout, stderr: `${stderr}${error.message}` })
    })
    child.on('close', (status) => {
      clearTimeout(timer)
      resolve({
        status,
        stdout,
        stderr: timedOut ? `${stderr}PowerShell installer timed out` : stderr,
      })
    })
  })
}

async function writeInstallerReleaseAsset(root, content, checksumContent) {
  await writeFixture(root, 'release/secureai-claude-code-guard.mjs', content)
  await writeFixture(root, 'release/SHA256SUMS.txt', checksumContent)
  const releaseDir = path.join(root, 'release')
  return {
    releaseBaseUrl: pathToFileURL(releaseDir).href,
    checksumsUrl: pathToFileURL(path.join(releaseDir, 'SHA256SUMS.txt')).href,
    guardUrl: pathToFileURL(path.join(releaseDir, 'secureai-claude-code-guard.mjs')).href,
  }
}

async function writeInstallerReleaseAssets(root, assets) {
  const lines = []
  for (const asset of assets) {
    await writeFixture(root, `release/${asset.name}`, asset.content)
    lines.push(`${sha256Text(asset.content)}  ${asset.name}`)
  }
  await writeFixture(root, 'release/SHA256SUMS.txt', `${lines.join('\n')}\n`)
  return {
    releaseBaseUrl: pathToFileURL(path.join(root, 'release')).href,
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

test('installers default to the published release asset bundle', async () => {
  const [bashInstaller, powerShellInstaller, dashboardConfig] = await Promise.all([
    readFile(path.join(PROJECT_ROOT, 'scanner/public/install.sh'), 'utf8'),
    readFile(path.join(PROJECT_ROOT, 'scanner/public/install.ps1'), 'utf8'),
    readFile(path.join(PROJECT_ROOT, 'scanner/src/config.ts'), 'utf8'),
  ])

  assert.ok(bashInstaller.includes(`DEFAULT_RELEASE_BASE_URL="${DEFAULT_RELEASE_BASE_URL}"`))
  assert.ok(
    bashInstaller.includes(
      'RELEASE_BASE_URL="${SECUREAI_RELEASE_BASE_URL:-${DEFAULT_RELEASE_BASE_URL}}"',
    ),
  )
  assert.doesNotMatch(bashInstaller, /SECUREAI_RELEASE_BASE_URL:-\$\{API_URL\}/)

  assert.ok(powerShellInstaller.includes(`$DefaultReleaseBaseUrl = '${DEFAULT_RELEASE_BASE_URL}'`))
  assert.ok(
    powerShellInstaller.includes(
      '$ReleaseBaseUrl = if ($env:SECUREAI_RELEASE_BASE_URL) { $env:SECUREAI_RELEASE_BASE_URL } else { $DefaultReleaseBaseUrl }',
    ),
  )
  assert.doesNotMatch(powerShellInstaller, /else \{ \$ApiUrl\.TrimEnd\('\/'\) \}/)

  assert.ok(dashboardConfig.includes("'https://secureai.software/install.sh' as const"))
  assert.ok(
    dashboardConfig.includes(
      'return `curl -fsSL ${GUARD_INSTALL_URL} | SECUREAI_API_KEY="${apiKey}" bash`',
    ),
  )
  assert.doesNotMatch(dashboardConfig, /SECUREAI_RELEASE_BASE_URL/)
})

test('Bash installer accepts a valid local checksum manifest and adapter asset', { skip: bashPath ? false : 'usable Bash not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    `${sha256Text(adapterContent)}  secureai-claude-code-guard.mjs\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runBashInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /Verified Claude Code adapter checksum/)
    assert.equal(
      await readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      adapterContent,
    )
    assert.equal(server.requests.length, 1)
  } finally {
    await server.close()
  }
})

test('Bash installer verifies Claude Code, Cursor, and Codex adapter mappings', { skip: bashPath ? false : 'usable Bash not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const assets = [
    {
      name: 'secureai-claude-code-guard.mjs',
      path: path.join(root, 'secureai', 'secureai-guard.mjs'),
      content: '#!/usr/bin/env node\nprocess.stdout.write("claude")\n',
      label: 'Claude Code',
    },
    {
      name: 'secureai-cursor-guard.mjs',
      path: path.join(root, 'secureai', 'secureai-cursor-guard.mjs'),
      content: '#!/usr/bin/env node\nprocess.stdout.write("cursor")\n',
      label: 'Cursor',
    },
    {
      name: 'secureai-codex-guard.mjs',
      path: path.join(root, 'secureai', 'secureai-codex-guard.mjs'),
      content: '#!/usr/bin/env node\nprocess.stdout.write("codex")\n',
      label: 'Codex',
    },
  ]
  const urls = await writeInstallerReleaseAssets(root, assets)
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runBashInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_AGENTS: 'claude,cursor,codex',
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
    })

    assert.equal(result.status, 0, result.stderr)
    for (const asset of assets) {
      assert.match(result.stdout, new RegExp(`Verified ${asset.label} adapter checksum`))
      assert.equal(await readFile(asset.path, 'utf8'), asset.content)
    }
  } finally {
    await server.close()
  }
})

test('Bash installer rejects a tampered adapter file', { skip: bashPath ? false : 'usable Bash not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const expectedContent = '#!/usr/bin/env node\nprocess.stdout.write("expected")\n'
  const tamperedContent = '#!/usr/bin/env node\nprocess.stdout.write("tampered")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    tamperedContent,
    `${sha256Text(expectedContent)}  secureai-claude-code-guard.mjs\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runBashInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_CLAUDE_GUARD_URL: urls.guardUrl,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Checksum mismatch for Claude Code adapter/)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('Bash installer rejects a missing checksum entry', { skip: bashPath ? false : 'usable Bash not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    `${sha256Text('other asset')}  secureai-codex-guard.mjs\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runBashInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_CLAUDE_GUARD_URL: urls.guardUrl,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Checksum manifest has no entry for secureai-claude-code-guard\.mjs/)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('Bash installer dry run does not require network or checksums', { skip: bashPath ? false : 'usable Bash not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const result = await runBashInstaller(root, {
    SECUREAI_API_URL: 'http://127.0.0.1:1',
    SECUREAI_RELEASE_BASE_URL: 'file:///missing-release-base',
    SECUREAI_CHECKSUMS_URL: 'file:///missing-checksums',
    SECUREAI_DRY_RUN: '1',
  })

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /Prepared Claude Code adapter/)
  assert.equal(
    await readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
    '#!/usr/bin/env node\nprocess.stdout.write("{}")\n',
  )
})

test('PowerShell installer parser tokenization succeeds', { skip: powerShellPath ? false : 'usable PowerShell not found' }, () => {
  const scriptPath = path.join(PROJECT_ROOT, 'scanner/public/install.ps1')
  const command = [
    `$content = Get-Content -Raw -LiteralPath ${powerShellLiteral(scriptPath)}`,
    '$errors = $null',
    '[System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null',
    'if ($errors) { $errors | Format-List; exit 1 }',
  ].join('; ')
  const result = spawnSync(
    powerShellPath,
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command],
    { cwd: PROJECT_ROOT, encoding: 'utf8', timeout: 10000 },
  )

  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`)
})

test('PowerShell installer accepts a valid local checksum manifest and adapter asset', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    `${sha256Text(adapterContent)}  secureai-claude-code-guard.mjs\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /Verified Claude Code adapter checksum/)
    assert.equal(
      await readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      adapterContent,
    )
    assert.equal(server.requests.length, 1)
  } finally {
    await server.close()
  }
})

test('PowerShell installer verifies Claude Code, Cursor, and Codex adapter mappings', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const assets = [
    {
      name: 'secureai-claude-code-guard.mjs',
      path: path.join(root, 'secureai', 'secureai-guard.mjs'),
      content: '#!/usr/bin/env node\nprocess.stdout.write("claude")\n',
      label: 'Claude Code',
    },
    {
      name: 'secureai-cursor-guard.mjs',
      path: path.join(root, 'secureai', 'secureai-cursor-guard.mjs'),
      content: '#!/usr/bin/env node\nprocess.stdout.write("cursor")\n',
      label: 'Cursor',
    },
    {
      name: 'secureai-codex-guard.mjs',
      path: path.join(root, 'secureai', 'secureai-codex-guard.mjs'),
      content: '#!/usr/bin/env node\nprocess.stdout.write("codex")\n',
      label: 'Codex',
    },
  ]
  const urls = await writeInstallerReleaseAssets(root, assets)
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_AGENTS: 'claude,cursor,codex',
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
    })

    assert.equal(result.status, 0, result.stderr)
    for (const asset of assets) {
      assert.match(result.stdout, new RegExp(`Verified ${asset.label} adapter checksum`))
      assert.equal(await readFile(asset.path, 'utf8'), asset.content)
    }
  } finally {
    await server.close()
  }
})

test('PowerShell installer rejects malformed existing config JSON before registration', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    `${sha256Text(adapterContent)}  secureai-claude-code-guard.mjs\n`,
  )
  await writeFixture(root, 'secureai/config.json', '{bad json\n')
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Existing SecureAI config is malformed JSON/)
    assert.equal(server.requests.length, 0)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('PowerShell installer rejects a tampered adapter file', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const expectedContent = '#!/usr/bin/env node\nprocess.stdout.write("expected")\n'
  const tamperedContent = '#!/usr/bin/env node\nprocess.stdout.write("tampered")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    tamperedContent,
    `${sha256Text(expectedContent)}  secureai-claude-code-guard.mjs\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_CLAUDE_GUARD_URL: urls.guardUrl,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Checksum mismatch for Claude Code adapter/)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('PowerShell installer rejects a missing checksum entry', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    `${sha256Text('other asset')}  secureai-codex-guard.mjs\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_CLAUDE_GUARD_URL: urls.guardUrl,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Checksum manifest has no entry for secureai-claude-code-guard\.mjs/)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('PowerShell installer rejects malformed checksum manifest lines', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    `${sha256Text(adapterContent)}  secureai-claude-code-guard.mjs extra-field\n`,
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_CLAUDE_GUARD_URL: urls.guardUrl,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Checksum manifest is malformed/)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('PowerShell installer rejects duplicate checksum entries', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const adapterContent = '#!/usr/bin/env node\nprocess.stdout.write("{}")\n'
  const urls = await writeInstallerReleaseAsset(
    root,
    adapterContent,
    [
      `${sha256Text(adapterContent)}  secureai-claude-code-guard.mjs`,
      `${sha256Text(adapterContent)}  secureai-claude-code-guard.mjs`,
    ].join('\n') + '\n',
  )
  const server = await startDeviceRegistrationServer()
  try {
    const result = await runPowerShellInstaller(root, {
      SECUREAI_API_URL: server.url,
      SECUREAI_CLAUDE_GUARD_URL: urls.guardUrl,
      SECUREAI_RELEASE_BASE_URL: urls.releaseBaseUrl,
      SECUREAI_CHECKSUMS_URL: urls.checksumsUrl,
    })

    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Checksum manifest has duplicate entries for secureai-claude-code-guard\.mjs/)
    await assert.rejects(
      readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
      /ENOENT/,
    )
  } finally {
    await server.close()
  }
})

test('PowerShell installer dry run does not require network or checksums', { skip: powerShellPath ? false : 'usable PowerShell not found' }, async () => {
  const root = await tempWorkspaceRoot()
  const result = await runPowerShellInstaller(root, {
    SECUREAI_API_URL: 'http://127.0.0.1:1',
    SECUREAI_RELEASE_BASE_URL: 'file:///missing-release-base',
    SECUREAI_CHECKSUMS_URL: 'file:///missing-checksums',
    SECUREAI_DRY_RUN: '1',
  })

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /Prepared Claude Code adapter/)
  assert.equal(
    await readFile(path.join(root, 'secureai', 'secureai-guard.mjs'), 'utf8'),
    '#!/usr/bin/env node\nprocess.stdout.write("{}")\n',
  )
})
