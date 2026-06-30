$ErrorActionPreference = 'Stop'

$ApiUrl = if ($env:SECUREAI_API_URL) { $env:SECUREAI_API_URL } else { 'https://secureai.software' }
$DefaultReleaseBaseUrl = 'https://github.com/danielwjh04/SecureAI/releases/latest/download'
$ReleaseBaseUrl = if ($env:SECUREAI_RELEASE_BASE_URL) { $env:SECUREAI_RELEASE_BASE_URL } else { $DefaultReleaseBaseUrl }
$ReleaseBaseUrl = $ReleaseBaseUrl.TrimEnd('/')
$ChecksumsUrl = if ($env:SECUREAI_CHECKSUMS_URL) { $env:SECUREAI_CHECKSUMS_URL } else { "$ReleaseBaseUrl/SHA256SUMS.txt" }
$SecureAiDir = if ($env:SECUREAI_DIR) { $env:SECUREAI_DIR } else { Join-Path $HOME '.secureai' }
$ConfigPath = if ($env:SECUREAI_CONFIG_PATH) { $env:SECUREAI_CONFIG_PATH } else { Join-Path $SecureAiDir 'config.json' }
$PrivacyMode = if ($env:SECUREAI_PRIVACY_MODE) { $env:SECUREAI_PRIVACY_MODE } else { 'balanced' }

$ClaudeGuardReleaseName = if ($env:SECUREAI_CLAUDE_GUARD_RELEASE_NAME) { $env:SECUREAI_CLAUDE_GUARD_RELEASE_NAME } else { 'secureai-claude-code-guard.mjs' }
$CursorGuardReleaseName = if ($env:SECUREAI_CURSOR_GUARD_RELEASE_NAME) { $env:SECUREAI_CURSOR_GUARD_RELEASE_NAME } else { 'secureai-cursor-guard.mjs' }
$CodexGuardReleaseName = if ($env:SECUREAI_CODEX_GUARD_RELEASE_NAME) { $env:SECUREAI_CODEX_GUARD_RELEASE_NAME } else { 'secureai-codex-guard.mjs' }

$ClaudeGuardUrl = if ($env:SECUREAI_CLAUDE_GUARD_URL) { $env:SECUREAI_CLAUDE_GUARD_URL } else { "$ReleaseBaseUrl/$ClaudeGuardReleaseName" }
$CursorGuardUrl = if ($env:SECUREAI_CURSOR_GUARD_URL) { $env:SECUREAI_CURSOR_GUARD_URL } else { "$ReleaseBaseUrl/$CursorGuardReleaseName" }
$CodexGuardUrl = if ($env:SECUREAI_CODEX_GUARD_URL) { $env:SECUREAI_CODEX_GUARD_URL } else { "$ReleaseBaseUrl/$CodexGuardReleaseName" }

$ClaudeGuardPath = if ($env:SECUREAI_CLAUDE_GUARD_PATH) { $env:SECUREAI_CLAUDE_GUARD_PATH } else { Join-Path $SecureAiDir 'secureai-guard.mjs' }
$CursorGuardPath = if ($env:SECUREAI_CURSOR_GUARD_PATH) { $env:SECUREAI_CURSOR_GUARD_PATH } else { Join-Path $SecureAiDir 'secureai-cursor-guard.mjs' }
$CodexGuardPath = if ($env:SECUREAI_CODEX_GUARD_PATH) { $env:SECUREAI_CODEX_GUARD_PATH } else { Join-Path $SecureAiDir 'secureai-codex-guard.mjs' }

$ClaudeSettingsPath = if ($env:SECUREAI_CLAUDE_SETTINGS_PATH) { $env:SECUREAI_CLAUDE_SETTINGS_PATH } else { Join-Path $HOME '.claude\settings.json' }
$CursorHooksPath = if ($env:SECUREAI_CURSOR_HOOKS_PATH) { $env:SECUREAI_CURSOR_HOOKS_PATH } else { Join-Path $HOME '.cursor\hooks.json' }
$CodexHooksPath = if ($env:SECUREAI_CODEX_HOOKS_PATH) { $env:SECUREAI_CODEX_HOOKS_PATH } else { Join-Path $HOME '.codex\hooks.json' }

$BrowserStoreUrl = if ($env:SECUREAI_BROWSER_STORE_URL) { $env:SECUREAI_BROWSER_STORE_URL } else { '' }
$BrowserPairingUrl = if ($env:SECUREAI_BROWSER_PAIRING_URL) { $env:SECUREAI_BROWSER_PAIRING_URL } else { "$ApiUrl/#browser-pair=" }
$DryRun = $env:SECUREAI_DRY_RUN -eq '1'
$script:ChecksumManifestContent = $null

function Info([string]$Message) { Write-Host "  $Message" }
function Ok([string]$Message) { Write-Host "[ok] $Message" }
function Fail([string]$Message) { Write-Error "[error] $Message"; exit 1 }

function Get-LocalFilePathFromUrl([string]$Url) {
  try {
    $uri = [System.Uri]$Url
  } catch {
    return $null
  }
  if ($uri.IsFile) {
    return $uri.LocalPath
  }
  return $null
}

function Read-UrlText([string]$Url) {
  $localPath = Get-LocalFilePathFromUrl $Url
  if ($localPath) {
    return Get-Content -Raw -LiteralPath $localPath
  }
  $response = Invoke-WebRequest -Uri $Url -UseBasicParsing
  return [string]$response.Content
}

function Save-UrlToFile([string]$Url, [string]$Path) {
  $localPath = Get-LocalFilePathFromUrl $Url
  if ($localPath) {
    Copy-Item -Force -LiteralPath $localPath -Destination $Path
    return
  }
  Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
}

function Get-ChecksumManifest {
  if ($null -ne $script:ChecksumManifestContent) {
    return $script:ChecksumManifestContent
  }
  try {
    $script:ChecksumManifestContent = Read-UrlText $ChecksumsUrl
  } catch {
    Fail 'Could not download checksum manifest.'
  }
  if (-not $script:ChecksumManifestContent -or $script:ChecksumManifestContent.Trim().Length -eq 0) {
    Fail 'Checksum manifest is empty.'
  }
  return $script:ChecksumManifestContent
}

function Get-ExpectedHash([string]$ReleaseName) {
  $expected = $null
  $manifest = Get-ChecksumManifest
  foreach ($line in ($manifest -split '\r?\n')) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) {
      continue
    }
    $parts = $trimmed -split '\s+'
    if ($parts.Count -ne 2) {
      Fail 'Checksum manifest is malformed.'
    }
    $hash = $parts[0]
    $filename = $parts[1]
    if ($hash -notmatch '^[0-9a-fA-F]{64}$') {
      Fail "Checksum manifest has a malformed hash for $filename."
    }
    if ($filename -eq $ReleaseName) {
      if ($expected) {
        Fail "Checksum manifest has duplicate entries for $ReleaseName."
      }
      $expected = $hash.ToLowerInvariant()
    }
  }
  if (-not $expected) {
    Fail "Checksum manifest has no entry for $ReleaseName."
  }
  return $expected
}

function Get-Sha256File([string]$Path, [string]$Label) {
  try {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  } catch {
    Fail "Could not compute SHA-256 for $Label adapter."
  }
}

function Ensure-Node {
  $node = Get-Command node -ErrorAction SilentlyContinue
  if (-not $node) {
    Fail 'node is required but was not found on PATH. Install Node 18+ and re-run.'
  }
}

function Get-AgentSelection {
  if ($env:SECUREAI_AGENTS) {
    return $env:SECUREAI_AGENTS
  }
  if (-not [Console]::IsInputRedirected -and $env:SECUREAI_NONINTERACTIVE -ne '1') {
    Write-Host 'Select endpoints to protect, comma separated:'
    Write-Host '  1) Claude Code'
    Write-Host '  2) Cursor'
    Write-Host '  3) Codex'
    Write-Host '  4) Browser'
    $answer = Read-Host 'Choice [1]'
    if ($answer) { return $answer }
  }
  return 'claude'
}

function Normalize-Agents([string]$Raw) {
  $selected = New-Object System.Collections.Generic.List[string]
  $tokens = $Raw.ToLowerInvariant().Split(@(',', ';', ' '), [System.StringSplitOptions]::RemoveEmptyEntries)
  foreach ($token in $tokens) {
    switch ($token) {
      'all' {
        $selected.Add('claude')
        $selected.Add('cursor')
        $selected.Add('codex')
        $selected.Add('browser')
      }
      { $_ -in @('1', 'claude', 'claude-code', 'claudecode') } { $selected.Add('claude') }
      { $_ -in @('2', 'cursor') } { $selected.Add('cursor') }
      { $_ -in @('3', 'codex') } { $selected.Add('codex') }
      { $_ -in @('4', 'browser', 'chrome', 'edge') } { $selected.Add('browser') }
    }
  }
  if ($selected.Count -eq 0) { $selected.Add('claude') }
  return $selected | Select-Object -Unique
}

function Download-Adapter([string]$Url, [string]$Path, [string]$Label, [string]$ReleaseName) {
  New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
  if ($DryRun) {
    $adapterContent = "#!/usr/bin/env node`nprocess.stdout.write(" + '"{}"' + ")`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $adapterContent, $utf8NoBom)
    Ok "Prepared $Label adapter at $Path (dry run)"
    return
  }

  $expectedHash = Get-ExpectedHash $ReleaseName
  $tmp = "$Path.tmp.$([guid]::NewGuid().ToString('N'))"
  try {
    Save-UrlToFile $Url $tmp
  } catch {
    Remove-Item -Force -Path $tmp -ErrorAction SilentlyContinue
    Fail "Could not download $Label adapter from $Url."
  }
  $actualHash = Get-Sha256File $tmp $Label
  if ($actualHash -ne $expectedHash) {
    Remove-Item -Force -Path $tmp -ErrorAction SilentlyContinue
    Fail "Checksum mismatch for $Label adapter."
  }
  Ok "Verified $Label adapter checksum"
  try {
    Move-Item -Force -LiteralPath $tmp -Destination $Path
  } catch {
    Remove-Item -Force -Path $tmp -ErrorAction SilentlyContinue
    Fail "Could not install $Label adapter at $Path."
  }
  Ok "Downloaded $Label adapter to $Path"
}

function Invoke-NodeScript([string]$Script) {
  $Script | node
  if ($LASTEXITCODE -ne 0) {
    Fail 'node helper failed while writing hook config.'
  }
}

function Resolve-DeviceId {
  if ($env:SECUREAI_DEVICE_ID) {
    return $env:SECUREAI_DEVICE_ID
  }
  if (Test-Path $ConfigPath) {
    try {
      $raw = Get-Content -Raw -Path $ConfigPath
      if ($raw.Trim().Length -gt 0) {
        $parsed = $raw | ConvertFrom-Json
        if ($parsed.deviceId) {
          return [string]$parsed.deviceId
        }
      }
    } catch {
      Fail 'Existing SecureAI config is malformed JSON.'
    }
  }
  return "dev_$([guid]::NewGuid().ToString())"
}

function Write-SecureAiConfig([string]$ApiKey) {
  New-Item -ItemType Directory -Path $SecureAiDir -Force | Out-Null
  $env:CONFIG_PATH = $ConfigPath
  $env:SECUREAI_API_KEY = $ApiKey
  $env:SECUREAI_API_URL = $ApiUrl
  $env:SECUREAI_DEVICE_ID = $DeviceId
  $env:SECUREAI_PRIVACY_MODE = $PrivacyMode
  Invoke-NodeScript @'
const fs = require('fs')
const path = process.env.CONFIG_PATH
const config = {
  apiUrl: process.env.SECUREAI_API_URL,
  apiKey: process.env.SECUREAI_API_KEY,
  deviceId: process.env.SECUREAI_DEVICE_ID,
  privacyMode: process.env.SECUREAI_PRIVACY_MODE,
}
fs.writeFileSync(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 })
'@
  Ok "Saved config to $ConfigPath"
}

function Register-GuardDevice([string]$AccountApiKey) {
  if ($DryRun) {
    return $AccountApiKey
  }
  $env:API_URL = $ApiUrl
  $env:ACCOUNT_API_KEY = $AccountApiKey
  $env:SECUREAI_DEVICE_ID = $DeviceId
  $env:SELECTED_AGENTS = ($agents -join ',')
  $credential = @'
const os = require('os')

async function main() {
  const apiUrl = process.env.API_URL.replace(/\/+$/, '')
  const response = await fetch(`${apiUrl}/api/guard/devices`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${process.env.ACCOUNT_API_KEY}`,
    },
    body: JSON.stringify({
      deviceId: process.env.SECUREAI_DEVICE_ID,
      name: os.hostname(),
      integration: `installer:${process.env.SELECTED_AGENTS}`,
      scopes: ['guard:decision'],
    }),
  })
  if (!response.ok) {
    throw new Error(`device registration failed with HTTP ${response.status}`)
  }
  const body = await response.json()
  if (!body || typeof body.credential !== 'string' || body.credential.length === 0) {
    throw new Error('device registration returned no credential')
  }
  process.stdout.write(body.credential)
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`)
  process.exit(1)
})
'@ | node
  if ($LASTEXITCODE -ne 0 -or -not $credential) {
    Fail 'Could not register this device with SecureAI.'
  }
  return $credential
}

function Wire-Claude([string]$ApiKey) {
  Download-Adapter $ClaudeGuardUrl $ClaudeGuardPath 'Claude Code' $ClaudeGuardReleaseName
  New-Item -ItemType Directory -Path (Split-Path -Parent $ClaudeSettingsPath) -Force | Out-Null
  $escapedPath = $ClaudeGuardPath.Replace("'", "''")
  $escapedKey = $ApiKey.Replace("'", "''")
  $escapedUrl = $ApiUrl.Replace("'", "''")
  $escapedDeviceId = $DeviceId.Replace("'", "''")
  $escapedPrivacyMode = $PrivacyMode.Replace("'", "''")
  $env:SETTINGS_PATH = $ClaudeSettingsPath
  $env:HOOK_COMMAND = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"`$env:SECUREAI_API_KEY='$escapedKey'; `$env:SECUREAI_API_URL='$escapedUrl'; `$env:SECUREAI_DEVICE_ID='$escapedDeviceId'; `$env:SECUREAI_PRIVACY_MODE='$escapedPrivacyMode'; node '$escapedPath'`""
  $env:GUARD_MARKER = 'secureai-guard.mjs'
  Invoke-NodeScript @'
const fs = require('fs')
const settingsPath = process.env.SETTINGS_PATH
const hookCommand = process.env.HOOK_COMMAND
const marker = process.env.GUARD_MARKER

function readJson(path) {
  try {
    const raw = fs.readFileSync(path, 'utf8')
    return raw.trim().length === 0 ? {} : JSON.parse(raw)
  } catch (error) {
    if (error && error.code === 'ENOENT') return {}
    throw error
  }
}

function isSecureAiGroup(group) {
  return Boolean(group && typeof group === 'object' && Array.isArray(group.hooks) && group.hooks.some((hook) => hook && typeof hook.command === 'string' && hook.command.includes(marker)))
}

const settings = readJson(settingsPath)
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) settings.hooks = {}
if (!Array.isArray(settings.hooks.PreToolUse)) settings.hooks.PreToolUse = []
settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter((group) => !isSecureAiGroup(group))
settings.hooks.PreToolUse.push({ matcher: '*', hooks: [{ type: 'command', command: hookCommand }] })
fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n')
'@
  Ok "Registered Claude Code hook in $ClaudeSettingsPath"
}

function Wire-Cursor {
  Download-Adapter $CursorGuardUrl $CursorGuardPath 'Cursor' $CursorGuardReleaseName
  New-Item -ItemType Directory -Path (Split-Path -Parent $CursorHooksPath) -Force | Out-Null
  $env:HOOKS_PATH = $CursorHooksPath
  $env:HOOK_COMMAND = "node `"$CursorGuardPath`""
  $env:GUARD_MARKER = 'secureai-cursor-guard.mjs'
  Invoke-NodeScript @'
const fs = require('fs')
const hooksPath = process.env.HOOKS_PATH
const hookCommand = process.env.HOOK_COMMAND
const marker = process.env.GUARD_MARKER

function readJson(path) {
  try {
    const raw = fs.readFileSync(path, 'utf8')
    return raw.trim().length === 0 ? {} : JSON.parse(raw)
  } catch (error) {
    if (error && error.code === 'ENOENT') return {}
    throw error
  }
}

function withoutSecureAi(hooks) {
  return hooks.filter((hook) => !(hook && typeof hook.command === 'string' && hook.command.includes(marker)))
}

const settings = readJson(hooksPath)
settings.version = settings.version ?? 1
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) settings.hooks = {}
for (const event of ['beforeShellExecution', 'beforeMCPExecution']) {
  if (!Array.isArray(settings.hooks[event])) settings.hooks[event] = []
  settings.hooks[event] = withoutSecureAi(settings.hooks[event])
  settings.hooks[event].push({ command: hookCommand, timeout: 30, failClosed: true })
}
fs.writeFileSync(hooksPath, JSON.stringify(settings, null, 2) + '\n')
'@
  Ok "Registered Cursor hooks in $CursorHooksPath"
}

function Wire-Codex {
  Download-Adapter $CodexGuardUrl $CodexGuardPath 'Codex' $CodexGuardReleaseName
  New-Item -ItemType Directory -Path (Split-Path -Parent $CodexHooksPath) -Force | Out-Null
  $env:HOOKS_PATH = $CodexHooksPath
  $env:HOOK_COMMAND = "node `"$CodexGuardPath`""
  $env:GUARD_MARKER = 'secureai-codex-guard.mjs'
  Invoke-NodeScript @'
const fs = require('fs')
const hooksPath = process.env.HOOKS_PATH
const hookCommand = process.env.HOOK_COMMAND
const marker = process.env.GUARD_MARKER

function readJson(path) {
  try {
    const raw = fs.readFileSync(path, 'utf8')
    return raw.trim().length === 0 ? {} : JSON.parse(raw)
  } catch (error) {
    if (error && error.code === 'ENOENT') return {}
    throw error
  }
}

function isSecureAiGroup(group) {
  return Boolean(group && typeof group === 'object' && Array.isArray(group.hooks) && group.hooks.some((hook) => hook && typeof hook.command === 'string' && hook.command.includes(marker)))
}

const settings = readJson(hooksPath)
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) settings.hooks = {}
if (!Array.isArray(settings.hooks.PreToolUse)) settings.hooks.PreToolUse = []
settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter((group) => !isSecureAiGroup(group))
settings.hooks.PreToolUse.push({ matcher: '*', hooks: [{ type: 'command', command: hookCommand, timeout: 30, statusMessage: 'Checking SecureAI' }] })
fs.writeFileSync(hooksPath, JSON.stringify(settings, null, 2) + '\n')
'@
  Ok "Registered Codex hook in $CodexHooksPath"
}

function Open-Url([string]$Url) {
  if (-not $Url) { return }
  if ($DryRun) {
    Info "Would open $Url"
    return
  }
  try {
    Start-Process $Url | Out-Null
  } catch {
  }
}

function Wire-Browser([string]$ApiKey) {
  $pairing = "$BrowserPairingUrl$ApiKey"
  if ($BrowserStoreUrl) {
    Open-Url $BrowserStoreUrl
    Info "Browser store page: $BrowserStoreUrl"
  } else {
    Info 'Browser extension store page is not configured yet.'
  }
  Open-Url $pairing
  Info "Pairing link: $pairing"
  Info 'Browser protection scans browser-visible content and blocks risky destinations in this browser.'
  Info 'It cannot see actions an AI provider runs only on its own servers.'
}

Write-Host ''
Write-Host 'SecureAI endpoint installer'
Write-Host ''

Ensure-Node

$apiKey = $env:SECUREAI_API_KEY
if (-not $apiKey) {
  if (-not [Console]::IsInputRedirected) {
    $apiKey = Read-Host 'Paste your SecureAI API key'
  } else {
    Fail 'No API key provided. Set SECUREAI_API_KEY and re-run.'
  }
}
$apiKey = ($apiKey -replace '\s', '')
if (-not $apiKey) { Fail 'An API key is required.' }
$accountApiKey = $apiKey

$DeviceId = Resolve-DeviceId
$agents = Normalize-Agents (Get-AgentSelection)
$guardApiKey = Register-GuardDevice $accountApiKey
Write-SecureAiConfig $guardApiKey

if ($agents -contains 'claude') { Wire-Claude $guardApiKey }
if ($agents -contains 'cursor') { Wire-Cursor }
if ($agents -contains 'codex') { Wire-Codex }
if ($agents -contains 'browser') { Wire-Browser $accountApiKey }

Write-Host ''
Write-Host 'SecureAI setup complete.'
Write-Host ''
Info "Selected endpoints: $($agents -join ' ')"
Info "Config: $ConfigPath"
Info "Device id: $DeviceId"
