$ErrorActionPreference = 'Stop'

$ApiUrl = if ($env:SECUREAI_API_URL) { $env:SECUREAI_API_URL } else { 'https://secureai.software' }
$SecureAiDir = if ($env:SECUREAI_DIR) { $env:SECUREAI_DIR } else { Join-Path $HOME '.secureai' }
$ConfigPath = if ($env:SECUREAI_CONFIG_PATH) { $env:SECUREAI_CONFIG_PATH } else { Join-Path $SecureAiDir 'config.json' }

$ClaudeGuardUrl = if ($env:SECUREAI_CLAUDE_GUARD_URL) { $env:SECUREAI_CLAUDE_GUARD_URL } else { "$ApiUrl/secureai-guard.mjs" }
$CursorGuardUrl = if ($env:SECUREAI_CURSOR_GUARD_URL) { $env:SECUREAI_CURSOR_GUARD_URL } else { 'https://raw.githubusercontent.com/danielwjh04/SecureAI/main/integrations/cursor/secureai-guard.mjs' }
$CodexGuardUrl = if ($env:SECUREAI_CODEX_GUARD_URL) { $env:SECUREAI_CODEX_GUARD_URL } else { 'https://raw.githubusercontent.com/danielwjh04/SecureAI/main/integrations/codex/secureai-guard.mjs' }

$ClaudeGuardPath = if ($env:SECUREAI_CLAUDE_GUARD_PATH) { $env:SECUREAI_CLAUDE_GUARD_PATH } else { Join-Path $SecureAiDir 'secureai-guard.mjs' }
$CursorGuardPath = if ($env:SECUREAI_CURSOR_GUARD_PATH) { $env:SECUREAI_CURSOR_GUARD_PATH } else { Join-Path $SecureAiDir 'secureai-cursor-guard.mjs' }
$CodexGuardPath = if ($env:SECUREAI_CODEX_GUARD_PATH) { $env:SECUREAI_CODEX_GUARD_PATH } else { Join-Path $SecureAiDir 'secureai-codex-guard.mjs' }

$ClaudeSettingsPath = if ($env:SECUREAI_CLAUDE_SETTINGS_PATH) { $env:SECUREAI_CLAUDE_SETTINGS_PATH } else { Join-Path $HOME '.claude\settings.json' }
$CursorHooksPath = if ($env:SECUREAI_CURSOR_HOOKS_PATH) { $env:SECUREAI_CURSOR_HOOKS_PATH } else { Join-Path $HOME '.cursor\hooks.json' }
$CodexHooksPath = if ($env:SECUREAI_CODEX_HOOKS_PATH) { $env:SECUREAI_CODEX_HOOKS_PATH } else { Join-Path $HOME '.codex\hooks.json' }

$BrowserStoreUrl = if ($env:SECUREAI_BROWSER_STORE_URL) { $env:SECUREAI_BROWSER_STORE_URL } else { '' }
$BrowserPairingUrl = if ($env:SECUREAI_BROWSER_PAIRING_URL) { $env:SECUREAI_BROWSER_PAIRING_URL } else { "$ApiUrl/#browser-pair=" }
$DryRun = $env:SECUREAI_DRY_RUN -eq '1'

function Info([string]$Message) { Write-Host "  $Message" }
function Ok([string]$Message) { Write-Host "[ok] $Message" }
function Fail([string]$Message) { Write-Error "[error] $Message"; exit 1 }

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

function Download-Adapter([string]$Url, [string]$Path, [string]$Label) {
  New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
  if ($DryRun) {
    Set-Content -Path $Path -Value "#!/usr/bin/env node`nprocess.stdout.write('{}')`n" -Encoding UTF8
    Ok "Prepared $Label adapter at $Path (dry run)"
    return
  }
  $tmp = "$Path.tmp"
  try {
    Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing
    Move-Item -Force -Path $tmp -Destination $Path
  } catch {
    Remove-Item -Force -Path $tmp -ErrorAction SilentlyContinue
    Fail "Could not download $Label adapter from $Url."
  }
  Ok "Downloaded $Label adapter to $Path"
}

function Invoke-NodeScript([string]$Script) {
  $Script | node
  if ($LASTEXITCODE -ne 0) {
    Fail 'node helper failed while writing hook config.'
  }
}

function Write-SecureAiConfig([string]$ApiKey) {
  New-Item -ItemType Directory -Path $SecureAiDir -Force | Out-Null
  $env:CONFIG_PATH = $ConfigPath
  $env:SECUREAI_API_KEY = $ApiKey
  $env:SECUREAI_API_URL = $ApiUrl
  Invoke-NodeScript @'
const fs = require('fs')
const path = process.env.CONFIG_PATH
const config = {
  apiUrl: process.env.SECUREAI_API_URL,
  apiKey: process.env.SECUREAI_API_KEY,
}
fs.writeFileSync(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 })
'@
  Ok "Saved config to $ConfigPath"
}

function Wire-Claude([string]$ApiKey) {
  Download-Adapter $ClaudeGuardUrl $ClaudeGuardPath 'Claude Code'
  New-Item -ItemType Directory -Path (Split-Path -Parent $ClaudeSettingsPath) -Force | Out-Null
  $escapedPath = $ClaudeGuardPath.Replace("'", "''")
  $escapedKey = $ApiKey.Replace("'", "''")
  $escapedUrl = $ApiUrl.Replace("'", "''")
  $env:SETTINGS_PATH = $ClaudeSettingsPath
  $env:HOOK_COMMAND = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"`$env:SECUREAI_API_KEY='$escapedKey'; `$env:SECUREAI_API_URL='$escapedUrl'; node '$escapedPath'`""
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
  Download-Adapter $CursorGuardUrl $CursorGuardPath 'Cursor'
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
  Download-Adapter $CodexGuardUrl $CodexGuardPath 'Codex'
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

$agents = Normalize-Agents (Get-AgentSelection)
Write-SecureAiConfig $apiKey

if ($agents -contains 'claude') { Wire-Claude $apiKey }
if ($agents -contains 'cursor') { Wire-Cursor }
if ($agents -contains 'codex') { Wire-Codex }
if ($agents -contains 'browser') { Wire-Browser $apiKey }

Write-Host ''
Write-Host 'SecureAI setup complete.'
Write-Host ''
Info "Selected endpoints: $($agents -join ' ')"
Info "Config: $ConfigPath"
