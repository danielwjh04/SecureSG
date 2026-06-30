#!/usr/bin/env bash
#
# SecureAI endpoint installer.
#
#   curl -fsSL https://secureai.software/install.sh | bash
#
# Wires SecureAI into selected local AI endpoints. The installer writes
# ~/.secureai/config.json, downloads the selected adapters, and merges hook
# config idempotently. It installs no service, daemon, binary, or local model.

set -euo pipefail

API_URL="${SECUREAI_API_URL:-https://secureai.software}"
SECUREAI_DIR="${SECUREAI_DIR:-${HOME}/.secureai}"
CONFIG_PATH="${SECUREAI_CONFIG_PATH:-${SECUREAI_DIR}/config.json}"
PRIVACY_MODE="${SECUREAI_PRIVACY_MODE:-balanced}"

CLAUDE_GUARD_URL="${SECUREAI_CLAUDE_GUARD_URL:-${API_URL}/secureai-guard.mjs}"
CURSOR_GUARD_URL="${SECUREAI_CURSOR_GUARD_URL:-https://raw.githubusercontent.com/danielwjh04/SecureAI/main/integrations/cursor/secureai-guard.mjs}"
CODEX_GUARD_URL="${SECUREAI_CODEX_GUARD_URL:-https://raw.githubusercontent.com/danielwjh04/SecureAI/main/integrations/codex/secureai-guard.mjs}"

CLAUDE_GUARD_PATH="${SECUREAI_CLAUDE_GUARD_PATH:-${SECUREAI_DIR}/secureai-guard.mjs}"
CURSOR_GUARD_PATH="${SECUREAI_CURSOR_GUARD_PATH:-${SECUREAI_DIR}/secureai-cursor-guard.mjs}"
CODEX_GUARD_PATH="${SECUREAI_CODEX_GUARD_PATH:-${SECUREAI_DIR}/secureai-codex-guard.mjs}"

CLAUDE_SETTINGS_PATH="${SECUREAI_CLAUDE_SETTINGS_PATH:-${HOME}/.claude/settings.json}"
CURSOR_HOOKS_PATH="${SECUREAI_CURSOR_HOOKS_PATH:-${HOME}/.cursor/hooks.json}"
CODEX_HOOKS_PATH="${SECUREAI_CODEX_HOOKS_PATH:-${HOME}/.codex/hooks.json}"

BROWSER_STORE_URL="${SECUREAI_BROWSER_STORE_URL:-}"
BROWSER_PAIRING_URL="${SECUREAI_BROWSER_PAIRING_URL:-${API_URL}/#browser-pair=}"
DRY_RUN="${SECUREAI_DRY_RUN:-0}"

info() { printf '  %s\n' "$1"; }
ok() { printf '[ok] %s\n' "$1"; }
fail() { printf '[error] %s\n' "$1" >&2; exit 1; }

printf '\nSecureAI endpoint installer\n\n'

command -v node >/dev/null 2>&1 || fail "node is required but was not found on PATH. Install Node 18+ and re-run."
if [ "${DRY_RUN}" != "1" ]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required but was not found on PATH."
fi

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --agents)
        shift
        SECUREAI_AGENTS="${1:-}"
        ;;
      --agents=*)
        SECUREAI_AGENTS="${1#--agents=}"
        ;;
      --api-url)
        shift
        API_URL="${1:-}"
        ;;
      --api-url=*)
        API_URL="${1#--api-url=}"
        ;;
      *)
        ;;
    esac
    shift || true
  done
}

terminal_available() {
  [ -r /dev/tty ] && [ -w /dev/tty ]
}

prompt_agents() {
  if [ -n "${SECUREAI_AGENTS:-}" ]; then
    printf '%s\n' "${SECUREAI_AGENTS}"
    return
  fi

  if terminal_available && [ "${SECUREAI_NONINTERACTIVE:-0}" != "1" ]; then
    printf 'Select endpoints to protect, comma separated:\n' >/dev/tty
    printf '  1) Claude Code\n' >/dev/tty
    printf '  2) Cursor\n' >/dev/tty
    printf '  3) Codex\n' >/dev/tty
    printf '  4) Browser\n' >/dev/tty
    printf 'Choice [1]: ' >/dev/tty
    local answer
    read -r answer </dev/tty || answer=""
    printf '%s\n' "${answer:-1}"
    return
  fi

  printf 'claude\n'
}

normalize_agents() {
  local raw
  raw="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr ',;' '  ')"
  local result=""
  local token
  for token in ${raw}; do
    case "${token}" in
      all)
        result="${result} claude cursor codex browser"
        ;;
      1|claude|claude-code|claudecode)
        result="${result} claude"
        ;;
      2|cursor)
        result="${result} cursor"
        ;;
      3|codex)
        result="${result} codex"
        ;;
      4|browser|chrome|edge)
        result="${result} browser"
        ;;
      *)
        ;;
    esac
  done
  if [ -z "${result// /}" ]; then
    result=" claude"
  fi
  printf '%s\n' "${result}"
}

has_agent() {
  local wanted="$1"
  local agent
  for agent in ${SELECTED_AGENTS}; do
    if [ "${agent}" = "${wanted}" ]; then
      return 0
    fi
  done
  return 1
}

download_adapter() {
  local url="$1"
  local path="$2"
  local label="$3"

  mkdir -p "$(dirname "${path}")"
  if [ "${DRY_RUN}" = "1" ]; then
    printf '#!/usr/bin/env node\nprocess.stdout.write("{}")\n' >"${path}"
    ok "Prepared ${label} adapter at ${path} (dry run)"
    return
  fi

  if ! curl -fsSL "${url}" -o "${path}.tmp"; then
    rm -f "${path}.tmp"
    fail "Could not download ${label} adapter from ${url}."
  fi
  mv "${path}.tmp" "${path}"
  chmod 700 "${path}" 2>/dev/null || true
  ok "Downloaded ${label} adapter to ${path}"
}

resolve_device_id() {
  if [ -n "${SECUREAI_DEVICE_ID:-}" ]; then
    printf '%s\n' "${SECUREAI_DEVICE_ID}"
    return
  fi
  if [ -f "${CONFIG_PATH}" ]; then
    local existing
    existing="$(
      CONFIG_PATH="${CONFIG_PATH}" node <<'NODE' 2>/dev/null || true
const fs = require('fs')
const path = process.env.CONFIG_PATH
try {
  const raw = fs.readFileSync(path, 'utf8')
  const parsed = raw.trim().length === 0 ? {} : JSON.parse(raw)
  if (parsed && typeof parsed.deviceId === 'string' && parsed.deviceId.trim().length > 0) {
    process.stdout.write(parsed.deviceId.trim())
  }
} catch {
}
NODE
    )"
    if [ -n "${existing}" ]; then
      printf '%s\n' "${existing}"
      return
    fi
  fi
  node <<'NODE'
const crypto = require('crypto')
process.stdout.write(`dev_${crypto.randomUUID()}`)
NODE
}

write_config() {
  mkdir -p "${SECUREAI_DIR}"
  CONFIG_PATH="${CONFIG_PATH}" \
  SECUREAI_API_KEY="${GUARD_API_KEY}" \
  SECUREAI_API_URL="${API_URL}" \
  SECUREAI_DEVICE_ID="${DEVICE_ID}" \
  SECUREAI_PRIVACY_MODE="${PRIVACY_MODE}" \
  node <<'NODE'
const fs = require('fs')
const path = process.env.CONFIG_PATH
const config = {
  apiUrl: process.env.SECUREAI_API_URL,
  apiKey: process.env.SECUREAI_API_KEY,
  deviceId: process.env.SECUREAI_DEVICE_ID,
  privacyMode: process.env.SECUREAI_PRIVACY_MODE,
}
fs.writeFileSync(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 })
NODE
  chmod 600 "${CONFIG_PATH}" 2>/dev/null || true
  ok "Saved config to ${CONFIG_PATH}"
}

register_guard_device() {
  if [ "${DRY_RUN}" = "1" ]; then
    printf '%s\n' "${API_KEY}"
    return
  fi
  API_URL="${API_URL}" \
  ACCOUNT_API_KEY="${API_KEY}" \
  SECUREAI_DEVICE_ID="${DEVICE_ID}" \
  SELECTED_AGENTS="${SELECTED_AGENTS}" \
  node <<'NODE'
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
      integration: `installer:${process.env.SELECTED_AGENTS.trim().replace(/\s+/g, ',')}`,
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
NODE
}

wire_claude() {
  download_adapter "${CLAUDE_GUARD_URL}" "${CLAUDE_GUARD_PATH}" "Claude Code"
  mkdir -p "$(dirname "${CLAUDE_SETTINGS_PATH}")"
  SETTINGS_PATH="${CLAUDE_SETTINGS_PATH}" \
  HOOK_COMMAND="SECUREAI_API_KEY=${GUARD_API_KEY} SECUREAI_API_URL=${API_URL} SECUREAI_DEVICE_ID=${DEVICE_ID} SECUREAI_PRIVACY_MODE=${PRIVACY_MODE} node \"${CLAUDE_GUARD_PATH}\"" \
  GUARD_MARKER="secureai-guard.mjs" \
  node <<'NODE'
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
  return Boolean(
    group &&
      typeof group === 'object' &&
      Array.isArray(group.hooks) &&
      group.hooks.some((hook) => hook && typeof hook.command === 'string' && hook.command.includes(marker)),
  )
}

const settings = readJson(settingsPath)
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) {
  settings.hooks = {}
}
if (!Array.isArray(settings.hooks.PreToolUse)) {
  settings.hooks.PreToolUse = []
}
settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter((group) => !isSecureAiGroup(group))
settings.hooks.PreToolUse.push({
  matcher: '*',
  hooks: [{ type: 'command', command: hookCommand }],
})
fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n')
NODE
  ok "Registered Claude Code hook in ${CLAUDE_SETTINGS_PATH}"
}

wire_cursor() {
  download_adapter "${CURSOR_GUARD_URL}" "${CURSOR_GUARD_PATH}" "Cursor"
  mkdir -p "$(dirname "${CURSOR_HOOKS_PATH}")"
  HOOKS_PATH="${CURSOR_HOOKS_PATH}" \
  HOOK_COMMAND="node \"${CURSOR_GUARD_PATH}\"" \
  GUARD_MARKER="secureai-cursor-guard.mjs" \
  node <<'NODE'
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
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) {
  settings.hooks = {}
}
for (const event of ['beforeShellExecution', 'beforeMCPExecution']) {
  if (!Array.isArray(settings.hooks[event])) settings.hooks[event] = []
  settings.hooks[event] = withoutSecureAi(settings.hooks[event])
  settings.hooks[event].push({ command: hookCommand, timeout: 30, failClosed: true })
}
fs.writeFileSync(hooksPath, JSON.stringify(settings, null, 2) + '\n')
NODE
  ok "Registered Cursor hooks in ${CURSOR_HOOKS_PATH}"
}

wire_codex() {
  download_adapter "${CODEX_GUARD_URL}" "${CODEX_GUARD_PATH}" "Codex"
  mkdir -p "$(dirname "${CODEX_HOOKS_PATH}")"
  HOOKS_PATH="${CODEX_HOOKS_PATH}" \
  HOOK_COMMAND="node \"${CODEX_GUARD_PATH}\"" \
  GUARD_MARKER="secureai-codex-guard.mjs" \
  node <<'NODE'
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
  return Boolean(
    group &&
      typeof group === 'object' &&
      Array.isArray(group.hooks) &&
      group.hooks.some((hook) => hook && typeof hook.command === 'string' && hook.command.includes(marker)),
  )
}

const settings = readJson(hooksPath)
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) {
  settings.hooks = {}
}
if (!Array.isArray(settings.hooks.PreToolUse)) {
  settings.hooks.PreToolUse = []
}
settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter((group) => !isSecureAiGroup(group))
settings.hooks.PreToolUse.push({
  matcher: '*',
  hooks: [{ type: 'command', command: hookCommand, timeout: 30, statusMessage: 'Checking SecureAI' }],
})
fs.writeFileSync(hooksPath, JSON.stringify(settings, null, 2) + '\n')
NODE
  ok "Registered Codex hook in ${CODEX_HOOKS_PATH}"
}

open_url() {
  local url="$1"
  if [ -z "${url}" ]; then
    return
  fi
  if [ "${DRY_RUN}" = "1" ]; then
    info "Would open ${url}"
    return
  fi
  if command -v open >/dev/null 2>&1; then
    open "${url}" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${url}" >/dev/null 2>&1 || true
  elif command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -Command "Start-Process '${url}'" >/dev/null 2>&1 || true
  fi
}

wire_browser() {
  local pairing="${BROWSER_PAIRING_URL}${ACCOUNT_API_KEY}"
  if [ -n "${BROWSER_STORE_URL}" ]; then
    open_url "${BROWSER_STORE_URL}"
    info "Browser store page: ${BROWSER_STORE_URL}"
  else
    info "Browser extension store page is not configured yet."
  fi
  open_url "${pairing}"
  info "Pairing link: ${pairing}"
  info "Browser protection scans browser-visible content and blocks risky destinations in this browser."
  info "It cannot see actions an AI provider runs only on its own servers."
}

parse_args "$@"
AGENTS_RAW="$(prompt_agents)"
SELECTED_AGENTS="$(normalize_agents "${AGENTS_RAW}")"

API_KEY="${SECUREAI_API_KEY:-}"
if [ -z "${API_KEY}" ]; then
  if terminal_available; then
    printf 'Paste your SecureAI API key: ' >/dev/tty
    read -r API_KEY </dev/tty
  else
    fail "No API key provided. Set SECUREAI_API_KEY and re-run."
  fi
fi
API_KEY="$(printf '%s' "${API_KEY}" | tr -d '[:space:]')"
[ -n "${API_KEY}" ] || fail "An API key is required."
ACCOUNT_API_KEY="${API_KEY}"

DEVICE_ID="$(resolve_device_id)"
if ! GUARD_API_KEY="$(register_guard_device)"; then
  fail "Could not register this device with SecureAI."
fi
write_config

if has_agent claude; then
  wire_claude
fi
if has_agent cursor; then
  wire_cursor
fi
if has_agent codex; then
  wire_codex
fi
if has_agent browser; then
  wire_browser
fi

printf '\nSecureAI setup complete.\n\n'
info "Selected endpoints:${SELECTED_AGENTS}"
info "Config: ${CONFIG_PATH}"
info "Device id: ${DEVICE_ID}"
