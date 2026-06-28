#!/usr/bin/env bash
#
# SecureAI Guard — one-line installer.
#
#   curl -fsSL https://secureai.zurielst.com/install.sh | bash
#
# Wires the SecureAI Guard into Claude Code as a PreToolUse hook so every tool
# call is screened (ALLOW / ASK / DENY) before it runs, fail-closed. The script
# is idempotent: re-running it refreshes the guard and replaces the existing
# SecureAI hook entry rather than duplicating it, and preserves every other
# setting in ~/.claude/settings.json.
#
# Requirements: bash, curl, and node (Node 18+; the guard uses global fetch).

set -euo pipefail

API_URL="https://secureai.zurielst.com"
GUARD_URL="${API_URL}/secureai-guard.mjs"
SECUREAI_DIR="${HOME}/.secureai"
GUARD_PATH="${SECUREAI_DIR}/secureai-guard.mjs"
CLAUDE_DIR="${HOME}/.claude"
SETTINGS_PATH="${CLAUDE_DIR}/settings.json"

# A marker the merge step uses to find (and replace) a prior SecureAI hook, so a
# re-run never stacks duplicate entries.
GUARD_MARKER="secureai-guard.mjs"

info()  { printf '  %s\n' "$1"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$1"; }
fail()  { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

printf '\n\033[1mSecureAI Guard installer\033[0m\n\n'

# --- Preflight: required tools -------------------------------------------------
command -v curl >/dev/null 2>&1 || fail "curl is required but was not found on PATH."
command -v node >/dev/null 2>&1 || fail "node is required but was not found on PATH. Install Node 18+ from https://nodejs.org and re-run."

# --- 1. Download the guard hook ------------------------------------------------
mkdir -p "${SECUREAI_DIR}"
if ! curl -fsSL "${GUARD_URL}" -o "${GUARD_PATH}.tmp"; then
  rm -f "${GUARD_PATH}.tmp"
  fail "Could not download the guard from ${GUARD_URL}. Check your connection and try again."
fi
mv "${GUARD_PATH}.tmp" "${GUARD_PATH}"
ok "Downloaded the guard to ${GUARD_PATH}"

# --- 2. Obtain the API key -----------------------------------------------------
# Prefer the environment so non-interactive installs (CI, scripts) work without a
# prompt; otherwise ask the user to paste it.
API_KEY="${SECUREAI_API_KEY:-}"
if [ -z "${API_KEY}" ]; then
  if [ ! -t 0 ]; then
    fail "No API key provided. Set SECUREAI_API_KEY and re-run, e.g.:  SECUREAI_API_KEY=sk_... bash -c \"\$(curl -fsSL ${API_URL}/install.sh)\""
  fi
  printf 'Paste your SecureAI API key (from your dashboard): '
  read -r API_KEY </dev/tty
fi
API_KEY="$(printf '%s' "${API_KEY}" | tr -d '[:space:]')"
[ -n "${API_KEY}" ] || fail "An API key is required to register the guard."
ok "API key captured"

# --- 3. Persist config (key + URL) ---------------------------------------------
# Written for the user's reference and reuse; the hook command below also carries
# the key + URL inline so the guard sees them regardless of how Claude Code spawns
# it. Node writes the file so the key is JSON-escaped safely.
CONFIG_PATH="${SECUREAI_DIR}/config.json"
CONFIG_PATH="${CONFIG_PATH}" \
SECUREAI_API_KEY="${API_KEY}" \
SECUREAI_API_URL="${API_URL}" \
node <<'NODE'
const fs = require('fs')
const path = process.env.CONFIG_PATH
const config = {
  apiUrl: process.env.SECUREAI_API_URL,
  apiKey: process.env.SECUREAI_API_KEY,
}
fs.writeFileSync(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 })
NODE
chmod 600 "${CONFIG_PATH}" 2>/dev/null || true
ok "Saved config to ${CONFIG_PATH}"

# --- 4. Merge the PreToolUse hook into ~/.claude/settings.json -----------------
# Done in node so the existing JSON is parsed, not regex-mangled: read the file
# (or {} when absent), ensure hooks.PreToolUse is an array, drop any prior
# SecureAI entry (idempotent), append the fresh one, and write it back —
# preserving every other setting.
mkdir -p "${CLAUDE_DIR}"
HOOK_COMMAND="SECUREAI_API_KEY=${API_KEY} SECUREAI_API_URL=${API_URL} node ${GUARD_PATH}"

SETTINGS_PATH="${SETTINGS_PATH}" \
HOOK_COMMAND="${HOOK_COMMAND}" \
GUARD_MARKER="${GUARD_MARKER}" \
node <<'NODE'
const fs = require('fs')

const settingsPath = process.env.SETTINGS_PATH
const hookCommand = process.env.HOOK_COMMAND
const marker = process.env.GUARD_MARKER

/** Read the existing settings, tolerating a missing or empty file. */
function readSettings() {
  let raw
  try {
    raw = fs.readFileSync(settingsPath, 'utf8')
  } catch (error) {
    if (error && error.code === 'ENOENT') return {}
    throw error
  }
  const trimmed = raw.trim()
  if (trimmed.length === 0) return {}
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch {
    // Refuse to clobber a settings file we cannot parse — back it up and start
    // clean so the merge never silently destroys hand-edited config.
    const backup = `${settingsPath}.securesg-backup-${Date.now()}`
    fs.copyFileSync(settingsPath, backup)
    process.stderr.write(`Existing settings were not valid JSON; backed up to ${backup}\n`)
    return {}
  }
}

/** True when a hook group already carries the SecureAI guard command. */
function isSecureAiGroup(group) {
  if (!group || typeof group !== 'object' || !Array.isArray(group.hooks)) return false
  return group.hooks.some(
    (hook) =>
      hook && typeof hook === 'object' && typeof hook.command === 'string' && hook.command.includes(marker),
  )
}

const settings = readSettings()
if (!settings.hooks || typeof settings.hooks !== 'object' || Array.isArray(settings.hooks)) {
  settings.hooks = {}
}
if (!Array.isArray(settings.hooks.PreToolUse)) {
  settings.hooks.PreToolUse = []
}

// Drop any prior SecureAI hook group, then add the fresh one — idempotent.
settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter((group) => !isSecureAiGroup(group))
settings.hooks.PreToolUse.push({
  matcher: '*',
  hooks: [{ type: 'command', command: hookCommand }],
})

fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n')
NODE
ok "Registered the PreToolUse hook in ${SETTINGS_PATH}"

# --- Done ----------------------------------------------------------------------
printf '\n\033[1m\033[32mSecureAI Guard is installed.\033[0m\n\n'
info "Every Claude Code tool call is now screened before it runs (fail-closed)."
info "Verify it:"
info "  1. Restart Claude Code (or start a new session) so it reloads settings."
info "  2. Run a tool — the guard screens it via ${API_URL}."
info "  3. Inspect the hook:  cat ${SETTINGS_PATH}"
printf '\n'
