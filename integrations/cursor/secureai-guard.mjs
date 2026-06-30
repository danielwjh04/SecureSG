#!/usr/bin/env node
/**
 * SecureAI Guard, Cursor hook adapter.
 *
 * Cursor command hooks read JSON from stdin and return JSON on stdout. This
 * adapter translates Cursor beforeShellExecution and beforeMCPExecution payloads
 * into SecureAI's guard contract, calls /api/guard, and maps the server decision
 * back into Cursor's permission shape.
 *
 * Fail-closed: any unreadable input, missing API key, network error, timeout,
 * non-2xx response, malformed JSON, or unknown decision returns permission
 * "deny". The script exits 0 because the decision lives in stdout JSON.
 */

import { readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const DEFAULT_API_URL = 'https://secureai.software'
const DEFAULT_TIMEOUT_MS = 5000
const GUARD_PATH = '/api/guard'
const PROVIDER = 'cursor'
const PRE_TOOL_USE_EVENT = 'PreToolUse'
const SHELL_TOOL_NAME = 'Shell'
const DEFAULT_PRIVACY_MODE = 'balanced'
const PRIVACY_MODES = new Set(['maximum', 'balanced', 'investigation'])
const REDACTED = '[REDACTED]'
const SECRET_KEY_PATTERN = /(token|secret|password|passwd|pwd|credential|authorization|cookie|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)/i
const SECRET_ASSIGNMENT_PATTERN =
  /\b([A-Za-z_][A-Za-z0-9_-]*(?:token|secret|password|passwd|pwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[A-Za-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;&|]+)/gi
const BEARER_PATTERN = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi
const BASIC_PATTERN = /\b(Basic\s+)[A-Za-z0-9._~+/=-]+/gi
const TOKEN_PREFIX_PATTERN =
  /\b(ghp|github_pat|sk|sk_live|sk_test|xoxb|xoxp|AKIA|ASIA)_[A-Za-z0-9_=-]+/g
const QUERY_SECRET_PATTERN =
  /([?&][^=]*(?:token|secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[^=]*=)[^&#\s]+/gi

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function failClosedOutput(reason) {
  const message = `SecureAI guard could not verify this Cursor action: ${reason}. Blocked fail-closed.`
  return { permission: 'deny', user_message: message, agent_message: message }
}

function redactString(value) {
  return value
    .replace(SECRET_ASSIGNMENT_PATTERN, (_match, key) => `${key}=${REDACTED}`)
    .replace(BEARER_PATTERN, (_match, prefix) => `${prefix}${REDACTED}`)
    .replace(BASIC_PATTERN, (_match, prefix) => `${prefix}${REDACTED}`)
    .replace(TOKEN_PREFIX_PATTERN, REDACTED)
    .replace(QUERY_SECRET_PATTERN, (_match, prefix) => `${prefix}${REDACTED}`)
}

function redactSecrets(value) {
  if (typeof value === 'string') {
    return redactString(value)
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item))
  }
  if (value !== null && typeof value === 'object') {
    const output = {}
    for (const [key, item] of Object.entries(value)) {
      output[key] = SECRET_KEY_PATTERN.test(key) ? REDACTED : redactSecrets(item)
    }
    return output
  }
  return value
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk) => {
      data += chunk
    })
    process.stdin.on('end', () => resolve(data))
    process.stdin.on('error', reject)
  })
}

function parseArgs(argv) {
  const parsed = {}
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg.startsWith('--api-url=')) {
      parsed.apiUrl = arg.slice('--api-url='.length)
    } else if (arg === '--api-url') {
      index += 1
      parsed.apiUrl = argv[index]
    } else if (arg.startsWith('--api-key=')) {
      parsed.apiKey = arg.slice('--api-key='.length)
    } else if (arg === '--api-key') {
      index += 1
      parsed.apiKey = argv[index]
    } else if (arg.startsWith('--timeout-ms=')) {
      parsed.timeoutMs = arg.slice('--timeout-ms='.length)
    } else if (arg === '--timeout-ms') {
      index += 1
      parsed.timeoutMs = argv[index]
    } else if (arg.startsWith('--device-id=')) {
      parsed.deviceId = arg.slice('--device-id='.length)
    } else if (arg === '--device-id') {
      index += 1
      parsed.deviceId = argv[index]
    } else if (arg.startsWith('--privacy-mode=')) {
      parsed.privacyMode = arg.slice('--privacy-mode='.length)
    } else if (arg === '--privacy-mode') {
      index += 1
      parsed.privacyMode = argv[index]
    } else if (arg.startsWith('--integration-version=')) {
      parsed.integrationVersion = arg.slice('--integration-version='.length)
    } else if (arg === '--integration-version') {
      index += 1
      parsed.integrationVersion = argv[index]
    } else if (arg.startsWith('--config=')) {
      parsed.configPath = arg.slice('--config='.length)
    } else if (arg === '--config') {
      index += 1
      parsed.configPath = argv[index]
    }
  }
  return parsed
}

function readConfigFile(configPath, readFile) {
  let raw
  try {
    raw = readFile(configPath, 'utf8')
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return {}
    }
    throw error
  }
  if (raw.trim().length === 0) {
    return {}
  }
  const parsed = JSON.parse(raw)
  return isRecord(parsed) ? parsed : {}
}

function positiveInt(value, fallback) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

function optionalString(value) {
  return nonEmptyString(value) ? value.trim() : undefined
}

function normalizePrivacyMode(value) {
  const mode = nonEmptyString(value) ? value.trim().toLowerCase() : DEFAULT_PRIVACY_MODE
  return PRIVACY_MODES.has(mode) ? mode : DEFAULT_PRIVACY_MODE
}

function normalizeApiUrl(value) {
  return String(value).replace(/\/+$/, '')
}

function resolveConfig(options = {}) {
  const env = options.env ?? process.env
  const argv = options.argv ?? []
  const homeDir = options.homeDir ?? os.homedir()
  const readFile = options.readFileSync ?? readFileSync
  const flags = parseArgs(argv)
  const configPath =
    flags.configPath ?? env.SECUREAI_CONFIG_PATH ?? path.join(homeDir, '.secureai', 'config.json')
  const fileConfig = readConfigFile(configPath, readFile)

  const apiUrl = normalizeApiUrl(
    flags.apiUrl ?? env.SECUREAI_API_URL ?? fileConfig.apiUrl ?? DEFAULT_API_URL,
  )
  const apiKey = flags.apiKey ?? env.SECUREAI_API_KEY ?? fileConfig.apiKey
  const timeoutMs = positiveInt(
    flags.timeoutMs ?? env.SECUREAI_TIMEOUT_MS ?? fileConfig.timeoutMs,
    DEFAULT_TIMEOUT_MS,
  )
  const deviceId = optionalString(flags.deviceId ?? env.SECUREAI_DEVICE_ID ?? fileConfig.deviceId)
  const privacyMode = normalizePrivacyMode(
    flags.privacyMode ?? env.SECUREAI_PRIVACY_MODE ?? fileConfig.privacyMode,
  )
  const integrationVersion = optionalString(
    flags.integrationVersion ?? env.SECUREAI_INTEGRATION_VERSION ?? fileConfig.integrationVersion,
  )

  return { apiUrl, apiKey, timeoutMs, deviceId, privacyMode, integrationVersion }
}

function healthFromConfig(provider, config) {
  return {
    provider,
    status: nonEmptyString(config.apiKey) ? 'enabled' : 'disabled',
    api_url: config.apiUrl,
    auth: nonEmptyString(config.apiKey) ? 'present' : 'missing',
    device_id: nonEmptyString(config.deviceId) ? 'present' : 'missing',
    privacy_mode: config.privacyMode,
    integration_version: nonEmptyString(config.integrationVersion) ? 'present' : 'missing',
  }
}

export function cursorGuardHealth(options = {}) {
  try {
    return healthFromConfig(PROVIDER, resolveConfig({
      env: options.env ?? process.env,
      argv: options.argv ?? [],
      homeDir: options.homeDir,
      readFileSync: options.readFileSync,
    }))
  } catch {
    return {
      provider: PROVIDER,
      status: 'unknown',
      api_url: 'unknown',
      auth: 'unknown',
      device_id: 'unknown',
      privacy_mode: 'unknown',
      integration_version: 'unknown',
    }
  }
}

function attachLocalContext(payload, config) {
  const output = { ...payload, privacy_mode: config.privacyMode }
  if (nonEmptyString(config.deviceId)) {
    output.device_id = config.deviceId
  }
  if (nonEmptyString(config.integrationVersion)) {
    output.integration_version = config.integrationVersion
  }
  return output
}

function applyPrivacyMode(payload, privacyMode) {
  const output = redactSecrets(payload)
  if (privacyMode === 'maximum') {
    delete output.session_id
    delete output.transcript_path
    if (isRecord(output.tool_input)) {
      delete output.tool_input.cwd
    }
  }
  return output
}

function normalizeMcpToolInput(value) {
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value)
      return isRecord(parsed) ? { ...parsed } : { raw: value }
    } catch {
      return { raw: value }
    }
  }
  if (isRecord(value)) {
    return { ...value }
  }
  if (value === undefined) {
    return {}
  }
  return { value }
}

function contextFields(payload, env) {
  const cwd = nonEmptyString(payload.cwd)
    ? payload.cwd
    : nonEmptyString(env.CURSOR_PROJECT_DIR)
      ? env.CURSOR_PROJECT_DIR
      : nonEmptyString(env.CLAUDE_PROJECT_DIR)
        ? env.CLAUDE_PROJECT_DIR
        : undefined
  const transcriptPath = nonEmptyString(payload.transcript_path)
    ? payload.transcript_path
    : nonEmptyString(env.CURSOR_TRANSCRIPT_PATH)
      ? env.CURSOR_TRANSCRIPT_PATH
      : undefined
  const sessionId = nonEmptyString(payload.session_id)
    ? payload.session_id
    : nonEmptyString(env.CURSOR_SESSION_ID)
      ? env.CURSOR_SESSION_ID
      : undefined

  return { cwd, transcriptPath, sessionId }
}

/**
 * Translate a Cursor beforeShellExecution or beforeMCPExecution payload into
 * SecureAI's guard request body.
 */
export function mapCursorPayload(payload, env = process.env) {
  if (!isRecord(payload)) {
    throw new TypeError('Cursor hook payload must be an object')
  }

  const { cwd, transcriptPath, sessionId } = contextFields(payload, env)

  if (nonEmptyString(payload.tool_name)) {
    const toolInput = normalizeMcpToolInput(payload.tool_input)
    if (nonEmptyString(payload.url)) {
      toolInput.mcp_server_url = payload.url
    }
    if (nonEmptyString(payload.command)) {
      toolInput.mcp_server_command = payload.command
    }
    return {
      hook_event_name: PRE_TOOL_USE_EVENT,
      tool_name: payload.tool_name,
      tool_input: toolInput,
      session_id: sessionId,
      transcript_path: transcriptPath,
      cwd,
      provider: PROVIDER,
      cursor_hook_event_name: 'beforeMCPExecution',
    }
  }

  if (nonEmptyString(payload.command)) {
    const toolInput = { command: payload.command }
    if (nonEmptyString(payload.cwd)) {
      toolInput.cwd = payload.cwd
    }
    if (typeof payload.sandbox === 'boolean') {
      toolInput.sandbox = payload.sandbox
    }
    return {
      hook_event_name: PRE_TOOL_USE_EVENT,
      tool_name: SHELL_TOOL_NAME,
      tool_input: toolInput,
      session_id: sessionId,
      transcript_path: transcriptPath,
      cwd,
      provider: PROVIDER,
      cursor_hook_event_name: 'beforeShellExecution',
    }
  }

  throw new TypeError('unsupported Cursor hook payload')
}

function mapGuardDecision(body) {
  const decision = isRecord(body) ? body.decision : undefined
  const reason = isRecord(body) && nonEmptyString(body.reason) ? body.reason : 'no reason provided'

  if (decision === 'allow') {
    return { permission: 'allow' }
  }
  if (decision === 'ask' || decision === 'deny') {
    return { permission: decision, user_message: reason, agent_message: reason }
  }
  return failClosedOutput('scanner returned an unrecognized decision')
}

/**
 * Run one Cursor hook payload through SecureAI and return Cursor's output body.
 */
export async function runCursorGuard(input, options = {}) {
  const env = options.env ?? process.env
  let config
  try {
    config = resolveConfig({
      env,
      argv: options.argv ?? [],
      homeDir: options.homeDir,
      readFileSync: options.readFileSync,
    })
  } catch {
    return failClosedOutput('could not read SecureAI config')
  }

  if (!nonEmptyString(config.apiKey)) {
    return failClosedOutput('missing API key')
  }

  let cursorPayload
  try {
    cursorPayload = JSON.parse(input)
  } catch {
    return failClosedOutput('hook payload was not valid JSON')
  }

  let guardPayload
  try {
    guardPayload = mapCursorPayload(cursorPayload, env)
  } catch {
    return failClosedOutput('hook payload did not match a supported Cursor hook')
  }
  guardPayload = applyPrivacyMode(attachLocalContext(guardPayload, config), config.privacyMode)

  const fetchImpl = options.fetchImpl ?? fetch
  let response
  try {
    response = await fetchImpl(`${config.apiUrl}${GUARD_PATH}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify(guardPayload),
      signal: AbortSignal.timeout(config.timeoutMs),
    })
  } catch (error) {
    const detail =
      error && error.name === 'TimeoutError'
        ? `timed out after ${config.timeoutMs}ms`
        : 'network error'
    return failClosedOutput(detail)
  }

  if (!response.ok) {
    return failClosedOutput(`scanner responded with HTTP ${response.status}`)
  }

  let body
  try {
    body = await response.json()
  } catch {
    return failClosedOutput('scanner response was not valid JSON')
  }

  return mapGuardDecision(body)
}

async function main() {
  const argv = process.argv.slice(2)
  if (argv.includes('--health')) {
    process.stdout.write(JSON.stringify(cursorGuardHealth({ argv })))
    return
  }
  const input = await readStdin()
  const output = await runCursorGuard(input, { argv })
  process.stdout.write(JSON.stringify(output))
}

function isCliEntry() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href
}

if (isCliEntry()) {
  main().catch(() => {
    process.stdout.write(JSON.stringify(failClosedOutput('unexpected guard error')))
  })
}
