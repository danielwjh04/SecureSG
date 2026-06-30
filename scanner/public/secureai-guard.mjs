#!/usr/bin/env node
/**
 * SecureAI Guard, Claude Code PreToolUse hook (client side).
 *
 * Claude Code runs this script BEFORE every tool call. It reads the full
 * PreToolUse JSON payload from stdin, forwards it to the SecureAI scanner's
 * `/api/guard` endpoint, and translates the scanner's verdict into a Claude Code
 * permission decision printed on stdout:
 *
 *     ALLOW                   -> permissionDecision "allow"
 *     HUMAN_APPROVAL_REQUIRED -> permissionDecision "ask"
 *     BLOCK                   -> permissionDecision "deny"
 *
 * FAIL-CLOSED GUARANTEE: if the guard cannot reach a confident decision, a
 * network error, a timeout, a non-2xx response, or an unparseable body, it
 * prints a `deny` decision and exits 0. It NEVER prints `allow` on failure, so a
 * down or unreachable scanner blocks the tool call rather than waving it through.
 *
 * Zero dependencies. Node 18+ (global `fetch`, `AbortSignal.timeout`). Reads
 * configuration from the environment; nothing is hardcoded:
 *   - SECUREAI_API_URL    base URL of the scanner (default the hosted endpoint)
 *   - SECUREAI_API_KEY    optional bearer token; sent as Authorization if set
 *   - SECUREAI_TIMEOUT_MS request timeout in milliseconds (default 5000)
 *
 * The script always exits 0: the decision lives in the printed JSON, not the
 * exit code, which is how Claude Code expects a PreToolUse hook to communicate.
 */

import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const DEFAULT_API_URL = 'https://secureai.software'
const DEFAULT_TIMEOUT_MS = 5000
const HOOK_EVENT_NAME = 'PreToolUse'
const GUARD_PATH = '/api/guard'
// SECUREAI-REDACT:BEGIN (generated, do not edit)
/**
 * Source of truth for guard-adapter secret redaction, content hashing, and
 * privacy modes. Inlined into each standalone adapter by
 * scripts/sync-adapter-redaction.mjs (the adapters cannot import it because
 * each is distributed as a single downloaded file). Pure: no process or env
 * access. Security rule: never let a known secret format through; over
 * redaction is acceptable, under redaction is a defect.
 */


const REDACTED = '[REDACTED]'
const DEFAULT_PRIVACY_MODE = 'balanced'
const PRIVACY_MODES = new Set(['maximum', 'balanced', 'investigation'])

const SECRET_KEY_PATTERN = /(token|secret|password|passwd|pwd|credential|authorization|cookie|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)/i
const SECRET_ASSIGNMENT_PATTERN = /\b([A-Za-z0-9_-]*(?:token|secret|password|passwd|pwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[A-Za-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;&|]+)/gi
const SECRET_COLON_PATTERN = /(["']?[A-Za-z0-9_-]*(?:token|secret|password|passwd|pwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[A-Za-z0-9_-]*["']?\s*:\s*)("[^"]*"|'[^']*'|[^\s,}\]]+)/gi
const BEARER_PATTERN = /\b(Bearer\s+)\S+/gi
const BASIC_PATTERN = /\b(Basic\s+)\S+/gi
const SLACK_TOKEN_PATTERN = /\bxox[baprs]-[A-Za-z0-9-]{8,}/g
const AWS_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/g
const PREFIX_TOKEN_PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|hf|sk_live|sk_test|sk|pk_live|pk_test|xkeysib|shpat)[_-][A-Za-z0-9_-]{8,}/g
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----/g
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g
const CONNECTION_CRED_PATTERN = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:@]*):([^\s]+)@/gi
const QUERY_SECRET_PATTERN = /([?&][^=]*(?:token|secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[^=]*=)[^&#\s]+/gi

/**
 * Redact likely secrets from a string. Order matters: structured blocks (PEM)
 * and assignments first (both key=value and key: value forms), then token
 * shapes, then connection credentials and query secrets.
 *
 * Time complexity: O(n) in string length across a fixed pattern set.
 */
function redactString(value) {
  return value
    .replace(PEM_PRIVATE_KEY_PATTERN, REDACTED)
    .replace(SECRET_ASSIGNMENT_PATTERN, (_m, key) => `${key}=${REDACTED}`)
    .replace(SECRET_COLON_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
    .replace(BEARER_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
    .replace(BASIC_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
    .replace(CONNECTION_CRED_PATTERN, (_m, head) => `${head}:${REDACTED}@`)
    .replace(SLACK_TOKEN_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_PATTERN, REDACTED)
    .replace(PREFIX_TOKEN_PATTERN, REDACTED)
    .replace(JWT_PATTERN, REDACTED)
    .replace(QUERY_SECRET_PATTERN, (_m, prefix) => `${prefix}${REDACTED}`)
}

/** Deep-redact a value: strings, arrays, and objects (secret-named keys fully redacted). */
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

function canonical(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(',')}]`
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
  }
  return JSON.stringify(value === undefined ? null : value)
}

/** Lowercase-hex sha256 over the canonical JSON of the redacted {tool_name, tool_input}. */
function computeContentHash(payload) {
  const redacted = redactSecrets({ tool_name: payload.tool_name ?? null, tool_input: payload.tool_input ?? null })
  return createHash('sha256').update(canonical(redacted)).digest('hex')
}

/**
 * Redact, then apply the privacy mode. `maximum` sends metadata plus the content
 * hash only (no raw content); `balanced` and `investigation` keep the redacted
 * content. The caller must set `content_hash` before calling so `maximum` still
 * carries it.
 */
function applyPrivacyMode(payload, mode) {
  const output = redactSecrets(payload)
  if (mode === 'maximum' && output !== null && typeof output === 'object' && !Array.isArray(output)) {
    delete output.session_id
    delete output.transcript_path
    delete output.cwd
    delete output.tool_input
  }
  return output
}
// SECUREAI-REDACT:END

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

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
}

function normalizePrivacyMode(value) {
  const mode = nonEmptyString(value) ? value.trim().toLowerCase() : DEFAULT_PRIVACY_MODE
  return PRIVACY_MODES.has(mode) ? mode : DEFAULT_PRIVACY_MODE
}

function attachLocalContext(payload, privacyMode, env) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return payload
  }
  const output = { ...payload, privacy_mode: privacyMode }
  if (nonEmptyString(env.SECUREAI_DEVICE_ID)) {
    output.device_id = env.SECUREAI_DEVICE_ID.trim()
  }
  if (nonEmptyString(env.SECUREAI_INTEGRATION_VERSION)) {
    output.integration_version = env.SECUREAI_INTEGRATION_VERSION.trim()
  }
  return output
}

function mapGuardDecision(body) {
  const decision = body && typeof body === 'object' ? body.decision : undefined
  const reason =
    body && typeof body === 'object' && typeof body.reason === 'string'
      ? body.reason
      : 'no reason provided'

  if (decision === 'allow' || decision === 'ask' || decision === 'deny') {
    return {
      hookSpecificOutput: {
        hookEventName: HOOK_EVENT_NAME,
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    }
  }
  return null
}

function failClosedOutput(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT_NAME,
      permissionDecision: 'deny',
      permissionDecisionReason: `SecureAI guard could not verify this tool call: ${reason}. Blocked fail-closed.`,
    },
  }
}

/**
 * Run one Claude Code PreToolUse payload through SecureAI and return the hook
 * output object. Accepts env and fetchImpl for testability.
 */
export async function runGuard(input, options = {}) {
  const env = options.env ?? process.env
  const fetchImpl = options.fetchImpl ?? fetch

  const apiUrl = (env.SECUREAI_API_URL || DEFAULT_API_URL).replace(/\/+$/, '')
  const apiKey = env.SECUREAI_API_KEY
  const privacyMode = normalizePrivacyMode(env.SECUREAI_PRIVACY_MODE)
  const timeoutRaw = Number(env.SECUREAI_TIMEOUT_MS)
  const timeoutMs = Number.isFinite(timeoutRaw) && timeoutRaw > 0 ? timeoutRaw : DEFAULT_TIMEOUT_MS

  let parsed
  try {
    parsed = JSON.parse(input)
  } catch {
    return failClosedOutput('hook payload was not valid JSON')
  }

  const withContext = attachLocalContext(parsed, privacyMode, env)
  withContext.content_hash = computeContentHash(withContext)
  const guardPayload = JSON.stringify(applyPrivacyMode(withContext, privacyMode))

  const headers = { 'content-type': 'application/json' }
  if (typeof apiKey === 'string' && apiKey.length > 0) {
    headers.authorization = `Bearer ${apiKey}`
  }

  let response
  try {
    response = await fetchImpl(`${apiUrl}${GUARD_PATH}`, {
      method: 'POST',
      headers,
      body: guardPayload,
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (error) {
    const detail = error && error.name === 'TimeoutError' ? `timed out after ${timeoutMs}ms` : 'network error'
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

  return mapGuardDecision(body) ?? failClosedOutput('scanner returned an unrecognized decision')
}

/**
 * Entry point: read stdin, run the guard, emit the decision to stdout.
 */
async function main() {
  const env = process.env
  let input
  try {
    input = await readStdin()
  } catch {
    process.stdout.write(JSON.stringify(failClosedOutput('could not read the hook payload from stdin')))
    process.exit(0)
    return
  }

  const output = await runGuard(input, { env })
  process.stdout.write(JSON.stringify(output))
  process.exit(0)
}

function isCliEntry() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href
}

if (isCliEntry()) {
  main().catch(() => {
    process.stdout.write(JSON.stringify(failClosedOutput('unexpected guard error')))
    process.exit(0)
  })
}
