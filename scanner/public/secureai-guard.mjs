#!/usr/bin/env node
/**
 * SecureAI Guard — Claude Code PreToolUse hook (client side).
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
 * FAIL-CLOSED GUARANTEE: if the guard cannot reach a confident decision — a
 * network error, a timeout, a non-2xx response, or an unparseable body — it
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

const DEFAULT_API_URL = 'https://secureai.zurielst.com'
const DEFAULT_TIMEOUT_MS = 5000
const HOOK_EVENT_NAME = 'PreToolUse'
const GUARD_PATH = '/api/guard'

/**
 * Read all of stdin and resolve it as a UTF-8 string. Claude Code writes the
 * hook payload to stdin and closes it, so this resolves once the stream ends.
 *
 * @returns {Promise<string>} The complete stdin contents.
 */
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

/**
 * Print a Claude Code PreToolUse hook decision to stdout, then exit 0.
 *
 * @param {'allow'|'ask'|'deny'} permissionDecision The mapped decision.
 * @param {string} permissionDecisionReason A human-readable rationale.
 */
function emitDecision(permissionDecision, permissionDecisionReason) {
  const output = {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT_NAME,
      permissionDecision,
      permissionDecisionReason,
    },
  }
  process.stdout.write(JSON.stringify(output))
  process.exit(0)
}

/**
 * Emit the fail-closed `deny` decision. Centralized so every failure path —
 * unreadable stdin, network fault, timeout, non-2xx, malformed body — produces
 * the identical deny-by-default output. Never allows on failure.
 *
 * @param {string} reason Why the guard could not verify the call.
 */
function failClosed(reason) {
  emitDecision('deny', `SecureAI guard could not verify this tool call: ${reason}. Blocked fail-closed.`)
}

/**
 * Map the server's `GuardDecision` body to a Claude Code decision and emit it.
 * A body missing the required string fields is treated as unverifiable and fails
 * closed rather than being trusted.
 *
 * @param {unknown} body The parsed JSON response from `/api/guard`.
 */
function emitFromGuardDecision(body) {
  const decision = body && typeof body === 'object' ? body.decision : undefined
  const reason =
    body && typeof body === 'object' && typeof body.reason === 'string'
      ? body.reason
      : 'no reason provided'

  if (decision === 'allow' || decision === 'ask' || decision === 'deny') {
    emitDecision(decision, reason)
    return
  }
  failClosed('scanner returned an unrecognized decision')
}

/**
 * Entry point: read the payload, POST it to the guard, and emit the decision.
 * Every error path routes through failClosed.
 */
async function main() {
  const apiUrl = (process.env.SECUREAI_API_URL || DEFAULT_API_URL).replace(/\/+$/, '')
  const apiKey = process.env.SECUREAI_API_KEY
  const timeoutRaw = Number(process.env.SECUREAI_TIMEOUT_MS)
  const timeoutMs =
    Number.isFinite(timeoutRaw) && timeoutRaw > 0 ? timeoutRaw : DEFAULT_TIMEOUT_MS

  let payload
  try {
    payload = await readStdin()
  } catch {
    failClosed('could not read the hook payload from stdin')
    return
  }

  // The payload must be valid JSON; if Claude Code handed us something
  // unparseable, we cannot safely forward it — fail closed.
  try {
    JSON.parse(payload)
  } catch {
    failClosed('hook payload was not valid JSON')
    return
  }

  const headers = { 'content-type': 'application/json' }
  if (typeof apiKey === 'string' && apiKey.length > 0) {
    headers.authorization = `Bearer ${apiKey}`
  }

  let response
  try {
    response = await fetch(`${apiUrl}${GUARD_PATH}`, {
      method: 'POST',
      headers,
      body: payload,
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (error) {
    const detail = error && error.name === 'TimeoutError' ? `timed out after ${timeoutMs}ms` : 'network error'
    failClosed(detail)
    return
  }

  if (!response.ok) {
    failClosed(`scanner responded with HTTP ${response.status}`)
    return
  }

  let body
  try {
    body = await response.json()
  } catch {
    failClosed('scanner response was not valid JSON')
    return
  }

  emitFromGuardDecision(body)
}

main().catch(() => {
  // Last-resort guard: any unforeseen throw still fails closed, never allows.
  failClosed('unexpected guard error')
})
