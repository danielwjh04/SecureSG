/**
 * Source of truth for guard-adapter secret redaction, content hashing, and
 * privacy modes. Inlined into each standalone adapter by
 * scripts/sync-adapter-redaction.mjs (the adapters cannot import it because
 * each is distributed as a single downloaded file). Pure: no process or env
 * access. Security rule: never let a known secret format through; over
 * redaction is acceptable, under redaction is a defect.
 */
import { createHash } from 'node:crypto'

export const REDACTED = '[REDACTED]'
export const DEFAULT_PRIVACY_MODE = 'balanced'
export const PRIVACY_MODES = new Set(['maximum', 'balanced', 'investigation'])

const SECRET_KEY_PATTERN = /(token|secret|password|passwd|pwd|credential|authorization|cookie|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)/i
const SECRET_ASSIGNMENT_PATTERN = /\b([A-Za-z_][A-Za-z0-9_-]*(?:token|secret|password|passwd|pwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[A-Za-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;&|]+)/gi
const BEARER_PATTERN = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi
const BASIC_PATTERN = /\b(Basic\s+)[A-Za-z0-9._~+/=-]+/gi
const SLACK_TOKEN_PATTERN = /\bxox[baprs]-[A-Za-z0-9-]{8,}/g
const AWS_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/g
const PREFIX_TOKEN_PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|sk_live|sk_test|sk|pk_live|pk_test|xkeysib|shpat)[_-][A-Za-z0-9_-]{8,}/g
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
const CONNECTION_CRED_PATTERN = /\b([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+):([^\s:@/]+)@/gi
const QUERY_SECRET_PATTERN = /([?&][^=]*(?:token|secret|password|credential|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key)[^=]*=)[^&#\s]+/gi

/**
 * Redact likely secrets from a string. Order matters: structured blocks (PEM)
 * and assignments first, then token shapes, then connection credentials and
 * query secrets.
 *
 * Time complexity: O(n) in string length across a fixed pattern set.
 */
export function redactString(value) {
  return value
    .replace(PEM_PRIVATE_KEY_PATTERN, REDACTED)
    .replace(SECRET_ASSIGNMENT_PATTERN, (_m, key) => `${key}=${REDACTED}`)
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
export function redactSecrets(value) {
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
export function computeContentHash(payload) {
  const redacted = redactSecrets({ tool_name: payload.tool_name ?? null, tool_input: payload.tool_input ?? null })
  return createHash('sha256').update(canonical(redacted)).digest('hex')
}

/**
 * Redact, then apply the privacy mode. `maximum` sends metadata plus the content
 * hash only (no raw content); `balanced` and `investigation` keep the redacted
 * content. The caller must set `content_hash` before calling so `maximum` still
 * carries it.
 */
export function applyPrivacyMode(payload, mode) {
  const output = redactSecrets(payload)
  if (mode === 'maximum' && output !== null && typeof output === 'object' && !Array.isArray(output)) {
    delete output.session_id
    delete output.transcript_path
    delete output.cwd
    delete output.tool_input
  }
  return output
}
