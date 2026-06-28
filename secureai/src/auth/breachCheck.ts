/**
 * Online leaked-password check via the Have I Been Pwned (HIBP) range API, using
 * k-anonymity so the password — and even its full hash — NEVER leaves the Worker.
 *
 * Protocol: SHA-1 the candidate, send ONLY the first 5 hex characters of the
 * digest to `range/<prefix>`, and match the remaining 35-character suffix against
 * the returned list locally. HIBP never learns which suffix we were looking for.
 *
 * SHA-1 NOTE: this is the one place SHA-1 is used, and it is mandated by the HIBP
 * protocol for a k-anonymity range query — NOT for integrity. It has nothing to
 * do with the audit chain, which is SHA-256-only (CLAUDE.md §5); a breach lookup
 * is not a security primitive whose collision-resistance we rely on.
 *
 * FAIL-OPEN: a timeout, network error, or non-200 response returns `false` (not
 * breached) so a third-party outage never blocks a legitimate signup. The offline
 * `assessPasswordStrength` denylist still runs first, so weak passwords are caught
 * even when this check is degraded. Pair the timeout with `AbortSignal.timeout`.
 */

/** HIBP range endpoint base; the 5-hex-char prefix is appended per query. */
const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/'
/** Length of the hashed-prefix sent to HIBP (the k-anonymity bucket key). */
const PREFIX_LENGTH = 5

const textEncoder = new TextEncoder()

/** Uppercase-hex SHA-1 of a UTF-8 string (HIBP works in uppercase hex). */
async function sha1HexUpper(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', textEncoder.encode(value))
  const view = new Uint8Array(digest)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex.toUpperCase()
}

/**
 * Report whether `password` appears in the HIBP breach corpus. Fails OPEN
 * (returns `false`) on any timeout/network/HTTP error so an outage never blocks
 * registration.
 *
 * Time complexity: O(m) in the bucket size returned by HIBP (a few hundred
 * lines), plus one bounded fetch. Space complexity: O(m).
 *
 * @param password - The plaintext candidate (never sent; only a 5-char hash prefix is).
 * @param timeoutMs - Hard timeout for the HIBP fetch (`config.pwnedTimeoutMs`).
 * @returns `true` only if the suffix is found in the breach list; `false` otherwise.
 */
export async function isPasswordBreached(password: string, timeoutMs: number): Promise<boolean> {
  try {
    const hash = await sha1HexUpper(password)
    const prefix = hash.slice(0, PREFIX_LENGTH)
    const suffix = hash.slice(PREFIX_LENGTH)
    const response = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
      method: 'GET',
      // Add-Padding returns a constant-size response so the bucket size cannot be
      // inferred from over-the-wire length — a small extra privacy hardening.
      headers: { 'Add-Padding': 'true' },
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!response.ok) {
      return false
    }
    const body = await response.text()
    for (const line of body.split('\n')) {
      // Each line is `SUFFIX:count`; a padded entry has count 0 and never matches
      // a real suffix. Compare only the suffix, case-insensitively.
      const separator = line.indexOf(':')
      if (separator === -1) {
        continue
      }
      if (line.slice(0, separator).trim().toUpperCase() === suffix) {
        return true
      }
    }
    return false
  } catch {
    // Fail open: a degraded breach service must not block a legitimate signup.
    return false
  }
}
