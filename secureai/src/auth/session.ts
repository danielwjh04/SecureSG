/**
 * Stateless, HMAC-signed session tokens and the `secureai_session` cookie they
 * ride in.
 *
 * A session token is `base64url(payload).base64url(HMAC-SHA256(payload, secret))`
 * where the payload is `<userId>.<expiresAtSeconds>`. There is no server-side
 * session store: a token is valid iff its signature verifies under the configured
 * secret AND its embedded expiry is in the future. `nowSeconds` is passed IN by
 * the caller (the route stamps it once at the edge) so signing and verification
 * are deterministic and unit-testable without mocking the clock.
 *
 * Security posture (CLAUDE.md §6):
 *   - SHA-256 only, via Web Crypto `crypto.subtle` (present in Workers and Node
 *     test runtimes).
 *   - Signature comparison is constant-time.
 *   - Any tamper (payload edit, signature edit), a wrong secret, a malformed
 *     token, or an expired token all yield `null` — fail closed, never throw.
 *   - The cookie is `HttpOnly; Secure; SameSite=Lax; Path=/` so it is invisible
 *     to scripts, sent only over HTTPS, and not attached on cross-site requests.
 */

/** Name of the session cookie the browser stores and replays. */
export const SESSION_COOKIE_NAME = 'secureai_session'
/** Separator between the payload and its signature in a token. */
const TOKEN_SEPARATOR = '.'
/** Separator between the user id and the expiry inside the payload. */
const PAYLOAD_SEPARATOR = '.'

const textEncoder = new TextEncoder()

/** Encode bytes as URL-safe base64 without padding. Time/space O(n). */
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Encode a UTF-8 string as URL-safe base64. Time/space O(n). */
function stringToBase64Url(value: string): string {
  return bytesToBase64Url(textEncoder.encode(value))
}

/** Decode URL-safe base64 to a UTF-8 string, or `null` if undecodable. */
function base64UrlToString(value: string): string | null {
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/')
    return atob(padded)
  } catch {
    return null
  }
}

/**
 * Compute the URL-safe-base64 HMAC-SHA256 of `payload` under `secret`.
 *
 * Time complexity: O(n) in `payload` length. Space complexity: O(1).
 */
async function sign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload))
  return bytesToBase64Url(new Uint8Array(signature))
}

/** Constant-time string equality (lengths are not secret). Time O(n). */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

/**
 * Mint a signed session token for `userId` that expires `ttlSeconds` after
 * `nowSeconds`.
 *
 * Time complexity: O(1) (one HMAC over a short payload). Space complexity: O(1).
 *
 * @param userId - The account id the session authenticates.
 * @param nowSeconds - Current UNIX time in seconds, supplied by the caller.
 * @param ttlSeconds - Lifetime in seconds (from `config.sessionTtlSeconds`).
 * @param secret - The HMAC secret (`env.SESSION_SECRET`).
 * @returns The `payload.signature` session token.
 */
export async function signSession(
  userId: string,
  nowSeconds: number,
  ttlSeconds: number,
  secret: string,
): Promise<string> {
  const expiresAt = Math.floor(nowSeconds) + ttlSeconds
  const payload = `${userId}${PAYLOAD_SEPARATOR}${expiresAt}`
  const encodedPayload = stringToBase64Url(payload)
  const signature = await sign(encodedPayload, secret)
  return `${encodedPayload}${TOKEN_SEPARATOR}${signature}`
}

/**
 * Verify a session token and return its user id, or `null` when the token is
 * invalid: malformed structure, bad signature (tamper or wrong secret), or
 * expired relative to `nowSeconds`.
 *
 * The signature is recomputed over the RECEIVED encoded payload and compared in
 * constant time, so editing either the payload or the signature breaks
 * verification. Only after the signature passes is the embedded expiry trusted.
 *
 * Time complexity: O(n) in token length. Space complexity: O(1).
 *
 * @param token - The presented session token.
 * @param nowSeconds - Current UNIX time in seconds, supplied by the caller.
 * @param secret - The HMAC secret (`env.SESSION_SECRET`).
 * @returns The authenticated user id, or `null` if the token is not valid now.
 */
export async function verifySession(
  token: string,
  nowSeconds: number,
  secret: string,
): Promise<string | null> {
  const sepIndex = token.indexOf(TOKEN_SEPARATOR)
  if (sepIndex <= 0 || sepIndex === token.length - 1) {
    return null
  }
  const encodedPayload = token.slice(0, sepIndex)
  const presentedSignature = token.slice(sepIndex + 1)

  const expectedSignature = await sign(encodedPayload, secret)
  if (!constantTimeEquals(presentedSignature, expectedSignature)) {
    return null
  }

  const payload = base64UrlToString(encodedPayload)
  if (payload === null) {
    return null
  }
  const lastSep = payload.lastIndexOf(PAYLOAD_SEPARATOR)
  if (lastSep <= 0) {
    return null
  }
  const userId = payload.slice(0, lastSep)
  const expiresAt = Number(payload.slice(lastSep + 1))
  if (userId.length === 0 || !Number.isInteger(expiresAt)) {
    return null
  }
  if (Math.floor(nowSeconds) >= expiresAt) {
    return null
  }
  return userId
}

/**
 * Build a `Set-Cookie` header value carrying `token` in the session cookie,
 * expiring after `ttlSeconds`. Flags: `HttpOnly` (no script access), `Secure`
 * (HTTPS only), `SameSite=Lax` (not sent cross-site), `Path=/` (whole origin).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function buildSessionCookie(token: string, ttlSeconds: number): string {
  return (
    `${SESSION_COOKIE_NAME}=${token}; ` +
    `Max-Age=${ttlSeconds}; Path=/; HttpOnly; Secure; SameSite=Lax`
  )
}

/**
 * Build a `Set-Cookie` header value that clears the session cookie (`Max-Age=0`
 * with an empty value), used by logout. Same flags so the browser matches and
 * deletes the existing cookie.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function buildClearedSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
}

/**
 * Parse the session token out of a request's `Cookie` header, or `null` when the
 * header is absent or carries no `secureai_session` cookie.
 *
 * Time complexity: O(c) in the cookie-header length. Space complexity: O(1).
 */
export function readSessionCookie(request: Request): string | null {
  const header = request.headers.get('Cookie')
  if (header === null) {
    return null
  }
  for (const pair of header.split(';')) {
    const trimmed = pair.trim()
    const eq = trimmed.indexOf('=')
    if (eq <= 0) {
      continue
    }
    if (trimmed.slice(0, eq) === SESSION_COOKIE_NAME) {
      const value = trimmed.slice(eq + 1).trim()
      return value.length > 0 ? value : null
    }
  }
  return null
}
