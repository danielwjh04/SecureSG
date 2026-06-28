/**
 * Request authentication: resolve a caller to a metering {@link AuthContext}.
 *
 * The contract is deliberately permissive on the credential and strict on the
 * outcome: a valid `Authorization: Bearer <key>` resolves to that user's id and
 * tier; failing that, a valid `secureai_session` cookie (when a session secret
 * is configured) resolves to its user; the ABSENCE of both, OR an unknown key /
 * invalid cookie, resolves to an anonymous context keyed by client IP. An
 * unknown credential is NOT an error — it is simply unauthenticated, so a typo,
 * a revoked key, or an expired cookie downgrades to the anonymous cap rather than
 * failing the request. `authenticate` therefore never throws on a bad credential;
 * it only propagates a fault if the underlying store is corrupt.
 *
 * Credential precedence is fixed: `Authorization: Bearer` is tried FIRST, then
 * the session cookie. This keeps the existing API-key path unchanged and makes
 * the cookie a fallback for browser callers.
 */

import type { Database } from '../db/database'
import type { AccountTier } from '../db/accounts'
import { findUserByApiKey, findTierByUserId, isEmailVerified } from '../db/accounts'
import { readSessionCookie, verifySession } from '../auth/session'

/** The tier dimension used for gating, widened with the anonymous pseudo-tier. */
export type AuthTier = 'anonymous' | AccountTier

/** The resolved caller identity used for metering and tier gating. */
export interface AuthContext {
  /** User id for an authenticated caller, else `anon:<ip>`. */
  readonly subject: string
  /** The caller's tier; `anonymous` for unauthenticated callers. */
  readonly tier: AuthTier
}

/** Header carrying the bearer credential. */
const AUTHORIZATION_HEADER = 'Authorization'
/** Cloudflare's true-client-IP header, used to key anonymous subjects. */
const CLIENT_IP_HEADER = 'CF-Connecting-IP'
/** Fallback subject suffix when no client IP is present. */
const UNKNOWN_IP = 'unknown'
/** Anonymous subject prefix, namespacing IPs away from user ids. */
const ANON_SUBJECT_PREFIX = 'anon:'

const BEARER_SCHEME = /^Bearer\s+(.+)$/i

/**
 * Extract the raw bearer key from the `Authorization` header, or `null` when the
 * header is absent or not a non-empty `Bearer <key>`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function extractBearerKey(request: Request): string | null {
  const header = request.headers.get(AUTHORIZATION_HEADER)
  if (header === null) {
    return null
  }
  const match = BEARER_SCHEME.exec(header.trim())
  if (match === null) {
    return null
  }
  const key = (match[1] ?? '').trim()
  return key.length === 0 ? null : key
}

/** Build the anonymous context for a request, keyed by client IP. */
function anonymousContext(request: Request): AuthContext {
  const ip = request.headers.get(CLIENT_IP_HEADER)?.trim()
  const subject = `${ANON_SUBJECT_PREFIX}${ip && ip.length > 0 ? ip : UNKNOWN_IP}`
  return { subject, tier: 'anonymous' }
}

/** Current UNIX time in whole seconds, for session expiry checks. */
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Resolve the session cookie to an authenticated context, or `null` when there
 * is no usable session: no `sessionSecret` configured, no cookie present, a
 * cookie that fails verification (bad signature / expired), one that maps to a
 * user id that no longer resolves to a live account, OR one whose account has
 * not verified its email.
 *
 * The email-verified gate fails closed: a session subject whose account is
 * UNVERIFIED (e.g. a registration that issued no session but whose cookie was
 * somehow presented, or an account un-verified after the fact) is rejected here
 * so the cookie downgrades to anonymous — mirroring the API-key gate in
 * {@link findUserByApiKey}, so NEITHER credential authenticates an unverified
 * account. The check runs before the tier lookup so an unverified account never
 * reaches an authenticated context.
 *
 * Time complexity: O(1) — one HMAC verify + two indexed lookups.
 * Space complexity: O(1).
 *
 * @throws {AuthError} Only if the resolved user's stored tier is corrupt.
 */
async function resolveSession(
  request: Request,
  db: Database,
  sessionSecret: string,
): Promise<AuthContext | null> {
  const token = readSessionCookie(request)
  if (token === null) {
    return null
  }
  const userId = await verifySession(token, nowSeconds(), sessionSecret)
  if (userId === null) {
    return null
  }
  if (!(await isEmailVerified(db, userId))) {
    return null
  }
  const tier = await findTierByUserId(db, userId)
  if (tier === null) {
    return null
  }
  return { subject: userId, tier }
}

/**
 * Resolve a request to an {@link AuthContext}.
 *
 * Tries `Authorization: Bearer <key>` FIRST; a key that resolves to an active
 * account yields `{ subject: userId, tier }`. Failing that, when `sessionSecret`
 * is supplied, the `secureai_session` cookie is verified and, if valid and still
 * mapping to a live account, yields that user's context. No credential, a
 * malformed header, an unknown key, an absent secret, or an invalid/expired
 * cookie all yield `{ subject: 'anon:' + clientIp, tier: 'anonymous' }` — a bad
 * credential is anonymous, never an error.
 *
 * Time complexity: O(1) — at most two indexed credential lookups.
 * Space complexity: O(1).
 *
 * @param request - The inbound request.
 * @param db - The persistence seam used to resolve the credential.
 * @param sessionSecret - `env.SESSION_SECRET` (omit to disable cookie auth).
 * @returns The caller's metering identity and tier.
 * @throws {AuthError} Only if a matched credential record is structurally
 *   corrupt (propagated from the accounts repo); never on a bad credential.
 */
export async function authenticate(
  request: Request,
  db: Database,
  sessionSecret?: string,
): Promise<AuthContext> {
  const rawKey = extractBearerKey(request)
  if (rawKey !== null) {
    const credential = await findUserByApiKey(db, rawKey)
    if (credential !== null) {
      return { subject: credential.userId, tier: credential.tier }
    }
  }

  if (sessionSecret !== undefined && sessionSecret.length > 0) {
    const session = await resolveSession(request, db, sessionSecret)
    if (session !== null) {
      return session
    }
  }

  return anonymousContext(request)
}
