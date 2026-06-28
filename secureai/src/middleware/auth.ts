/**
 * Request authentication: resolve a caller to a metering {@link AuthContext}.
 *
 * The contract is deliberately permissive on the credential and strict on the
 * outcome: a valid `Authorization: Bearer <key>` resolves to that user's id and
 * tier; the ABSENCE of a key, OR a present-but-unknown key, resolves to an
 * anonymous context keyed by client IP. An unknown key is NOT an error — it is
 * simply unauthenticated, so a typo or a revoked key downgrades to the anonymous
 * cap rather than failing the request. `authenticate` therefore never throws on
 * a bad key; it only propagates a fault if the underlying store is corrupt.
 */

import type { Database } from '../db/database'
import type { AccountTier } from '../db/accounts'
import { findUserByApiKey } from '../db/accounts'

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

/**
 * Resolve a request to an {@link AuthContext}.
 *
 * Reads `Authorization: Bearer <key>`; a key that resolves to an active account
 * yields `{ subject: userId, tier }`. No key, a malformed header, or an unknown
 * key all yield `{ subject: 'anon:' + clientIp, tier: 'anonymous' }` — a bad key
 * is anonymous, never an error.
 *
 * Time complexity: O(1) — at most one indexed credential lookup.
 * Space complexity: O(1).
 *
 * @param request - The inbound request.
 * @param db - The persistence seam used to resolve the key.
 * @returns The caller's metering identity and tier.
 * @throws {AuthError} Only if a matched credential record is structurally
 *   corrupt (propagated from {@link findUserByApiKey}); never on a bad key.
 */
export async function authenticate(
  request: Request,
  db: Database,
): Promise<AuthContext> {
  const rawKey = extractBearerKey(request)
  if (rawKey === null) {
    return anonymousContext(request)
  }
  const credential = await findUserByApiKey(db, rawKey)
  if (credential === null) {
    return anonymousContext(request)
  }
  return { subject: credential.userId, tier: credential.tier }
}
