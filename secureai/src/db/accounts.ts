/**
 * Accounts repository: user provisioning, API-key minting, and credential
 * resolution over the narrow {@link Database} seam.
 *
 * Credential discipline (CLAUDE.md §6): a raw API key NEVER touches the
 * database. On mint, a high-entropy key is generated, returned to the caller
 * exactly once, and only its hex SHA-256 digest is persisted in `api_keys`.
 * Resolution hashes the presented key and looks up by that digest, so the store
 * never holds anything an attacker could replay.
 */

import type { Database, Row } from './database'
import { AuthError } from '../errors'

/** A persisted account. `tier` gates the paid AI stage. */
export interface User {
  readonly id: string
  readonly email: string
  readonly tier: AccountTier
  readonly stripeCustomerId: string | null
  readonly createdAt: string
}

/** The paid-account tiers, plus the default free tier. */
export type AccountTier = 'free' | 'pro' | 'enterprise'

/** The allowlisted persisted tiers, validated on read (never trust the store). */
const ACCOUNT_TIERS: ReadonlySet<string> = new Set<AccountTier>([
  'free',
  'pro',
  'enterprise',
])

/** The result of {@link createFreeUser}: the new user and its one-time raw key. */
export interface MintedAccount {
  readonly user: User
  readonly apiKey: string
}

/** The identity resolved from a valid API key. */
export interface ResolvedCredential {
  readonly userId: string
  readonly tier: AccountTier
}

/**
 * A user resolved by email for password login. Carries the stored password hash
 * (or `null` for an API-key-only account that never set one) so the route can
 * verify credentials. The hash is internal: it is NEVER returned to a client.
 */
export interface UserCredentialRecord {
  readonly id: string
  readonly email: string
  readonly tier: AccountTier
  readonly passwordHash: string | null
}

/**
 * The public-facing profile for `GET /api/me`. `apiKeyPrefix` is a short,
 * non-secret prefix of the caller's active key (enough to recognize it) — never
 * the full key, which is unrecoverable after mint.
 */
export interface AccountProfile {
  readonly email: string
  readonly tier: AccountTier
  readonly createdAt: string
  readonly apiKeyPrefix: string | null
}

/** Bytes of entropy in a freshly minted raw API key (256-bit). */
const API_KEY_ENTROPY_BYTES = 32

/** Human-facing prefix so a leaked key is recognizable in logs/scans. */
const API_KEY_PREFIX = 'sk_secureai_'

const textEncoder = new TextEncoder()

/**
 * Lowercase-hex SHA-256 of a UTF-8 string, matching the audit chain's hashing
 * approach (`audit/chain.ts`): `sha256(utf8(value))`, hex-encoded. Used to
 * derive the stored credential digest from a raw key.
 *
 * Time complexity: O(n) in `value` length. Space complexity: O(n).
 */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  const view = new Uint8Array(digest)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Generate a high-entropy raw API key: a fixed prefix followed by the
 * lowercase-hex encoding of 32 cryptographically-random bytes (256 bits).
 *
 * Time complexity: O(b) in the entropy byte count. Space complexity: O(b).
 */
function generateApiKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(API_KEY_ENTROPY_BYTES))
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return `${API_KEY_PREFIX}${hex}`
}

/**
 * Coerce a stored `tier` column into the validated {@link AccountTier} union,
 * allowlisting the three legal values. An unrecognized stored tier is a
 * corrupted record and fails closed (CLAUDE.md §6: allowlist all field values).
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @throws {AuthError} If the stored tier is not one of the allowlisted values.
 */
function parseTier(value: unknown): AccountTier {
  if (typeof value === 'string' && ACCOUNT_TIERS.has(value)) {
    return value as AccountTier
  }
  throw new AuthError(`stored account tier is not recognized: ${String(value)}`)
}

/** Read a column as a non-empty string, failing closed on a malformed record. */
function requireString(row: Row, column: string): string {
  const value = row[column]
  if (typeof value !== 'string' || value.length === 0) {
    throw new AuthError(`stored account record missing string column: ${column}`)
  }
  return value
}

/**
 * Insert one fresh active API key for `userId`, returning the raw key.
 *
 * Generates a high-entropy raw key, persists ONLY its SHA-256 digest, and
 * returns the raw key for one-time display. Shared by account provisioning and
 * key rotation so both mint keys identically.
 *
 * Time complexity: O(1) (one insert). Space complexity: O(1).
 *
 * @throws Propagates the underlying database error to the caller, which wraps it.
 */
async function insertApiKey(db: Database, userId: string, createdAt: string): Promise<string> {
  const apiKey = generateApiKey()
  const keyHash = await sha256Hex(apiKey)
  await db.execute(
    'INSERT INTO api_keys (key_sha256, user_id, status, created_at) VALUES (?, ?, ?, ?)',
    [keyHash, userId, 'active', createdAt],
  )
  return apiKey
}

/**
 * Provision a new free-tier user and mint its first API key.
 *
 * Mints a `crypto.randomUUID()` user id and a high-entropy raw key, persists
 * the user and ONLY the key's SHA-256 digest, and returns the user plus the raw
 * key — which is shown to the caller exactly once and is otherwise
 * unrecoverable. The two inserts run as separate statements; the user is
 * inserted first so a key row can never reference a missing user.
 *
 * Time complexity: O(1) (two single-row inserts). Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param email - The account email (caller-validated; UNIQUE in the store).
 * @returns The created {@link User} and its one-time raw API key.
 * @throws {AuthError} If persistence fails (e.g. a duplicate email).
 */
export async function createFreeUser(
  db: Database,
  email: string,
): Promise<MintedAccount> {
  const id = crypto.randomUUID()
  const createdAt = new Date().toISOString()
  const tier: AccountTier = 'free'

  let apiKey: string
  try {
    await db.execute(
      'INSERT INTO users (id, email, tier, stripe_customer_id, created_at) VALUES (?, ?, ?, ?, ?)',
      [id, email, tier, null, createdAt],
    )
    apiKey = await insertApiKey(db, id, createdAt)
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[accounts] createFreeUser failed: ${name}`)
    throw new AuthError('failed to provision account', { cause: error })
  }

  const user: User = {
    id,
    email,
    tier,
    stripeCustomerId: null,
    createdAt,
  }
  return { user, apiKey }
}

/**
 * Provision a new free-tier user that has a password, and mint its first API key.
 *
 * Identical persistence to {@link createFreeUser} (user row first, then key),
 * but also stores the caller-supplied PBKDF2 `passwordHash` on the user so the
 * account can later authenticate by email + password OR by Bearer key. The
 * plaintext password is never seen here — only its already-derived hash.
 *
 * Time complexity: O(1) (two single-row inserts). Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param email - The account email (caller-validated; UNIQUE in the store).
 * @param passwordHash - The serialized PBKDF2 hash from `hashPassword`.
 * @returns The created {@link User} and its one-time raw API key.
 * @throws {AuthError} If persistence fails (e.g. a duplicate email).
 */
export async function createUserWithPassword(
  db: Database,
  email: string,
  passwordHash: string,
): Promise<MintedAccount> {
  const id = crypto.randomUUID()
  const createdAt = new Date().toISOString()
  const tier: AccountTier = 'free'

  let apiKey: string
  try {
    await db.execute(
      'INSERT INTO users (id, email, tier, stripe_customer_id, created_at, password_hash) ' +
        'VALUES (?, ?, ?, ?, ?, ?)',
      [id, email, tier, null, createdAt, passwordHash],
    )
    apiKey = await insertApiKey(db, id, createdAt)
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[accounts] createUserWithPassword failed: ${name}`)
    throw new AuthError('failed to provision account', { cause: error })
  }

  const user: User = { id, email, tier, stripeCustomerId: null, createdAt }
  return { user, apiKey }
}

/**
 * Resolve the identity behind a raw API key, or `null` when the key is unknown
 * or inactive.
 *
 * Hashes the presented key and joins `api_keys` (status `active`) to `users`,
 * returning the owning user id and tier. A missing or revoked key resolves to
 * `null` — this is an authentication MISS, not a fault, and is never thrown
 * (the auth middleware treats a miss as anonymous, CLAUDE.md auth spec).
 *
 * Time complexity: O(1) — primary-key lookup on `key_sha256` + PK join.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param rawKey - The presented bearer key (never persisted).
 * @returns The resolved credential, or `null` on a miss / inactive key.
 * @throws {AuthError} Only if a matched record is structurally corrupt.
 */
export async function findUserByApiKey(
  db: Database,
  rawKey: string,
): Promise<ResolvedCredential | null> {
  const keyHash = await sha256Hex(rawKey)
  const row = await db.queryOne(
    'SELECT u.id AS id, u.tier AS tier ' +
      'FROM api_keys k JOIN users u ON u.id = k.user_id ' +
      "WHERE k.key_sha256 = ? AND k.status = 'active'",
    [keyHash],
  )
  if (row === null) {
    return null
  }
  return { userId: requireString(row, 'id'), tier: parseTier(row['tier']) }
}

/**
 * Set a user's tier by their Stripe customer id (used by the billing webhook).
 *
 * Idempotent: replaying the same `(stripeCustomerId, tier)` leaves the row in
 * the same state. A customer id that matches no user updates zero rows and is
 * a no-op, not an error — the webhook is the source of truth for whether the
 * customer should exist.
 *
 * Time complexity: O(1) — indexed update on `stripe_customer_id`.
 * Space complexity: O(1).
 *
 * @throws {AuthError} On a database failure.
 */
export async function setTierByStripeCustomer(
  db: Database,
  stripeCustomerId: string,
  tier: AccountTier,
): Promise<void> {
  try {
    await db.execute('UPDATE users SET tier = ? WHERE stripe_customer_id = ?', [
      tier,
      stripeCustomerId,
    ])
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[accounts] setTierByStripeCustomer failed: ${name}`)
    throw new AuthError('failed to set tier by Stripe customer', { cause: error })
  }
}

/**
 * Set a user's tier by user id (used by billing and admin flows).
 *
 * Idempotent for the same `(userId, tier)`. Updating an unknown user id is a
 * zero-row no-op rather than an error.
 *
 * Time complexity: O(1) — primary-key update. Space complexity: O(1).
 *
 * @throws {AuthError} On a database failure.
 */
export async function setUserTier(
  db: Database,
  userId: string,
  tier: AccountTier,
): Promise<void> {
  try {
    await db.execute('UPDATE users SET tier = ? WHERE id = ?', [tier, userId])
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[accounts] setUserTier failed: ${name}`)
    throw new AuthError('failed to set user tier', { cause: error })
  }
}

/**
 * Resolve a user by email for password login, or `null` when no account has that
 * email. Returns the id, tier, and stored password hash (`null` for an
 * API-key-only account). A miss is NOT an error — the login route maps both a
 * miss and a bad password to the same generic 401, never revealing which failed.
 *
 * Time complexity: O(1) — unique-index lookup on `email`. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param email - The canonical (trimmed, lowercased) account email.
 * @returns The credential record, or `null` on a miss.
 * @throws {AuthError} If a matched record is structurally corrupt.
 */
export async function findUserByEmail(
  db: Database,
  email: string,
): Promise<UserCredentialRecord | null> {
  const row = await db.queryOne(
    'SELECT id, email, tier, password_hash FROM users WHERE email = ?',
    [email],
  )
  if (row === null) {
    return null
  }
  const passwordHashRaw = row['password_hash']
  const passwordHash =
    typeof passwordHashRaw === 'string' && passwordHashRaw.length > 0 ? passwordHashRaw : null
  return {
    id: requireString(row, 'id'),
    email: requireString(row, 'email'),
    tier: parseTier(row['tier']),
    passwordHash,
  }
}

/**
 * Resolve a user id to its tier, or `null` when the id is unknown. Used by the
 * session-cookie auth path to turn a verified session subject into the metering
 * tier. A miss is `null` (the cookie no longer maps to a live account), not an
 * error — the auth middleware then downgrades to anonymous.
 *
 * Time complexity: O(1) — primary-key lookup. Space complexity: O(1).
 *
 * @throws {AuthError} If the matched record has a corrupt (unrecognized) tier.
 */
export async function findTierByUserId(
  db: Database,
  userId: string,
): Promise<AccountTier | null> {
  const row = await db.queryOne('SELECT tier FROM users WHERE id = ?', [userId])
  if (row === null) {
    return null
  }
  return parseTier(row['tier'])
}

/**
 * Read the public {@link AccountProfile} for `userId` (for `GET /api/me`), or
 * `null` when the id is unknown. `apiKeyPrefix` is the non-secret brand prefix
 * when the account has at least one ACTIVE key, else `null` — it never exposes
 * key material (the full key is unrecoverable after mint).
 *
 * Time complexity: O(1) — primary-key read plus one indexed key-existence probe.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param userId - The account id (already authenticated).
 * @returns The profile, or `null` if the user row is gone.
 * @throws {AuthError} If a matched record is structurally corrupt.
 */
export async function getAccountProfile(
  db: Database,
  userId: string,
): Promise<AccountProfile | null> {
  const row = await db.queryOne(
    'SELECT email, tier, created_at FROM users WHERE id = ?',
    [userId],
  )
  if (row === null) {
    return null
  }
  const activeKey = await db.queryOne(
    "SELECT 1 AS present FROM api_keys WHERE user_id = ? AND status = 'active' LIMIT 1",
    [userId],
  )
  return {
    email: requireString(row, 'email'),
    tier: parseTier(row['tier']),
    createdAt: requireString(row, 'created_at'),
    apiKeyPrefix: activeKey === null ? null : API_KEY_PREFIX,
  }
}

/**
 * Deactivate (revoke) every currently-active API key for `userId`. Used by key
 * rotation so the caller's previous key(s) stop authenticating the moment the
 * new one is minted. Idempotent: a user with no active keys changes zero rows.
 *
 * Time complexity: O(k) in the user's active-key count (indexed by `user_id`).
 * Space complexity: O(1).
 *
 * @throws {AuthError} On a database failure.
 */
export async function deactivateApiKeys(db: Database, userId: string): Promise<void> {
  try {
    await db.execute(
      "UPDATE api_keys SET status = 'revoked' WHERE user_id = ? AND status = 'active'",
      [userId],
    )
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[accounts] deactivateApiKeys failed: ${name}`)
    throw new AuthError('failed to revoke API keys', { cause: error })
  }
}

/**
 * Rotate a user's API key: revoke every active key, then mint and persist a
 * fresh one, returning the new raw key for one-time display.
 *
 * Revoke-then-mint ordering means that even if the mint were to fail, the caller
 * is left with no active key (fail-closed) rather than two. The new key's raw
 * value is returned exactly once and is otherwise unrecoverable (only its digest
 * is stored).
 *
 * Time complexity: O(k) (one revoke over active keys + one insert).
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param userId - The account whose key is rotated (already authenticated).
 * @returns The new one-time raw API key.
 * @throws {AuthError} On a database failure.
 */
export async function rotateApiKey(db: Database, userId: string): Promise<string> {
  await deactivateApiKeys(db, userId)
  try {
    return await insertApiKey(db, userId, new Date().toISOString())
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[accounts] rotateApiKey failed: ${name}`)
    throw new AuthError('failed to mint a new API key', { cause: error })
  }
}
