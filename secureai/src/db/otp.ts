/**
 * OTP-challenge repository: create / read / attempt-bump / delete short-lived
 * two-factor challenges over the narrow {@link Database} seam.
 *
 * Credential discipline (CLAUDE.md §6): the row stores only the SHA-256 hash of
 * the 6-digit code (see `auth/otp.ts`), never the code. Every write is
 * fail-closed — a store fault throws {@link OtpError} so the verify/resend
 * routes deny rather than silently passing. A missing challenge on read is NOT
 * an error (it resolves to `null`); the route maps that to a generic 401.
 */

import type { Database, Row } from './database'
import { OtpError } from '../errors'

/** A persisted two-factor challenge, as read back for verification. */
export interface OtpChallenge {
  readonly id: string
  readonly userId: string
  readonly codeHash: string
  readonly expiresAt: string
  readonly attempts: number
  readonly createdAt: string
}

/** The fields needed to mint a new challenge row. */
export interface NewOtpChallenge {
  readonly id: string
  readonly userId: string
  readonly codeHash: string
  readonly expiresAt: string
  readonly createdAt: string
}

/** Read a column as a non-empty string, failing closed on a malformed record. */
function requireString(row: Row, column: string): string {
  const value = row[column]
  if (typeof value !== 'string' || value.length === 0) {
    throw new OtpError(`stored challenge record missing string column: ${column}`)
  }
  return value
}

/** Read a column as a non-negative integer, failing closed on a bad record. */
function requireInteger(row: Row, column: string): number {
  const value = row[column]
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new OtpError(`stored challenge record has invalid integer column: ${column}`)
  }
  return value
}

/**
 * Insert a fresh challenge row. The id is a caller-minted `crypto.randomUUID()`
 * and the code hash is the digest of a freshly generated code; only the hash is
 * persisted.
 *
 * Time complexity: O(1) (one insert). Space complexity: O(1).
 *
 * @throws {OtpError} On a database failure.
 */
export async function createChallenge(db: Database, challenge: NewOtpChallenge): Promise<void> {
  try {
    await db.execute(
      'INSERT INTO otp_challenges (id, user_id, code_hash, expires_at, attempts, created_at) ' +
        'VALUES (?, ?, ?, ?, 0, ?)',
      [
        challenge.id,
        challenge.userId,
        challenge.codeHash,
        challenge.expiresAt,
        challenge.createdAt,
      ],
    )
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[otp] createChallenge failed: ${name}`)
    throw new OtpError('failed to create two-factor challenge', { cause: error })
  }
}

/**
 * Resolve a challenge by id, or `null` when none exists (a miss is not an
 * error — the route maps it to a generic 401). A matched-but-corrupt record
 * fails closed via {@link OtpError}.
 *
 * Time complexity: O(1) — primary-key lookup. Space complexity: O(1).
 *
 * @throws {OtpError} If a matched record is structurally corrupt, or on a store
 *   fault other than a miss.
 */
export async function getChallenge(db: Database, id: string): Promise<OtpChallenge | null> {
  let row: Row | null
  try {
    row = await db.queryOne(
      'SELECT id, user_id, code_hash, expires_at, attempts, created_at ' +
        'FROM otp_challenges WHERE id = ?',
      [id],
    )
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[otp] getChallenge failed: ${name}`)
    throw new OtpError('failed to read two-factor challenge', { cause: error })
  }
  if (row === null) {
    return null
  }
  return {
    id: requireString(row, 'id'),
    userId: requireString(row, 'user_id'),
    codeHash: requireString(row, 'code_hash'),
    expiresAt: requireString(row, 'expires_at'),
    attempts: requireInteger(row, 'attempts'),
    createdAt: requireString(row, 'created_at'),
  }
}

/**
 * Atomically bump a challenge's attempt counter by one (a wrong-code attempt).
 * Idempotency is not required here — each verify attempt is a distinct event —
 * but the increment is a single statement so concurrent verifies cannot lose a
 * count.
 *
 * Time complexity: O(1) — primary-key update. Space complexity: O(1).
 *
 * @throws {OtpError} On a database failure.
 */
export async function incrementAttempt(db: Database, id: string): Promise<void> {
  try {
    await db.execute(
      'UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?',
      [id],
    )
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[otp] incrementAttempt failed: ${name}`)
    throw new OtpError('failed to record two-factor attempt', { cause: error })
  }
}

/**
 * Delete a single challenge by id. Called after a successful verify (the code is
 * single-use) so a replay of the same code cannot mint a second session.
 * Idempotent: deleting an already-gone challenge changes zero rows.
 *
 * Time complexity: O(1) — primary-key delete. Space complexity: O(1).
 *
 * @throws {OtpError} On a database failure.
 */
export async function deleteChallenge(db: Database, id: string): Promise<void> {
  try {
    await db.execute('DELETE FROM otp_challenges WHERE id = ?', [id])
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[otp] deleteChallenge failed: ${name}`)
    throw new OtpError('failed to delete two-factor challenge', { cause: error })
  }
}

/**
 * Delete EVERY challenge for a user. Called at the start of a fresh login so a
 * new code invalidates any prior, still-pending codes — there is only ever one
 * live challenge per account. Idempotent: a user with no challenges changes zero
 * rows.
 *
 * Time complexity: O(k) in the user's challenge count (indexed by `user_id`).
 * Space complexity: O(1).
 *
 * @throws {OtpError} On a database failure.
 */
export async function deleteUserChallenges(db: Database, userId: string): Promise<void> {
  try {
    await db.execute('DELETE FROM otp_challenges WHERE user_id = ?', [userId])
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[otp] deleteUserChallenges failed: ${name}`)
    throw new OtpError('failed to invalidate prior two-factor challenges', { cause: error })
  }
}
