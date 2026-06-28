/**
 * Admin analytics repository: sitewide aggregate reads over the narrow
 * {@link Database} seam, for the owner-only analytics dashboard.
 *
 * Every read is a single aggregate query (COUNT / SUM / GROUP BY) so a metric is
 * one round trip, never a row-by-row scan in application code. Each function
 * fails closed: a store fault is wrapped in {@link AdminError} so the admin route
 * maps it to HTTP 500 rather than leaking an internal error.
 */

import type { Database, Row } from './database'
import type { AssignableRole } from '../auth/roles'
import { AdminError } from '../errors'

/** Per-tier account counts. Absent tiers read as 0, never undefined. */
export interface TierCounts {
  readonly free: number
  readonly pro: number
  readonly enterprise: number
}

/** One calendar day's signup count, `day` an ISO `YYYY-MM-DD` string. */
export interface SignupDay {
  readonly day: string
  readonly count: number
}

/** Sitewide verdict + indicator totals summed across the usage table. */
export interface UsageTotals {
  readonly scans: number
  readonly allows: number
  readonly reviews: number
  readonly blocks: number
  readonly flagged: number
}

/**
 * One account row in the members directory: identity, tier, the RAW stored role
 * column, signup time, and that account's lifetime scan count. The route layer
 * derives the EFFECTIVE role (owners overridden to `owner`) from `role` + the
 * email allowlist; the repository returns the column verbatim so the same read
 * serves both the gate and the display.
 */
export interface MemberRow {
  readonly id: string
  readonly email: string
  readonly tier: string
  /** The raw `users.role` column value (not yet owner-overridden). */
  readonly role: string
  readonly createdAt: string
  /** Sum of `usage.scans` across every day for this account (0 if none). */
  readonly scans: number
}

/** The three persisted account tiers, used to densify the tier breakdown. */
const TIERS = ['free', 'pro', 'enterprise'] as const

/**
 * Coerce an aggregate column to a non-negative integer, defaulting to 0. A
 * `COUNT`/`SUM` over zero rows can come back `null` (SUM) or `0` (COUNT); both
 * read as 0, so a metric is never `NaN` or negative.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function readCount(row: Row | null, column: string): number {
  if (row === null) {
    return 0
  }
  const value = row[column]
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? Math.trunc(value)
    : 0
}

/**
 * Count all registered accounts.
 *
 * Time complexity: O(1) — single `COUNT(*)` aggregate. Space complexity: O(1).
 *
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function countUsers(db: Database): Promise<number> {
  try {
    const row = await db.queryOne('SELECT COUNT(*) AS total FROM users', [])
    return readCount(row, 'total')
  } catch (error: unknown) {
    throw wrap('countUsers', error)
  }
}

/**
 * Count accounts grouped by tier, densified to the three known tiers so a tier
 * with no accounts reads as 0 (an unknown stored tier is simply ignored — the
 * breakdown only reports the allowlisted tiers).
 *
 * Time complexity: O(t) in the distinct tiers returned. Space complexity: O(1).
 *
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function usersByTier(db: Database): Promise<TierCounts> {
  try {
    const rows = await db.queryAll(
      'SELECT tier, COUNT(*) AS count FROM users GROUP BY tier',
      [],
    )
    const counts: Record<string, number> = {}
    for (const row of rows) {
      const tier = typeof row['tier'] === 'string' ? row['tier'] : ''
      if (tier.length > 0) {
        counts[tier] = readCount(row, 'count')
      }
    }
    return {
      free: counts[TIERS[0]] ?? 0,
      pro: counts[TIERS[1]] ?? 0,
      enterprise: counts[TIERS[2]] ?? 0,
    }
  } catch (error: unknown) {
    throw wrap('usersByTier', error)
  }
}

/**
 * Daily signup counts from `sinceDay` (inclusive) onward, ascending by day. Days
 * with no signups are simply absent (the dashboard zero-fills gaps), so the
 * series is sparse. `day` is `date(created_at)` — the UTC calendar day of the
 * `created_at` ISO timestamp.
 *
 * Time complexity: O(r) in the active days in the window. Space complexity: O(r).
 *
 * @param sinceDay - Inclusive lower-bound UTC `YYYY-MM-DD` for the window.
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function signupsByDay(
  db: Database,
  sinceDay: string,
): Promise<SignupDay[]> {
  try {
    const rows = await db.queryAll(
      'SELECT date(created_at) AS day, COUNT(*) AS count FROM users ' +
        'WHERE date(created_at) >= ? GROUP BY day ORDER BY day ASC',
      [sinceDay],
    )
    const series: SignupDay[] = []
    for (const row of rows) {
      const day = typeof row['day'] === 'string' ? row['day'] : ''
      if (day.length > 0) {
        series.push({ day, count: readCount(row, 'count') })
      }
    }
    return series
  } catch (error: unknown) {
    throw wrap('signupsByDay', error)
  }
}

/**
 * Sum every verdict/indicator counter across the whole usage table. A `SUM` over
 * zero rows is `null`, which {@link readCount} coerces to 0, so an empty table
 * reports all-zero totals rather than nulls.
 *
 * Time complexity: O(1) — single multi-`SUM` aggregate. Space complexity: O(1).
 *
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function usageTotals(db: Database): Promise<UsageTotals> {
  try {
    const row = await db.queryOne(
      'SELECT SUM(scans) AS scans, SUM(allows) AS allows, SUM(reviews) AS reviews, ' +
        'SUM(blocks) AS blocks, SUM(flagged) AS flagged FROM usage',
      [],
    )
    return {
      scans: readCount(row, 'scans'),
      allows: readCount(row, 'allows'),
      reviews: readCount(row, 'reviews'),
      blocks: readCount(row, 'blocks'),
      flagged: readCount(row, 'flagged'),
    }
  } catch (error: unknown) {
    throw wrap('usageTotals', error)
  }
}

/**
 * Count subscriptions whose status is live (`active` or `trialing`) — the count
 * of currently-paying (or trialing) Pro accounts.
 *
 * Time complexity: O(1) — single filtered `COUNT(*)`. Space complexity: O(1).
 *
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function activeSubscriptions(db: Database): Promise<number> {
  try {
    const row = await db.queryOne(
      "SELECT COUNT(*) AS count FROM subscriptions WHERE status IN ('active', 'trialing')",
      [],
    )
    return readCount(row, 'count')
  } catch (error: unknown) {
    throw wrap('activeSubscriptions', error)
  }
}

/**
 * Read a page of the members directory: `limit` accounts from `offset`, ordered
 * oldest-first (stable signup order), each with its summed lifetime scan count.
 *
 * The scan total is a LEFT JOIN + `SUM` over `usage` keyed by the user id as the
 * `subject`, so an account that has never scanned still appears with `scans = 0`
 * (an INNER join would silently drop zero-scan accounts). `GROUP BY` collapses
 * the per-day usage rows to one total per user. The role column is returned
 * verbatim; the route derives the effective role.
 *
 * Time complexity: O(p log p) for the ordered page of size p = `limit` (the
 * index on `created_at` is unavailable, so SQLite sorts the page). Space
 * complexity: O(p).
 *
 * @param db - The persistence seam.
 * @param limit - Max rows to return (caller-clamped to a sane bound).
 * @param offset - Rows to skip (caller-clamped to non-negative).
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function listMembers(
  db: Database,
  limit: number,
  offset: number,
): Promise<MemberRow[]> {
  try {
    const rows = await db.queryAll(
      'SELECT u.id AS id, u.email AS email, u.tier AS tier, u.role AS role, ' +
        'u.created_at AS created_at, ' +
        'COALESCE(SUM(g.scans), 0) AS scans ' +
        'FROM users u LEFT JOIN usage g ON g.subject = u.id ' +
        'GROUP BY u.id ' +
        'ORDER BY u.created_at ASC, u.id ASC ' +
        'LIMIT ? OFFSET ?',
      [limit, offset],
    )
    const members: MemberRow[] = []
    for (const row of rows) {
      members.push({
        id: requireString(row, 'id'),
        email: requireString(row, 'email'),
        tier: requireString(row, 'tier'),
        role: typeof row['role'] === 'string' ? row['role'] : '',
        createdAt: requireString(row, 'created_at'),
        scans: readCount(row, 'scans'),
      })
    }
    return members
  } catch (error: unknown) {
    throw wrap('listMembers', error)
  }
}

/**
 * Count all registered accounts (the total for the members directory's
 * pagination). Distinct from {@link countUsers} only in intent; both are a
 * single `COUNT(*)`.
 *
 * Time complexity: O(1) — single `COUNT(*)` aggregate. Space complexity: O(1).
 *
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function countMembers(db: Database): Promise<number> {
  try {
    const row = await db.queryOne('SELECT COUNT(*) AS total FROM users', [])
    return readCount(row, 'total')
  } catch (error: unknown) {
    throw wrap('countMembers', error)
  }
}

/**
 * Set an account's granted role by user id (used by the owner-only role-change
 * endpoint). The `role` is the already-validated {@link AssignableRole}
 * ({`member`, `admin`}); `owner` is never written here — it is conferred by the
 * email allowlist, not the column.
 *
 * Idempotent for the same `(userId, role)`. Returns the row-change count so the
 * route can distinguish a real update (1) from an unknown user id (0 → 404)
 * without a follow-up read.
 *
 * Time complexity: O(1) — primary-key update. Space complexity: O(1).
 *
 * @throws {AdminError} On a database failure (fail-closed).
 */
export async function setUserRole(
  db: Database,
  userId: string,
  role: AssignableRole,
): Promise<number> {
  try {
    const result = await db.execute('UPDATE users SET role = ? WHERE id = ?', [role, userId])
    return result.changes
  } catch (error: unknown) {
    throw wrap('setUserRole', error)
  }
}

/** Read a column as a non-empty string, failing closed on a malformed record. */
function requireString(row: Row, column: string): string {
  const value = row[column]
  if (typeof value !== 'string' || value.length === 0) {
    throw new AdminError(`members row missing string column: ${column}`)
  }
  return value
}

/** Wrap a store fault as an {@link AdminError}, logging the exact class. */
function wrap(operation: string, error: unknown): AdminError {
  const name = error instanceof Error ? error.name : typeof error
  console.error(`[admin] ${operation} failed: ${name}`)
  return new AdminError(`admin aggregate '${operation}' failed`, { cause: error })
}
