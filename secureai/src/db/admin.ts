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

/** Wrap a store fault as an {@link AdminError}, logging the exact class. */
function wrap(operation: string, error: unknown): AdminError {
  const name = error instanceof Error ? error.name : typeof error
  console.error(`[admin] ${operation} failed: ${name}`)
  return new AdminError(`admin aggregate '${operation}' failed`, { cause: error })
}
