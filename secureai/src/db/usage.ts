/**
 * Per-subject, per-day usage metering over the narrow {@link Database} seam.
 *
 * A `subject` is a user id for authenticated callers, or `anon:<ip>` for
 * unauthenticated ones. A `day` is a UTC `YYYY-MM-DD` string supplied BY THE
 * CALLER — never computed in here — so metering is deterministic and the cap
 * checks are testable without mocking the clock.
 *
 * `scans` counts every metered scan; `ai_scans` counts the subset that invoked
 * the paid AI stage, so cost can be attributed per subject.
 */

import type { BatchStatement, Database, Row } from './database'
import type { Verdict } from '../schemas/contract'

/** A subject's counters for a single UTC day. */
export interface UsageCounters {
  readonly scans: number
  readonly aiScans: number
}

/** A subject's per-verdict + indicator counters for one UTC day. */
export interface VerdictCounters {
  readonly scans: number
  readonly allows: number
  readonly reviews: number
  readonly blocks: number
  readonly flagged: number
}

/** One day's protection stats: the day string plus its {@link VerdictCounters}. */
export interface DailyStat extends VerdictCounters {
  readonly day: string
}

/** Aggregated protection stats over a window: totals plus the per-day series. */
export interface ProtectionStats {
  readonly totals: VerdictCounters
  readonly daily: readonly DailyStat[]
}

/**
 * Map a {@link Verdict} to the `usage` column it increments. Total and exhaustive
 * over the three-state enum (a new verdict would be a compile error), so a verdict
 * can never silently fail to be counted.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function columnForVerdict(verdict: Verdict): 'allows' | 'reviews' | 'blocks' {
  switch (verdict) {
    case 'ALLOW':
      return 'allows'
    case 'HUMAN_APPROVAL_REQUIRED':
      return 'reviews'
    case 'BLOCK':
      return 'blocks'
  }
}

/** Whether an increment also consumed the paid AI stage. */
export interface IncrementOptions {
  readonly ai: boolean
}

/** Zero counters, returned when a `(subject, day)` row does not yet exist. */
const ZERO_USAGE: UsageCounters = { scans: 0, aiScans: 0 }

/** Coerce a stored counter column to a non-negative integer, defaulting to 0. */
function readCount(row: Row, column: string): number {
  const value = row[column]
  return typeof value === 'number' && Number.isInteger(value) && value >= 0
    ? value
    : 0
}

/**
 * Read a subject's counters for a given UTC day. A subject with no activity that
 * day returns {@link ZERO_USAGE} rather than `null`, so cap checks need no
 * null-handling at the call site.
 *
 * Time complexity: O(1) — composite primary-key lookup on `(subject, day)`.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param subject - User id, or `anon:<ip>`.
 * @param day - UTC `YYYY-MM-DD` string, supplied by the caller.
 * @returns The subject's counters for that day (zeros when none recorded).
 */
export async function getUsage(
  db: Database,
  subject: string,
  day: string,
): Promise<UsageCounters> {
  const row = await db.queryOne(
    'SELECT scans, ai_scans FROM usage WHERE subject = ? AND day = ?',
    [subject, day],
  )
  if (row === null) {
    return ZERO_USAGE
  }
  return { scans: readCount(row, 'scans'), aiScans: readCount(row, 'ai_scans') }
}

/**
 * Atomically increment a subject's counters for a UTC day.
 *
 * Implemented as a single `INSERT ... ON CONFLICT (subject, day) DO UPDATE`
 * upsert, so the read-modify-write is one atomic statement (no lost-update race
 * between concurrent requests) and the first scan of the day creates the row.
 * `scans` always rises by 1; `ai_scans` rises by 1 only when `options.ai` is
 * true.
 *
 * Time complexity: O(1) — single upsert on the composite primary key.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param subject - User id, or `anon:<ip>`.
 * @param day - UTC `YYYY-MM-DD` string, supplied by the caller.
 * @param options - Whether this scan consumed the paid AI stage.
 */
export async function incrementUsage(
  db: Database,
  subject: string,
  day: string,
  options: IncrementOptions,
): Promise<void> {
  const aiDelta = options.ai ? 1 : 0
  await db.execute(
    'INSERT INTO usage (subject, day, scans, ai_scans) VALUES (?, ?, 1, ?) ' +
      'ON CONFLICT (subject, day) DO UPDATE SET ' +
      'scans = scans + 1, ai_scans = ai_scans + ?',
    [subject, day, aiDelta, aiDelta],
  )
}

/**
 * Atomically record one scan's outcome: bump `scans`, the column matching the
 * scan {@link Verdict} (allows / reviews / blocks), `flagged` by the count of
 * flagged reputation indicators, and `ai_scans` when the paid AI stage ran.
 *
 * This is the single metering write the scan/guard routes make per successful
 * scan, replacing the prior `incrementUsage` call so the protection-stats counters
 * stay consistent with `scans` (every counted scan contributes to exactly one
 * verdict column). Implemented as one `INSERT ... ON CONFLICT DO UPDATE` upsert,
 * so the read-modify-write is atomic and the first scan of the day creates the
 * row.
 *
 * The verdict column is chosen from a fixed allowlist ({@link columnForVerdict}),
 * never interpolated from caller input, so the SQL is not injection-prone.
 *
 * Time complexity: O(1) — single upsert on the composite primary key.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param subject - User id, or `anon:<ip>`.
 * @param day - UTC `YYYY-MM-DD` string, supplied by the caller.
 * @param verdict - The scan's overall verdict (selects which column to bump).
 * @param flaggedCount - Number of flagged reputation indicators in this scan.
 * @param options - Whether this scan consumed the paid AI stage.
 */
export async function recordVerdict(
  db: Database,
  subject: string,
  day: string,
  verdict: Verdict,
  flaggedCount: number,
  options: IncrementOptions,
): Promise<void> {
  const statement = verdictStatement(subject, day, verdict, flaggedCount, options)
  await db.execute(statement.sql, statement.params)
}

/**
 * Build the metering upsert {@link BatchStatement} {@link recordVerdict} runs,
 * exposed so the scan write path can include it in an atomic {@link Database.batch}
 * alongside the history/detail inserts. Produces byte-identical SQL to the
 * standalone path (the verdict column is chosen from a fixed allowlist, never
 * interpolated from caller input).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function verdictStatement(
  subject: string,
  day: string,
  verdict: Verdict,
  flaggedCount: number,
  options: IncrementOptions,
): BatchStatement {
  const column = columnForVerdict(verdict)
  const flagged = Number.isInteger(flaggedCount) && flaggedCount >= 0 ? flaggedCount : 0
  const aiDelta = options.ai ? 1 : 0
  return {
    sql:
      `INSERT INTO usage (subject, day, scans, ai_scans, allows, reviews, blocks, flagged) ` +
      `VALUES (?, ?, 1, ?, ?, ?, ?, ?) ` +
      `ON CONFLICT (subject, day) DO UPDATE SET ` +
      `scans = scans + 1, ai_scans = ai_scans + ?, ${column} = ${column} + 1, ` +
      `flagged = flagged + ?`,
    params: [
      subject,
      day,
      aiDelta,
      column === 'allows' ? 1 : 0,
      column === 'reviews' ? 1 : 0,
      column === 'blocks' ? 1 : 0,
      flagged,
      aiDelta,
      flagged,
    ],
  }
}

/** Coerce a stored counter to a non-negative integer, defaulting to 0. */
function statCount(row: Row, column: string): number {
  const value = row[column]
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0
}

/**
 * Read a subject's protection stats from `sinceDay` (inclusive) onward: the
 * per-day series ascending by day, plus the summed totals.
 *
 * One indexed range read over the `(subject, day)` primary key returns the days
 * with activity; days with no scans are simply absent (the frontend zero-fills
 * gaps). Totals are summed in a single pass over the returned rows.
 *
 * Time complexity: O(r) in the number of active days in the window.
 * Space complexity: O(r).
 *
 * @param db - The persistence seam.
 * @param subject - User id, or `anon:<ip>`.
 * @param sinceDay - Inclusive lower-bound UTC `YYYY-MM-DD` for the window.
 * @returns The subject's totals and ascending per-day series.
 */
export async function getStats(
  db: Database,
  subject: string,
  sinceDay: string,
): Promise<ProtectionStats> {
  const rows = await db.queryAll(
    'SELECT day, scans, allows, reviews, blocks, flagged FROM usage ' +
      'WHERE subject = ? AND day >= ? ORDER BY day ASC',
    [subject, sinceDay],
  )
  const daily: DailyStat[] = []
  let scans = 0
  let allows = 0
  let reviews = 0
  let blocks = 0
  let flagged = 0
  for (const row of rows) {
    const day = typeof row['day'] === 'string' ? (row['day'] as string) : ''
    if (day.length === 0) {
      continue
    }
    const stat: DailyStat = {
      day,
      scans: statCount(row, 'scans'),
      allows: statCount(row, 'allows'),
      reviews: statCount(row, 'reviews'),
      blocks: statCount(row, 'blocks'),
      flagged: statCount(row, 'flagged'),
    }
    daily.push(stat)
    scans += stat.scans
    allows += stat.allows
    reviews += stat.reviews
    blocks += stat.blocks
    flagged += stat.flagged
  }
  return { totals: { scans, allows, reviews, blocks, flagged }, daily }
}
