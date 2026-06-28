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

import type { Database, Row } from './database'

/** A subject's counters for a single UTC day. */
export interface UsageCounters {
  readonly scans: number
  readonly aiScans: number
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
