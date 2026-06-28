/**
 * Pure helpers for the protection-stats dashboard: turning a sparse daily series
 * (only days with activity) into a dense, zero-filled window the trend chart can
 * plot without gaps.
 */

import type { StatsDay } from '../api/types'

/** Format a Date as an ISO calendar day (`YYYY-MM-DD`) in UTC. */
function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10)
}

/** An empty day's tallies, used for days the server returned no row for. */
function emptyDay(day: string): StatsDay {
  return { day, scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 }
}

/**
 * Expand a sparse daily series into a dense `days`-long window ending today
 * (inclusive), in chronological order, zero-filling any missing calendar day.
 * Days returned by the server that fall outside the window are dropped.
 *
 * Indexing the input by its `day` key makes each lookup O(1), so the whole pass
 * is O(days + n) over the window length and the input rows.
 *
 * Time complexity: O(days + n). Space complexity: O(days + n).
 *
 * @param daily The server's (possibly sparse) per-day rows.
 * @param days The window length in days, ending today.
 * @param now The reference "today"; injectable so the result is deterministic.
 */
export function zeroFillDaily(
  daily: readonly StatsDay[],
  days: number,
  now: Date = new Date(),
): StatsDay[] {
  const byDay = new Map<string, StatsDay>()
  for (const row of daily) byDay.set(row.day, row)

  const filled: StatsDay[] = []
  // Walk from the oldest day in the window to today so the series is ordered.
  const start = new Date(now)
  start.setUTCDate(start.getUTCDate() - (days - 1))
  for (let offset = 0; offset < days; offset += 1) {
    const date = new Date(start)
    date.setUTCDate(start.getUTCDate() + offset)
    const key = isoDay(date)
    filled.push(byDay.get(key) ?? emptyDay(key))
  }
  return filled
}
