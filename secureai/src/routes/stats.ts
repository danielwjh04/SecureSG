/**
 * `GET /api/stats` handler — the authenticated caller's protection stats over the
 * last 30 days: totals plus an ascending per-day series of verdict/indicator
 * counters, for the dashboard's monthly summary.
 *
 * Authenticated via Bearer key OR session cookie; an anonymous caller is 401
 * (stats are per-account). Requires `env.DB` (503 otherwise). The window lower
 * bound is computed here, at the edge, from a single `now` so the read is
 * deterministic per request.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import { ScannerError } from '../errors'
import { authenticate } from '../middleware/auth'
import { getStats } from '../db/usage'
import { log } from '../observability/logger'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** Inclusive window length in days (today plus the 29 prior days). */
const WINDOW_DAYS = 30
/** Milliseconds in one day, for the window lower-bound computation. */
const MS_PER_DAY = 86_400_000

/** A configured stats route's dependencies, assembled by the worker entry. */
export interface StatsDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
  readonly config: ScannerConfig
}

/**
 * Compute the inclusive UTC `YYYY-MM-DD` lower bound of the stats window:
 * `now - (WINDOW_DAYS - 1)` days. With `WINDOW_DAYS = 30` the window spans today
 * and the 29 days before it.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function windowStart(now: Date): string {
  const start = new Date(now.getTime() - (WINDOW_DAYS - 1) * MS_PER_DAY)
  return start.toISOString().slice(0, 10)
}

/**
 * Handle `GET /api/stats`. Authenticates the caller (401 if anonymous), reads the
 * last-{@link WINDOW_DAYS}-days protection stats for its subject, and returns
 * `{ tier, totals, daily }`. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(r) in active days in the window. Space complexity: O(r).
 */
export async function handleStats(request: Request, deps: StatsDeps): Promise<Response> {
  if (deps.db === null) {
    return Response.json(
      { error: 'service_unavailable', message: 'account store is not configured' },
      { status: STATUS_SERVICE_UNAVAILABLE },
    )
  }
  const db = deps.db
  try {
    const ctx = await authenticate(request, db, deps.sessionSecret ?? undefined)
    if (ctx.tier === 'anonymous') {
      return Response.json(
        { error: 'unauthorized', message: 'authentication required' },
        { status: STATUS_UNAUTHORIZED },
      )
    }

    const sinceDay = windowStart(new Date())
    const stats = await getStats(db, ctx.subject, sinceDay)

    return Response.json(
      { tier: ctx.tier, totals: stats.totals, daily: stats.daily },
      { status: STATUS_OK },
    )
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.error('handleStats', 'request failed', { errorClass: className })
    const status = error instanceof ScannerError ? STATUS_SERVER_ERROR : STATUS_SERVER_ERROR
    return Response.json({ error: 'stats_failed' }, { status })
  }
}
