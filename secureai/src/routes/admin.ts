/**
 * `GET /api/admin/overview` handler — the owner-only sitewide analytics overview:
 * total accounts, the tier breakdown, the last-30-days signup series, sitewide
 * verdict/indicator totals, and the active-subscription count.
 *
 * Gating is strict (CLAUDE.md §6, fail-closed): authenticated via Bearer key OR
 * session cookie; an anonymous caller is 401, and an authenticated caller whose
 * email is NOT in `config.adminEmails` is 403. Only an admin reaches the
 * aggregate reads. Requires `env.DB` (503 otherwise). The signup-window lower
 * bound and `generatedAt` stamp are computed here, at the edge, from a single
 * `now` so the read is deterministic per request.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { SignupDay, TierCounts, UsageTotals } from '../db/admin'
import { ScannerError } from '../errors'
import { authenticate } from '../middleware/auth'
import { getAccountProfile } from '../db/accounts'
import {
  activeSubscriptions,
  countUsers,
  signupsByDay,
  usageTotals,
  usersByTier,
} from '../db/admin'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_FORBIDDEN = 403
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** Inclusive signup-window length in days (today plus the 29 prior days). */
const SIGNUP_WINDOW_DAYS = 30
/** Milliseconds in one day, for the window lower-bound computation. */
const MS_PER_DAY = 86_400_000

/** A configured admin route's dependencies, assembled by the worker entry. */
export interface AdminDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
  readonly config: ScannerConfig
}

/** The 200 body of `GET /api/admin/overview`. */
export interface AdminOverview {
  readonly totalUsers: number
  readonly usersByTier: TierCounts
  readonly signupsDaily: readonly SignupDay[]
  readonly usageTotals: UsageTotals
  readonly activeSubscriptions: number
  /** ISO timestamp the edge stamped the response; outside any hash. */
  readonly generatedAt: string
}

/**
 * Compute the inclusive UTC `YYYY-MM-DD` lower bound of the signup window:
 * `now - (SIGNUP_WINDOW_DAYS - 1)` days. With 30 days the window spans today and
 * the 29 days before it.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function windowStart(now: Date): string {
  const start = new Date(now.getTime() - (SIGNUP_WINDOW_DAYS - 1) * MS_PER_DAY)
  return start.toISOString().slice(0, 10)
}

/** Build a 401 with the shared unauthenticated body. */
function unauthorized(): Response {
  return Response.json(
    { error: 'unauthorized', message: 'authentication required' },
    { status: STATUS_UNAUTHORIZED },
  )
}

/**
 * Handle `GET /api/admin/overview`. Authenticates the caller, requires the
 * resolved profile email to be in `config.adminEmails` (403 otherwise), then
 * returns the sitewide {@link AdminOverview}. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(r) in the active signup days in the window (every other
 * metric is an O(1) aggregate). Space complexity: O(r).
 */
export async function handleAdminOverview(
  request: Request,
  deps: AdminDeps,
): Promise<Response> {
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
      return unauthorized()
    }
    const profile = await getAccountProfile(db, ctx.subject)
    if (profile === null) {
      // Resolved to a user id that no longer exists — treat as unauthenticated.
      return unauthorized()
    }
    if (!deps.config.adminEmails.has(profile.email.toLowerCase())) {
      return Response.json({ error: 'forbidden' }, { status: STATUS_FORBIDDEN })
    }

    const now = new Date()
    const [totalUsers, tierCounts, signupsDaily, totals, subscriptions] = await Promise.all([
      countUsers(db),
      usersByTier(db),
      signupsByDay(db, windowStart(now)),
      usageTotals(db),
      activeSubscriptions(db),
    ])

    const body: AdminOverview = {
      totalUsers,
      usersByTier: tierCounts,
      signupsDaily,
      usageTotals: totals,
      activeSubscriptions: subscriptions,
      generatedAt: now.toISOString(),
    }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.error(`[handleAdminOverview] ${className}`)
    const status = error instanceof ScannerError ? STATUS_SERVER_ERROR : STATUS_SERVER_ERROR
    return Response.json({ error: 'admin_overview_failed' }, { status })
  }
}
