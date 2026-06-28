/**
 * `GET /api/scans/recent` handler — the authenticated caller's most recent
 * scans, newest first, for the dashboard's recent-activity panel.
 *
 * Authenticated via Bearer key OR session cookie; an anonymous caller is 401
 * (recent scans are per-account). Requires `env.DB` (503 otherwise). The
 * `?limit` query param is Zod-validated (default 3, max 20) so the page size is
 * always bounded; a malformed limit is a 422 at the boundary.
 *
 * Privacy: each entry surfaces only the source LABEL (a URL or `paste`) the scan
 * route persisted — never the scanned content — plus the proof head hash that
 * ties the entry back to its tamper-evident chain.
 */

import type { Database } from '../db/database'
import { ScannerError } from '../errors'
import { authenticate } from '../middleware/auth'
import { listRecentScans } from '../db/scans'
import { recentScansLimitSchema } from '../schemas/validate'
import { log } from '../observability/logger'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 422
const STATUS_UNAUTHORIZED = 401
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** A configured recent-scans route's dependencies, assembled by the worker entry. */
export interface RecentScansDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
}

/**
 * Handle `GET /api/scans/recent`. Validates `?limit`, authenticates the caller
 * (401 if anonymous), reads its newest-first recent scans capped at `limit`, and
 * returns `{ scans: [...] }`. Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(limit) in the rows read. Space complexity: O(limit).
 */
export async function handleRecentScans(
  request: Request,
  deps: RecentScansDeps,
): Promise<Response> {
  if (deps.db === null) {
    return Response.json(
      { error: 'service_unavailable', message: 'account store is not configured' },
      { status: STATUS_SERVICE_UNAVAILABLE },
    )
  }
  const db = deps.db

  const url = new URL(request.url)
  const parsedLimit = recentScansLimitSchema.safeParse(url.searchParams.get('limit') ?? undefined)
  if (!parsedLimit.success) {
    return Response.json(
      { error: 'invalid_limit', message: 'limit must be a positive integer' },
      { status: STATUS_BAD_REQUEST },
    )
  }
  const limit = parsedLimit.data

  try {
    const ctx = await authenticate(request, db, deps.sessionSecret ?? undefined)
    if (ctx.tier === 'anonymous') {
      return Response.json(
        { error: 'unauthorized', message: 'authentication required' },
        { status: STATUS_UNAUTHORIZED },
      )
    }

    const scans = await listRecentScans(db, ctx.subject, limit)
    return Response.json({ scans }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.error('handleRecentScans', 'request failed', { errorClass: className })
    const status = error instanceof ScannerError ? STATUS_SERVER_ERROR : STATUS_SERVER_ERROR
    return Response.json({ error: 'recent_scans_failed' }, { status })
  }
}
