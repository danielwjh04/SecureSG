/**
 * `GET /api/scans/:id` handler: the OWNER-scoped detail (the "block report") for
 * one of the caller's own caught scans, so the Activity view can expand a BLOCK
 * or REVIEW row into its full evidence.
 *
 * Authenticated via Bearer key OR session cookie; an anonymous caller is 401
 * (scan details are per-account). The scan must belong to the caller: an id that
 * is unknown, clean (never detail-persisted), or owned by another account is a
 * 404, so the route can never leak a peer's evidence. Requires `env.DB` (503
 * otherwise).
 *
 * Privacy: the returned `content` is the caller's OWN scanned text (truncated at
 * write time) and the evidence is parsed from the stored `result_json`; no other
 * account's data is reachable here.
 */

import type { Database } from '../db/database'
import type {
  InjectionFinding,
  LinkChain,
  ReputationReport,
  RuleFinding,
} from '../schemas/contract'
import { authenticate } from '../middleware/auth'
import { getUserScanDetail, parseScanEvidence } from '../db/scans'
import { log } from '../observability/logger'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_NOT_FOUND = 404
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** A configured scan-detail route's dependencies, assembled by the worker entry. */
export interface ScanDetailDeps {
  readonly db: Database | null
  readonly sessionSecret: string | null
}

/**
 * The 200 body of `GET /api/scans/:id`: the caller's own caught-scan detail, the
 * recorded verdict/source/proof plus the scanned `content` (or `null`) and the
 * structured evidence parsed from the stored `result_json`. Mirrors the admin
 * detail shape minus the owner email (the caller is the owner).
 */
export interface UserScanDetailResponse {
  readonly id: string
  readonly verdict: string
  readonly source: { readonly kind: string; readonly ref: string }
  readonly scannedAt: string
  readonly flagged: number
  readonly headHash: string
  readonly content: string | null
  readonly findings: readonly RuleFinding[]
  readonly chains: readonly LinkChain[]
  readonly injections: readonly InjectionFinding[]
  readonly reputation: readonly ReputationReport[]
}

/**
 * Handle `GET /api/scans/:id`. Authenticates the caller (401 if anonymous), reads
 * the OWNER-scoped detail for `scanId` (404 when unknown / clean / not owned),
 * and returns the full report with the evidence parsed from `result_json`.
 * Requires `env.DB` (503 otherwise).
 *
 * Time complexity: O(1) auth + O(d) in the stored evidence length. Space
 * complexity: O(d).
 *
 * @param request - The inbound request (carries the Bearer key or session cookie).
 * @param deps - The DB seam + session secret assembled by the worker entry.
 * @param scanId - The scan id extracted from the request path by the entry point.
 */
export async function handleScanDetail(
  request: Request,
  deps: ScanDetailDeps,
  scanId: string,
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
      return Response.json(
        { error: 'unauthorized', message: 'authentication required' },
        { status: STATUS_UNAUTHORIZED },
      )
    }

    const detail = await getUserScanDetail(db, scanId, ctx.subject)
    if (detail === null) {
      return Response.json({ error: 'not_found' }, { status: STATUS_NOT_FOUND })
    }
    const evidence = parseScanEvidence(detail.resultJson)
    const body: UserScanDetailResponse = {
      id: detail.id,
      verdict: detail.verdict,
      source: detail.source,
      scannedAt: detail.scannedAt,
      flagged: detail.flagged,
      headHash: detail.headHash,
      content: detail.content,
      findings: evidence.findings,
      chains: evidence.chains,
      injections: evidence.injections,
      reputation: evidence.reputation,
    }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.error('handleScanDetail', 'request failed', { errorClass: className })
    return Response.json({ error: 'scan_detail_failed' }, { status: STATUS_SERVER_ERROR })
  }
}
