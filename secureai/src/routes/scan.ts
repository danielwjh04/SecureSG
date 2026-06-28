/**
 * `POST /api/scan` handler.
 *
 * Validates the body with Zod at the edge, builds the real clients when their
 * capabilities are present (Workers AI inference; the reputation client lands
 * with the indicator feed), stamps a response timestamp OUTSIDE the hashed
 * proof, runs the pure {@link runScan} orchestrator, and maps the typed error
 * hierarchy to HTTP status codes. Never a silent 200 on failure.
 */

import type { Env, ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { ScanRequest, ScanResult } from '../schemas/contract'
import {
  ConfigError,
  InferenceError,
  ParseError,
  QuotaExceededError,
  RedirectResolutionError,
  ReputationError,
  ScannerError,
  SourceResolutionError,
} from '../errors'
import { runScan } from '../scanner/runScan'
import { buildInferenceClient, type AiRunner } from '../pipeline/inference'
import { DenylistReputationClient, type IndicatorKv } from '../pipeline/indicators'
import { scanRequestSchema } from '../schemas/validate'
import { d1Database } from '../db/database'
import { authenticate } from '../middleware/auth'
import { aiAllowedForTier, enforceDailyCap } from '../middleware/gate'
import { recordVerdict } from '../db/usage'
import { insertScan } from '../db/scans'
import { resolveCachedScan, type VerdictCacheKv } from '../scanner/verdictCache'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422
const STATUS_TOO_MANY_REQUESTS = 429
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502

/** Subject prefix marking an anonymous (IP-keyed) caller — never given history. */
const ANON_SUBJECT_PREFIX = 'anon:'
/** Max stored length of a scan-history `source_ref` label (privacy + bound). */
const SOURCE_REF_MAX_CHARS = 200

/**
 * Parse and Zod-validate the JSON body into a {@link ScanRequest}. A body that
 * is not JSON, or fails validation (e.g. neither/both of content & sourceUrl),
 * is a {@link ParseError} (mapped to 422), never an unhandled throw.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} On non-JSON or schema-invalid input.
 */
async function parseScanBody(request: Request): Promise<ScanRequest> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = scanRequestSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid scan request: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Map a thrown error to its HTTP status. The error class is the contract:
 * ParseError / SourceResolutionError → 422; ConfigError → 500; ReputationError /
 * RedirectResolutionError / InferenceError → 502; any other ScannerError → 400;
 * anything else → 500.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function statusForError(error: unknown): number {
  if (error instanceof ParseError || error instanceof SourceResolutionError) {
    return STATUS_UNPROCESSABLE
  }
  if (error instanceof QuotaExceededError) {
    return STATUS_TOO_MANY_REQUESTS
  }
  if (error instanceof ConfigError) {
    return STATUS_SERVER_ERROR
  }
  if (
    error instanceof ReputationError ||
    error instanceof RedirectResolutionError ||
    error instanceof InferenceError
  ) {
    return STATUS_BAD_GATEWAY
  }
  if (error instanceof ScannerError) {
    return STATUS_BAD_REQUEST
  }
  return STATUS_SERVER_ERROR
}

/**
 * Append one recent-scans history row for an AUTHENTICATED caller, best-effort.
 *
 * Anonymous (`anon:`) subjects are skipped — recent scans are a per-account
 * feature. The stored `source_ref` is the source LABEL only (a URL or `paste`),
 * truncated to {@link SOURCE_REF_MAX_CHARS}; the full scanned content NEVER
 * reaches this layer (CLAUDE.md §6 privacy). A history write must never fail the
 * scan, so any error is caught and logged here, not propagated.
 *
 * Time complexity: O(1) — single insert. Space complexity: O(1).
 *
 * @param db - The persistence seam (non-null; the caller gates on it).
 * @param subject - The caller's metering subject (user id, or `anon:<ip>`).
 * @param result - The scan result whose verdict/source/proof are recorded.
 * @param flaggedCount - The count of flagged reputation indicators in the scan.
 */
async function recordScanHistory(
  db: Database,
  subject: string,
  result: ScanResult,
  flaggedCount: number,
): Promise<void> {
  if (subject.startsWith(ANON_SUBJECT_PREFIX)) {
    return
  }
  try {
    await insertScan(db, {
      id: crypto.randomUUID(),
      userId: subject,
      verdict: result.verdict,
      sourceKind: result.source.kind,
      sourceRef: result.source.ref.slice(0, SOURCE_REF_MAX_CHARS),
      flagged: flaggedCount,
      headHash: result.proof.headHash,
      scannedAt: result.scannedAt,
    })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.warn(`[handleScan] scan-history insert failed (${className}); continuing`)
  }
}

/**
 * Handle `POST /api/scan`. Authenticates the caller, enforces its per-tier daily
 * cap BEFORE scanning, gates the paid AI stage to eligible tiers, runs the scan,
 * then meters usage. `scannedAt` is stamped here, at the edge, so the
 * time-varying value never enters the hashed proof.
 *
 * Accounts degrade gracefully: when `env.DB` is absent (e.g. local dev with no
 * D1) the route runs the scan as an unmetered anonymous caller — no cap check,
 * no usage write — rather than crashing. With `env.DB` present, the cap is
 * enforced and usage is incremented exactly once after a successful scan.
 *
 * The AI cost gate: the inference client is passed to `runScan` ONLY when the
 * caller's tier is in `config.aiTiers` AND the `AI` binding exists; otherwise it
 * is `null` (free / anon → deterministic + indicators only).
 *
 * Verdict cache: when KV is bound and `config.verdictCacheTtlSeconds > 0`, a
 * repeated identical scan is served from KV WITHOUT re-tracing redirects or
 * re-running the AI stage. Only the `runScan` compute is skipped — auth, the
 * daily-cap check, metering (`recordVerdict`), and the scan-history insert ALL
 * still run for the current caller on a cache hit, so cost accounting and the
 * audit trail stay correct. A fresh `scannedAt` is stamped on a hit; since
 * `scannedAt` is outside the hashed proof, the proof stays valid.
 *
 * Recent-scans history: after a successful AUTHENTICATED scan (anonymous
 * `anon:` subjects are skipped), one `scan_history` row is inserted best-effort.
 * It records only the source LABEL (never the scanned content); a failure here
 * is caught/logged and must NOT fail the scan response.
 *
 * Time complexity: dominated by `runScan` (O(U·H + R + F)); a cache hit is O(1)
 * plus the metering write. Space complexity: O(result size).
 */
export async function handleScan(
  request: Request,
  env: Env,
  config: ScannerConfig,
): Promise<Response> {
  try {
    const body = await parseScanBody(request)

    // Accounts seam: present only when D1 is bound. Without it, the caller is an
    // unmetered anonymous (no cap, no usage write), but the scan still runs.
    const db = env.DB !== undefined && env.DB !== null ? d1Database(env.DB) : null
    const today = new Date().toISOString().slice(0, 10)

    // Anonymous-by-default when there is no store to resolve a credential
    // against. With a store, accept either a Bearer key or a session cookie.
    const sessionSecret = typeof env.SESSION_SECRET === 'string' ? env.SESSION_SECRET : undefined
    const ctx = db !== null
      ? await authenticate(request, db, sessionSecret)
      : ({ subject: 'anon:unmetered', tier: 'anonymous' } as const)

    if (db !== null) {
      await enforceDailyCap(db, ctx.subject, ctx.tier, today, config)
    }

    // Cost-discipline gate: paid AI stage only for eligible tiers WITH a binding.
    const aiEligible =
      aiAllowedForTier(ctx.tier, config) && env.AI !== undefined && env.AI !== null
    const inference = aiEligible
      ? // The Workers AI binding's `run` is structurally an AiRunner.
        buildInferenceClient(env.AI as unknown as AiRunner, config)
      : null

    // Known-bad indicator lookup: the curated host denylist from config plus,
    // when KV is bound, dynamic `host:<hostname>` entries. Always present (an
    // empty denylist simply flags nothing statically) so the reputation stage
    // is wired in for every caller.
    const kv = env.KV !== undefined && env.KV !== null ? (env.KV as IndicatorKv) : null
    const reputation = new DenylistReputationClient(config.badHosts, kv)

    // The edge timestamp lives OUTSIDE the hashed proof, so it is stamped here
    // and is the same value whether the result is freshly computed or served
    // from the verdict cache.
    const scannedAt = new Date().toISOString()

    // Verdict cache: serve a repeated identical scan from KV (skipping the
    // redirect trace + AI compute), else run the real scan and populate the
    // cache. The cache wraps ONLY the `runScan` compute — auth/caps already ran,
    // and metering + history below STILL run for this caller on a hit.
    const cacheKv = env.KV !== undefined && env.KV !== null ? (env.KV as VerdictCacheKv) : null
    const { result } = await resolveCachedScan(
      body,
      cacheKv,
      config.verdictCacheTtlSeconds,
      scannedAt,
      () =>
        runScan(body, {
          config,
          reputation,
          inference,
          scannedAt,
          githubToken: typeof env.GITHUB_TOKEN === 'string' ? env.GITHUB_TOKEN : undefined,
        }),
    )

    const flaggedCount = result.reputation.filter((report) => report.flagged).length

    if (db !== null) {
      // Meter the scan: scans + the verdict column + flagged-indicator count +
      // ai_scans, in one atomic upsert, so the protection stats stay consistent
      // with the scan count. This runs on a cache hit too — the cache saves the
      // compute, never the per-caller accounting.
      await recordVerdict(db, ctx.subject, today, result.verdict, flaggedCount, {
        ai: inference !== null,
      })

      // Recent-scans history (authenticated callers only). Best-effort: a
      // failure here is logged and never fails the scan response.
      await recordScanHistory(db, ctx.subject, result, flaggedCount)
    }

    return Response.json(result, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.error(`[handleScan] ${className}: ${message}`)
    if (error instanceof QuotaExceededError) {
      return Response.json(
        { error: 'quota_exceeded', message },
        { status: STATUS_TOO_MANY_REQUESTS },
      )
    }
    return Response.json({ error: className, message }, { status: statusForError(error) })
  }
}
