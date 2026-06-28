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
import type { BatchStatement, Database } from '../db/database'
import type { ScanRequest, ScanResult } from '../schemas/contract'
import {
  CircuitOpenError,
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
import { breakerFor, type BreakerStore } from '../resilience/circuitBreaker'
import { putScanContent, type ObjectStore } from '../storage/r2'
import { DenylistReputationClient, type IndicatorKv } from '../pipeline/indicators'
import { scanRequestSchema } from '../schemas/validate'
import { d1Database } from '../db/database'
import { authenticate } from '../middleware/auth'
import { aiAllowedForTier, enforceDailyCap } from '../middleware/gate'
import { recordVerdict, verdictStatement } from '../db/usage'
import {
  insertScan,
  insertScanDetail,
  scanDetailStatement,
  scanHistoryStatement,
} from '../db/scans'
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
/** The clean verdict: a scan with this verdict is NEVER detail-persisted. */
const CLEAN_VERDICT: ScanResult['verdict'] = 'ALLOW'

/** Shared encoder/decoder for byte-bounded content truncation (allocation-free). */
const detailTextEncoder = new TextEncoder()
/** Non-fatal decoder: drops a partial trailing code point rather than throwing. */
const detailTextDecoder = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true })

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
  scanId: string,
  subject: string,
  result: ScanResult,
  flaggedCount: number,
): Promise<void> {
  if (subject.startsWith(ANON_SUBJECT_PREFIX)) {
    return
  }
  try {
    await insertScan(db, {
      id: scanId,
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
 * Truncate a string to at most `maxBytes` UTF-8 bytes WITHOUT splitting a
 * multi-byte code point. Encodes once, slices the byte view at the bound, then
 * decodes with `{ fatal: false }` so a partial trailing sequence is dropped
 * rather than emitting a replacement char. A string already within the bound is
 * returned unchanged (no re-encode round trip beyond the length check).
 *
 * Time complexity: O(n) in the string byte length. Space complexity: O(n).
 */
function truncateToBytes(text: string, maxBytes: number): string {
  const bytes = detailTextEncoder.encode(text)
  if (bytes.length <= maxBytes) {
    return text
  }
  return detailTextDecoder.decode(bytes.subarray(0, maxBytes))
}

/**
 * Persist one caught-scan DETAIL row for an AUTHENTICATED, non-clean scan,
 * best-effort. Records the scanned content (truncated to `config.detailMaxBytes`,
 * or `null` when unavailable — e.g. a verdict-cache hit recomputed no text) plus
 * the serialized `{ findings, chains, injections, reputation }` evidence, so an
 * admin can review what was caught.
 *
 * Privacy gate (CLAUDE.md §6): a clean (`ALLOW`) scan or an anonymous (`anon:`)
 * caller is NEVER detail-persisted — nothing was flagged, so there is nothing to
 * review, and the per-account review surface excludes anonymous callers. The
 * `scanId` pairs the detail 1:1 with the just-written `scan_history` row.
 *
 * A failure here is caught/logged and must NOT fail the scan (it runs after the
 * response is computed), exactly like {@link recordScanHistory}.
 *
 * Time complexity: O(d) in the content byte length (one truncate + one insert).
 * Space complexity: O(d).
 *
 * @param db - The persistence seam (non-null; the caller gates on it).
 * @param scanId - The paired `scan_history` row id.
 * @param subject - The caller's metering subject (user id, or `anon:<ip>`).
 * @param result - The scan result whose verdict gates persistence + supplies
 *   the serialized evidence.
 * @param scannedText - The scanned content, or `null` when unavailable.
 * @param config - The scanner config (supplies the detail byte cap).
 */
async function recordScanDetail(
  db: Database,
  scanId: string,
  subject: string,
  result: ScanResult,
  scannedText: string | null,
  config: ScannerConfig,
): Promise<void> {
  if (subject.startsWith(ANON_SUBJECT_PREFIX) || result.verdict === CLEAN_VERDICT) {
    return
  }
  try {
    const resultJson = JSON.stringify({
      findings: result.findings,
      chains: result.chains,
      injections: result.injections,
      reputation: result.reputation,
    })
    await insertScanDetail(db, {
      scanId,
      content: scannedText === null ? null : truncateToBytes(scannedText, config.detailMaxBytes),
      resultJson,
      createdAt: result.scannedAt,
    })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.warn(`[handleScan] scan-detail insert failed (${className}); continuing`)
  }
}

/**
 * Persist a scan's writes (metering + recent-scans history + caught-scan detail)
 * as ONE atomic {@link Database.batch}. Builds the statement set with the SAME
 * gates as the sequential path — metering always; history only for an
 * AUTHENTICATED caller; detail only for an authenticated NON-clean scan — then
 * runs them in a single transaction.
 *
 * Posture: the batch is best-effort for the RESPONSE — a failure is logged and
 * the computed verdict is still returned (the daily cap was already enforced
 * before the scan, so a rarely-dropped metering increment risks at most one extra
 * scan on a DB blip). Atomicity means the three writes never half-apply
 * (no "usage bumped but history missing").
 *
 * Time complexity: O(d) in the detail content byte length. Space complexity: O(d).
 */
async function writeScanAtomic(
  db: Database,
  subject: string,
  day: string,
  result: ScanResult,
  flaggedCount: number,
  aiUsed: boolean,
  scannedText: string | null,
  config: ScannerConfig,
  objectStore: ObjectStore | null,
): Promise<void> {
  const statements: BatchStatement[] = [
    verdictStatement(subject, day, result.verdict, flaggedCount, { ai: aiUsed }),
  ]
  // When R2 offload is on, the FULL content is stored to object storage keyed by
  // this scan id after the D1 batch commits (best-effort); D1 keeps the preview.
  let offload: { scanId: string; content: string } | null = null
  if (!subject.startsWith(ANON_SUBJECT_PREFIX)) {
    const scanId = crypto.randomUUID()
    statements.push(
      scanHistoryStatement({
        id: scanId,
        userId: subject,
        verdict: result.verdict,
        sourceKind: result.source.kind,
        sourceRef: result.source.ref.slice(0, SOURCE_REF_MAX_CHARS),
        flagged: flaggedCount,
        headHash: result.proof.headHash,
        scannedAt: result.scannedAt,
      }),
    )
    if (result.verdict !== CLEAN_VERDICT) {
      statements.push(
        scanDetailStatement({
          scanId,
          content:
            scannedText === null ? null : truncateToBytes(scannedText, config.detailMaxBytes),
          resultJson: JSON.stringify({
            findings: result.findings,
            chains: result.chains,
            injections: result.injections,
            reputation: result.reputation,
          }),
          createdAt: result.scannedAt,
        }),
      )
      if (objectStore !== null && scannedText !== null) {
        offload = { scanId, content: scannedText }
      }
    }
  }
  try {
    await db.batch(statements)
    // Offload the full payload only after the D1 row it pairs with is committed.
    if (offload !== null && objectStore !== null) {
      await putScanContent(objectStore, offload.scanId, offload.content)
    }
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.warn(`[handleScan] scan write batch failed (${className}); continuing`)
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
 * Caught-scan detail: for an AUTHENTICATED NON-clean scan (verdict != `ALLOW`),
 * one `scan_details` row is ALSO inserted best-effort, paired to the history row
 * by the same minted id. It stores the scanned content (truncated to
 * `config.detailMaxBytes`, or `null` on a cache hit that recomputed no text) plus
 * the serialized evidence, so an admin can review what was flagged. Clean and
 * anonymous scans are never detail-persisted (CLAUDE.md §6 privacy).
 *
 * Time complexity: dominated by `runScan` (O(U·H + R + F)); a cache hit is O(1)
 * plus the metering write. Space complexity: O(result size).
 */
export async function handleScan(
  request: Request,
  env: Env,
  config: ScannerConfig,
  db: Database | null = env.DB !== undefined && env.DB !== null ? d1Database(env.DB) : null,
): Promise<Response> {
  try {
    const body = await parseScanBody(request)

    // Accounts seam (threaded from the worker entry, session-aware when read
    // replication is on; defaults to a plain binding when called directly): null
    // when D1 is unbound — the caller is then an unmetered anonymous (no cap, no
    // usage write), but the scan still runs.
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
      ? // The Workers AI binding's `run` is structurally an AiRunner. The model
        // call is guarded by a KV-backed breaker (pass-through when KV is unbound).
        buildInferenceClient(
          env.AI as unknown as AiRunner,
          config,
          breakerFor(
            (env.KV as BreakerStore | undefined) ?? null,
            config,
            'inference',
            () =>
              new InferenceError('inference circuit open', {
                cause: new CircuitOpenError('inference breaker open'),
              }),
          ),
        )
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
    const { result, scannedText } = await resolveCachedScan(
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
      // Persist metering + recent-scans history + caught-scan detail. The default
      // path writes all three as ONE atomic batch (and is non-fatal to the
      // response on failure); the legacy path keeps the prior behavior — metering
      // critical (a failure 500s), history/detail best-effort — behind a config
      // flag. Both run on a cache hit too: the cache saves the compute, never the
      // per-caller accounting.
      if (config.scanWriteAtomic) {
        const objectStore =
          config.r2Enabled && env.R2 !== undefined && env.R2 !== null
            ? (env.R2 as ObjectStore)
            : null
        await writeScanAtomic(
          db,
          ctx.subject,
          today,
          result,
          flaggedCount,
          inference !== null,
          scannedText,
          config,
          objectStore,
        )
      } else {
        await recordVerdict(db, ctx.subject, today, result.verdict, flaggedCount, {
          ai: inference !== null,
        })
        const scanId = crypto.randomUUID()
        await recordScanHistory(db, scanId, ctx.subject, result, flaggedCount)
        await recordScanDetail(db, scanId, ctx.subject, result, scannedText, config)
      }
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
