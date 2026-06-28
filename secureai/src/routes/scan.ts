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
import type { ScanRequest } from '../schemas/contract'
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
import { incrementUsage } from '../db/usage'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422
const STATUS_TOO_MANY_REQUESTS = 429
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502

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
 * Time complexity: dominated by `runScan` (O(U·H + R + F)).
 * Space complexity: O(result size).
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

    // Anonymous-by-default when there is no store to resolve a key against.
    const ctx = db !== null
      ? await authenticate(request, db)
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

    const result = await runScan(body, {
      config,
      reputation,
      inference,
      scannedAt: new Date().toISOString(),
      githubToken: typeof env.GITHUB_TOKEN === 'string' ? env.GITHUB_TOKEN : undefined,
    })

    if (db !== null) {
      await incrementUsage(db, ctx.subject, today, { ai: inference !== null })
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
