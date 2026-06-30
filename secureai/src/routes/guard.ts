/**
 * `POST /api/guard` handler, the server side of the Claude Code PreToolUse
 * guard. Validates the hook payload with Zod at the edge, builds the same
 * inference client `/api/scan` uses, runs {@link guardDecision}, and returns the
 * resulting {@link GuardDecision} as JSON.
 *
 * The decision IS the body: a clean allow / ask / deny is a 200 with the
 * decision in the payload, that is not a failure. Only a genuine fault (invalid
 * body, config error, transport failure surfaced as a typed error) maps to a
 * non-200 status. Never a silent 200 on internal failure; `guardDecision` itself
 * is fail-closed and only ever returns a decision, so an internal scan fault
 * becomes a `deny` decision at 200, while a malformed request body is a 422.
 */

import type { Env, ScannerConfig } from '../config/env'
import type { GuardDecision } from '../guard/claudeCode'
import type { PreToolUsePayload } from '../schemas/validate'
import {
  AuthError,
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
import { guardDecision } from '../guard/claudeCode'
import {
  parseGuardDecisionTicket,
  signGuardDecisionTicket,
  verifyGuardDecisionTicket,
  type GuardTicketContext,
} from '../guard/decisionTicket'
import { resolveCachedDecision, type GuardCacheKv } from '../guard/guardCache'
import { buildInferenceClient, type AiRunner } from '../pipeline/inference'
import { breakerFor, type BreakerStore } from '../resilience/circuitBreaker'
import { DenylistReputationClient, type IndicatorKv } from '../pipeline/indicators'
import { preToolUseSchema } from '../schemas/validate'
import { d1Database, type Database } from '../db/database'
import { d1FeedStore } from '../db/feed'
import { authenticateGuard } from '../middleware/guardAuth'
import { aiAllowedForTier, enforceDailyCap } from '../middleware/gate'
import { recordVerdict } from '../db/usage'
import { log } from '../observability/logger'
import { metrics } from '../observability/metrics'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422
const STATUS_TOO_MANY_REQUESTS = 429
const STATUS_SERVER_ERROR = 500
const STATUS_BAD_GATEWAY = 502

/**
 * Parse and Zod-validate the JSON body into a {@link PreToolUsePayload}. A body
 * that is not JSON, or fails the PreToolUse schema, is a {@link ParseError}
 * (mapped to 422), never an unhandled throw.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} On non-JSON or schema-invalid input.
 */
async function parseGuardBody(request: Request): Promise<PreToolUsePayload> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  const parsed = preToolUseSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError(`invalid PreToolUse payload: ${parsed.error.message}`)
  }
  return parsed.data
}

/**
 * Map a thrown error to its HTTP status, identical contract to `routes/scan.ts`
 * so the two routes behave uniformly: ParseError / SourceResolutionError → 422;
 * ConfigError → 500; ReputationError / RedirectResolutionError / InferenceError
 * → 502; any other ScannerError → 400; anything else → 500.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function statusForError(error: unknown): number {
  if (error instanceof AuthError) {
    return STATUS_UNAUTHORIZED
  }
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
 * Handle `POST /api/guard`. Authenticates the caller, enforces its per-tier
 * daily cap BEFORE the guard scan, gates the paid AI stage to eligible tiers,
 * runs `guardDecision`, then meters usage, mirroring `/api/scan` exactly so the
 * two metered routes behave uniformly. `scannedAt` is stamped here at the edge
 * so the time-varying value never enters the hashed proof.
 *
 * Guard auth is strict when a DB is bound and `config.guardRequireAuth` is true:
 * a missing, malformed, expired, or unknown credential is a 401 so local hooks
 * fail closed instead of silently downgrading to anonymous. When `env.DB` is
 * absent, the route still runs as an unmetered anonymous caller for local dev.
 * A successful call returns the {@link GuardDecision} at 200, the allow/ask/deny
 * lives in the body. A malformed body is 422; an exhausted daily cap is 429.
 *
 * Time complexity: dominated by `guardDecision` → `runScan` (O(U·H + R + F)).
 * Space complexity: O(decision size).
 */
export async function handleGuard(
  request: Request,
  env: Env,
  config: ScannerConfig,
  db: Database | null = env.DB !== undefined && env.DB !== null ? d1Database(env.DB) : null,
): Promise<Response> {
  try {
    const payload = await parseGuardBody(request)

    // Accounts seam (threaded from the worker entry, session-aware when read
    // replication is on; defaults to a plain binding when called directly): null
    // when D1 is unbound, the caller is then an unmetered anonymous.
    const today = new Date().toISOString().slice(0, 10)

    const sessionSecret = typeof env.SESSION_SECRET === 'string' ? env.SESSION_SECRET : undefined
    const now = new Date()
    const ctx = db !== null
      ? await authenticateGuard(request, db, config, now.toISOString(), sessionSecret)
      : ({ subject: 'anon:unmetered', tier: 'anonymous', credentialKind: 'anonymous' } as const)

    if (db !== null) {
      if (config.guardRequireAuth && ctx.tier === 'anonymous') {
        throw new AuthError('authentication required for guard decisions')
      }
      await enforceDailyCap(db, ctx.subject, ctx.tier, today, config)
    }

    const guardPayload: PreToolUsePayload =
      db !== null && ctx.credentialKind === 'guard_device'
        ? ({
            ...payload,
            device_id: ctx.deviceId,
            provider: (payload as unknown as Record<string, unknown>).provider ?? ctx.integration,
          } as PreToolUsePayload)
        : payload

    const ticketSecret =
      typeof env.GUARD_TICKET_SECRET === 'string' ? env.GUARD_TICKET_SECRET : undefined
    const ticketContext: GuardTicketContext | null = ticketSecret === undefined
      ? null
      : {
          secret: ticketSecret,
          policyVersion: config.guardPolicyVersion,
          trustRevision: config.guardTrustRevision,
          ttlSeconds: config.guardTicketTtlSeconds,
          now,
        }
    let decision: GuardDecision | null = null
    const presentedTicket = parseGuardDecisionTicket(
      (guardPayload as unknown as Record<string, unknown>).decision_ticket,
    )
    if (ticketContext !== null && presentedTicket !== null) {
      const verification = await verifyGuardDecisionTicket(guardPayload, presentedTicket, ticketContext)
      if (verification.ok && presentedTicket.decision === 'allow') {
        decision = {
          decision: 'allow',
          reason: 'valid signed decision ticket',
          verdict: null,
          ticket: presentedTicket,
        }
      }
    }

    // Cost-discipline gate: paid AI stage only for eligible tiers WITH a binding.
    const aiEligible =
      aiAllowedForTier(ctx.tier, config) && env.AI !== undefined && env.AI !== null
    const inference = aiEligible
      ? // The Workers AI binding's `run` is structurally an AiRunner; the model
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
    // Threat-feed layer (D1-backed), consulted after the static set + KV. Wired
    // only when enabled AND a DB is bound; otherwise null (the feed is skipped).
    const feedStore = config.feedEnabled && db !== null ? d1FeedStore(db) : null
    const reputation = new DenylistReputationClient(config.badHosts, kv, feedStore)

    // Decision cache: a repeated identical tool call (the common Guard case) is
    // served from KV, skipping the redirect trace + AI compute. Auth, the daily
    // cap, and metering below still run for this caller on a hit.
    const guardCacheKv = env.KV !== undefined && env.KV !== null ? (env.KV as GuardCacheKv) : null
    let inferenceMetered = false
    if (decision === null) {
      inferenceMetered = inference !== null
      decision = await resolveCachedDecision(
        guardPayload,
        guardCacheKv,
        config.verdictCacheTtlSeconds,
        () =>
          guardDecision(guardPayload, {
            config,
            reputation,
            inference,
            scannedAt: now.toISOString(),
            githubToken: typeof env.GITHUB_TOKEN === 'string' ? env.GITHUB_TOKEN : undefined,
          }),
        config.guardPolicyVersion,
        config.guardTrustRevision,
      )
    }

    if (
      decision.decision === 'allow' &&
      decision.ticket === undefined &&
      ticketContext !== null
    ) {
      const ticket = await signGuardDecisionTicket(guardPayload, decision.decision, ticketContext)
      if (ticket !== null) {
        decision = { ...decision, ticket }
      }
    }
    metrics.count('guard.decision', { labels: [decision.decision] })

    if (db !== null) {
      // Meter the guarded call. A `null` decision verdict means "nothing
      // scannable", a benign ALLOW for stats purposes. The guard decision does
      // not surface per-URL reputation, so flagged is 0 here.
      const meteredVerdict = decision.verdict ?? 'ALLOW'
      await recordVerdict(db, ctx.subject, today, meteredVerdict, 0, { ai: inferenceMetered })
    }

    return Response.json(decision, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleGuard', 'request failed', { errorClass: className })
    if (error instanceof QuotaExceededError) {
      return Response.json(
        { error: 'quota_exceeded', message },
        { status: STATUS_TOO_MANY_REQUESTS },
      )
    }
    return Response.json({ error: className, message }, { status: statusForError(error) })
  }
}
