/**
 * A KV-backed circuit breaker for outbound dependencies (Resend, Stripe, Workers
 * AI). On a stateless runtime an in-process breaker can't persist across requests,
 * so the open/closed state lives in KV, shared across isolates and colos.
 *
 * It is a COARSE load-shedder, not a precise global limiter: the failure counter's
 * read-modify-write races across concurrent isolates and KV propagates with some
 * lag, so the trip point is approximate. That is sufficient because every wrapped
 * dependency already fails closed per request (CLAUDE.md §5) — the breaker just
 * stops hammering a dependency that is clearly down, shedding load fast.
 *
 * States: CLOSED (calls flow, failures counted) → OPEN (calls short-circuit for
 * `cooldownSeconds`) → HALF-OPEN (a single probe is allowed; success closes,
 * failure re-opens). A missing/corrupt/unreadable KV record fails SAFE — treated
 * as CLOSED — so a KV blip can never wedge every outbound call shut.
 *
 * State writes are awaited INLINE (not via `ctx.waitUntil`): a few ms on the
 * failure path in exchange for not threading `ExecutionContext` through every
 * call site. KV errors are swallowed (logged) so the breaker never itself throws.
 */

import type { ScannerConfig } from '../config/env'
import { CircuitOpenError } from '../errors'
import { log } from '../observability/logger'
import { metrics } from '../observability/metrics'

/** The three breaker states. */
export type CircuitState = 'closed' | 'open' | 'half-open'

/**
 * The minimal KV surface the breaker needs (structural, so a `{ get, put }` fake
 * can be injected in tests). Mirrors {@link ../middleware/rateLimit.RateLimitKv}.
 */
export interface BreakerStore {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/** Breaker tuning (from config): trip threshold and open-state cooldown. */
export interface CircuitBreakerConfig {
  readonly enabled: boolean
  readonly failureThreshold: number
  readonly cooldownSeconds: number
}

/** A breaker instance: run an operation through the circuit. */
export interface CircuitBreaker {
  /**
   * Run `operation` through the circuit. When OPEN (and within cooldown), throws
   * `onOpen()` WITHOUT invoking `operation`. Otherwise runs it, recording success
   * (resets failures) or failure (increments; trips OPEN at the threshold) and
   * re-throwing the original error on failure.
   */
  run<T>(operation: () => Promise<T>): Promise<T>
}

/** Persisted breaker record. `openedAt` is epoch seconds when it last tripped. */
interface BreakerRecord {
  readonly state: CircuitState
  readonly failures: number
  readonly openedAt: number
}

/** Key prefix for breaker state in KV. */
const KEY_PREFIX = 'cb:v1:'

/** Parse a stored record, or `null` when absent/corrupt (→ treated as closed). */
function parseRecord(raw: string | null): BreakerRecord | null {
  if (raw === null) {
    return null
  }
  try {
    const value = JSON.parse(raw) as Partial<BreakerRecord>
    if (
      (value.state === 'closed' || value.state === 'open' || value.state === 'half-open') &&
      typeof value.failures === 'number' &&
      Number.isFinite(value.failures) &&
      typeof value.openedAt === 'number' &&
      Number.isFinite(value.openedAt)
    ) {
      return { state: value.state, failures: value.failures, openedAt: value.openedAt }
    }
  } catch {
    /* fall through to null (treated as closed) */
  }
  return null
}

/**
 * Build a circuit breaker. When disabled or given no `store`, returns a
 * PASS-THROUGH breaker that simply runs the operation (no state, no overhead) —
 * so the absence of a KV binding degrades gracefully, exactly like the rate limit.
 *
 * @param store - The KV state store, or `null` (→ pass-through).
 * @param config - Tuning; `enabled === false` also yields pass-through.
 * @param name - Stable breaker name (keys its KV record, e.g. `email`).
 * @param onOpen - Builds the error thrown when the circuit short-circuits a call;
 *   should return the WRAPPED dependency's own typed error.
 * @param now - Injectable clock returning epoch SECONDS (for tests).
 */
export function createCircuitBreaker(args: {
  store: BreakerStore | null
  config: CircuitBreakerConfig
  name: string
  onOpen: () => Error
  now: () => number
}): CircuitBreaker {
  const { store, config, name, onOpen, now } = args
  if (store === null || !config.enabled) {
    return { run: (operation) => operation() }
  }
  const key = `${KEY_PREFIX}${name}`
  const ttl = config.cooldownSeconds * 2 + 60

  async function read(): Promise<BreakerRecord> {
    try {
      return parseRecord(await store!.get(key)) ?? { state: 'closed', failures: 0, openedAt: 0 }
    } catch (error: unknown) {
      // A KV read fault must not wedge the circuit: treat as closed (allow traffic).
      const className = error instanceof Error ? error.constructor.name : typeof error
      log.warn('breaker', 'state read failed; treating as closed', { errorClass: className, name: name })
      return { state: 'closed', failures: 0, openedAt: 0 }
    }
  }

  async function write(record: BreakerRecord): Promise<void> {
    try {
      await store!.put(key, JSON.stringify(record), { expirationTtl: ttl })
    } catch (error: unknown) {
      const className = error instanceof Error ? error.constructor.name : typeof error
      log.warn('breaker', 'state write failed; continuing', { errorClass: className, name: name })
    }
  }

  return {
    async run<T>(operation: () => Promise<T>): Promise<T> {
      const record = await read()
      if (record.state === 'open' && now() < record.openedAt + config.cooldownSeconds) {
        // Short-circuit: do NOT invoke the operation. The cause is a
        // CircuitOpenError so logs distinguish this from a real upstream failure.
        throw onOpen()
      }
      // A call made while OPEN (past cooldown) or HALF-OPEN is a recovery PROBE:
      // its outcome alone decides whether to close or re-open.
      const probing = record.state !== 'closed'
      try {
        const result = await operation()
        // Success closes the circuit and clears the failure count.
        if (record.state !== 'closed' || record.failures !== 0) {
          await write({ state: 'closed', failures: 0, openedAt: 0 })
        }
        return result
      } catch (error: unknown) {
        const failures = record.failures + 1
        if (probing || failures >= config.failureThreshold) {
          // A failed probe re-opens; in CLOSED, reaching the threshold trips OPEN.
          await write({ state: 'open', failures, openedAt: now() })
          metrics.count('breaker.open', { labels: [name] })
        } else {
          await write({ state: 'closed', failures, openedAt: 0 })
        }
        throw error
      }
    },
  }
}

/**
 * Convenience constructor for production call sites: build a breaker from the
 * validated {@link ScannerConfig} (mapping its flat `breaker*` fields) and a real
 * seconds clock. Tests use {@link createCircuitBreaker} directly with an injected
 * clock and store.
 *
 * @param store - The KV store, or `null` (→ pass-through).
 * @param config - The scanner config (supplies the breaker tuning).
 * @param name - Stable breaker name (keys its KV record).
 * @param onOpen - Builds the wrapped dependency's typed error for a short circuit.
 */
export function breakerFor(
  store: BreakerStore | null,
  config: ScannerConfig,
  name: string,
  onOpen: () => Error,
): CircuitBreaker {
  return createCircuitBreaker({
    store,
    config: {
      enabled: config.breakerEnabled,
      failureThreshold: config.breakerFailureThreshold,
      cooldownSeconds: config.breakerCooldownSeconds,
    },
    name,
    onOpen,
    now: () => Math.floor(Date.now() / 1000),
  })
}

/**
 * A no-op breaker that simply runs the operation. The default for call sites that
 * accept an optional breaker (e.g. the inference client in tests), so their
 * behavior is unchanged when no real breaker is injected.
 */
export function passThroughBreaker(): CircuitBreaker {
  return { run: (operation) => operation() }
}

/** Re-exported so call sites can build the cause without importing errors directly. */
export { CircuitOpenError }
