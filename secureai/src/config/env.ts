/**
 * Typed Worker {@link Env} (bindings + vars) and {@link loadConfig}, which
 * validates the `SCANNER_*` vars into an immutable {@link ScannerConfig} and
 * fails closed (throws {@link ConfigError}) on any bad or out-of-range value.
 *
 * No value is hardcoded in source: every tunable comes from a var (with a
 * default declared in `wrangler.jsonc`) so behavior can be retuned without a
 * code edit (CLAUDE.md §1, "code dynamically").
 */

import { ConfigError } from '../errors'

/**
 * Worker bindings and string vars. Bindings (AI, DB, KV, RATE_LIMITER, ASSETS)
 * are declared optional here and become required as the features that use them
 * land with their `wrangler.jsonc` binding declarations.
 */
export interface Env {
  ASSETS?: Fetcher
  AI?: unknown // Workers AI binding; typed at the inference call site.
  DB?: D1Database
  KV?: KVNamespace
  // SCANNER_* string vars (see wrangler.jsonc). Indexed for forward-compat.
  [key: string]: unknown
}

/** Immutable, validated runtime configuration. */
export interface ScannerConfig {
  readonly hashAlgorithm: 'SHA-256'
  readonly genesisSeed: string
  readonly graphPath: string
  readonly maxUrls: number
  readonly maxRedirectHops: number
  readonly redirectTimeoutMs: number
  readonly allowedSchemes: ReadonlySet<string>
  readonly shortenerHosts: ReadonlySet<string>
  readonly aiModel: string
  readonly aiTimeoutMs: number
  readonly reviewThreshold: number
  readonly blockThreshold: number
  readonly skillMaxBytes: number
  readonly subrequestCap: number
  /** Max metered scans per UTC day for an anonymous (IP-keyed) caller. */
  readonly capAnonymousPerDay: number
  /** Max metered scans per UTC day for a free-tier account. */
  readonly capFreePerDay: number
  /** Max metered scans per UTC day for a pro-tier account. */
  readonly capProPerDay: number
  /** Tiers granted the paid AI stage. Lowercased tier names, e.g. `pro`. */
  readonly aiTiers: ReadonlySet<string>
  /** Stripe Price id for the Pro tier ($12/mo recurring). Used at checkout. */
  readonly stripePricePro: string
  /** Public base URL for billing redirect (success/cancel) and portal returns. */
  readonly appBaseUrl: string
}

/**
 * Load and validate config from the environment. Fail-closed: any missing or
 * invalid value throws {@link ConfigError} before the request path is entered.
 *
 * Time complexity: O(v) in the var count. Space complexity: O(v).
 *
 * @throws {ConfigError} On a malformed or out-of-range var, or a violated
 *   cross-field invariant.
 */
export function loadConfig(env: Env): ScannerConfig {
  const genesisSeed = readString(env, 'SCANNER_GENESIS_SEED', 'secureai-scanner-genesis-v1')
  const graphPath = readString(env, 'SCANNER_GRAPH_PATH', './graph.json')
  const maxUrls = readIntInRange(env, 'SCANNER_MAX_URLS', 4, 1, 1000)
  const maxRedirectHops = readIntInRange(env, 'SCANNER_MAX_REDIRECT_HOPS', 10, 1, 50)
  const redirectTimeoutMs = readIntInRange(env, 'SCANNER_REDIRECT_TIMEOUT_MS', 5000, 100, 60000)
  const allowedSchemes = readSet(env, 'SCANNER_ALLOWED_SCHEMES', 'https')
  const shortenerHosts = readSet(env, 'SCANNER_URL_SHORTENERS', '')
  const aiModel = readString(env, 'SCANNER_AI_MODEL', '@cf/meta/llama-3.2-1b-instruct')
  const aiTimeoutMs = readIntInRange(env, 'SCANNER_AI_TIMEOUT_MS', 8000, 100, 60000)
  const reviewThreshold = readFloatInRange(env, 'SCANNER_REVIEW_THRESHOLD', 0.3, 0, 1)
  const blockThreshold = readFloatInRange(env, 'SCANNER_BLOCK_THRESHOLD', 0.7, 0, 1)
  const skillMaxBytes = readIntInRange(env, 'SCANNER_SKILL_MAX_BYTES', 262144, 1, 10485760)
  const subrequestCap = readIntInRange(env, 'SCANNER_SUBREQUEST_CAP', 50, 1, 1000)
  // Per-tier daily caps (accounts layer). Defaults match the free-tier funnel:
  // a small anonymous allowance, a larger free allowance, a high pro allowance.
  const capAnonymousPerDay = readIntInRange(env, 'SCANNER_CAP_ANONYMOUS_PER_DAY', 10, 0, 1000000)
  const capFreePerDay = readIntInRange(env, 'SCANNER_CAP_FREE_PER_DAY', 100, 0, 1000000)
  const capProPerDay = readIntInRange(env, 'SCANNER_CAP_PRO_PER_DAY', 5000, 0, 1000000)
  // Tiers that get the paid AI stage. Comma var, default just `pro`.
  const aiTiers = readSet(env, 'SCANNER_AI_TIERS', 'pro')
  // Billing (Stripe). The Pro price id has no safe default — it is account- and
  // mode-specific — so the placeholder is shipped in wrangler.jsonc and must be
  // replaced before the billing routes function. The base URL has a public
  // default. Secrets (STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET) are NOT read
  // here; they are read from env at the route so a missing secret degrades the
  // billing routes to 503 rather than failing config load for every route.
  const stripePricePro = readString(env, 'STRIPE_PRICE_PRO', 'price_REPLACE')
  const appBaseUrl = readString(env, 'SCANNER_APP_BASE_URL', 'https://secureai.zurielst.com')

  // Cross-field invariants (fail-closed).
  if (!(reviewThreshold < blockThreshold)) {
    throw new ConfigError(
      `SCANNER_REVIEW_THRESHOLD (${reviewThreshold}) must be < SCANNER_BLOCK_THRESHOLD (${blockThreshold})`,
    )
  }
  if (allowedSchemes.size === 0) {
    throw new ConfigError('SCANNER_ALLOWED_SCHEMES must list at least one scheme')
  }
  // Worst-case subrequest budget: one fetch per redirect hop per URL, plus the
  // source fetch and the inference call.
  const worstCaseSubrequests = maxUrls * maxRedirectHops + 2
  if (worstCaseSubrequests > subrequestCap) {
    throw new ConfigError(
      `maxUrls*maxRedirectHops+2 (${worstCaseSubrequests}) exceeds SCANNER_SUBREQUEST_CAP (${subrequestCap})`,
    )
  }

  return {
    hashAlgorithm: 'SHA-256',
    genesisSeed,
    graphPath,
    maxUrls,
    maxRedirectHops,
    redirectTimeoutMs,
    allowedSchemes,
    shortenerHosts,
    aiModel,
    aiTimeoutMs,
    reviewThreshold,
    blockThreshold,
    skillMaxBytes,
    subrequestCap,
    capAnonymousPerDay,
    capFreePerDay,
    capProPerDay,
    aiTiers,
    stripePricePro,
    appBaseUrl,
  }
}

// ------------------------------------------------------------- var parsing ---

function readRaw(env: Env, key: string): string | undefined {
  const value = env[key]
  if (value === undefined || value === null) {
    return undefined
  }
  if (typeof value !== 'string') {
    throw new ConfigError(`${key} must be a string var, got ${typeof value}`)
  }
  return value
}

function readString(env: Env, key: string, fallback: string): string {
  const raw = readRaw(env, key)
  const value = raw === undefined ? fallback : raw.trim()
  if (value.length === 0) {
    throw new ConfigError(`${key} must be a non-empty string`)
  }
  return value
}

function readSet(env: Env, key: string, fallback: string): ReadonlySet<string> {
  const raw = readRaw(env, key)
  const source = raw === undefined ? fallback : raw
  const items = source
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter((item) => item.length > 0)
  return new Set(items)
}

function readIntInRange(
  env: Env,
  key: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = readRaw(env, key)
  if (raw === undefined) {
    return fallback
  }
  const value = Number(raw)
  if (!Number.isInteger(value)) {
    throw new ConfigError(`${key} must be an integer, got "${raw}"`)
  }
  if (value < min || value > max) {
    throw new ConfigError(`${key} (${value}) must be in [${min}, ${max}]`)
  }
  return value
}

function readFloatInRange(
  env: Env,
  key: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = readRaw(env, key)
  if (raw === undefined) {
    return fallback
  }
  const value = Number(raw)
  if (!Number.isFinite(value)) {
    throw new ConfigError(`${key} must be a finite number, got "${raw}"`)
  }
  if (value < min || value > max) {
    throw new ConfigError(`${key} (${value}) must be in [${min}, ${max}]`)
  }
  return value
}
