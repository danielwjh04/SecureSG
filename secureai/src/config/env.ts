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
  /**
   * Optional R2 bucket for full caught-scan content offload (gated by
   * `SCANNER_R2_ENABLED`). Absent → the feature is a no-op and D1 keeps the
   * truncated preview only. Typed as the R2 binding when declared in wrangler.
   */
  R2?: R2Bucket
  /**
   * HMAC secret signing stateless session cookies. A SECRET (set via
   * `wrangler secret put SESSION_SECRET`), so it is read from `env` at the route
   * — never folded into {@link ScannerConfig}, and never in source. When absent,
   * cookie auth is simply unavailable and the register/login routes return 503;
   * Bearer API-key auth keeps working without it.
   */
  SESSION_SECRET?: string
  /**
   * API key for the Resend transactional-email provider, used to deliver 2FA
   * sign-in codes. A SECRET (set via `wrangler secret put RESEND_API_KEY`), so
   * it is read from `env` at the route — never folded into {@link ScannerConfig},
   * and never in source. When absent, email 2FA is simply unavailable and login
   * issues a session immediately after the password check (today's behavior);
   * when present, a successful password starts an emailed-code challenge.
   */
  RESEND_API_KEY?: string
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
  /**
   * Curated known-bad host/domain denylist (lowercased) for the reputation
   * stage. A entry `evil.com` flags `evil.com` and every subdomain of it.
   * Dynamic entries can additionally be added at runtime in KV under
   * `host:<hostname>` (see {@link DenylistReputationClient}).
   */
  readonly badHosts: ReadonlySet<string>
  readonly aiModel: string
  readonly aiTimeoutMs: number
  readonly reviewThreshold: number
  readonly blockThreshold: number
  readonly skillMaxBytes: number
  /**
   * Max bytes of scanned skill/artifact text persisted in `scan_details` for a
   * caught (non-ALLOW) AUTHENTICATED scan, so an admin can review what was
   * flagged. The stored content is truncated to this bound; clean (ALLOW) and
   * anonymous scans are NEVER persisted (CLAUDE.md §6 privacy).
   */
  readonly detailMaxBytes: number
  readonly subrequestCap: number
  /** Max metered scans per UTC day for an anonymous (IP-keyed) caller. */
  readonly capAnonymousPerDay: number
  /** Max metered scans per UTC day for a free-tier account. */
  readonly capFreePerDay: number
  /** Max metered scans per UTC day for a pro-tier account. */
  readonly capProPerDay: number
  /** Tiers granted the paid AI stage. Lowercased tier names, e.g. `pro`. */
  readonly aiTiers: ReadonlySet<string>
  /**
   * TTL, in seconds, of an edge verdict-cache entry (CLAUDE.md O(1) target). A
   * repeated identical scan within the window returns the cached
   * {@link ScanResult} (with a fresh `scannedAt`) without re-tracing redirects
   * or re-running the AI stage. `0` disables the cache. Kept SHORT by default:
   * the cache serves identical content for the window, so a changed indicator /
   * feed could be briefly masked — the documented tradeoff for the latency win.
   */
  readonly verdictCacheTtlSeconds: number
  /** Stripe Price id for the Pro tier ($12/mo recurring). Used at checkout. */
  readonly stripePricePro: string
  /** Public base URL for billing redirect (success/cancel) and portal returns. */
  readonly appBaseUrl: string
  /**
   * PBKDF2-HMAC-SHA256 iteration count for password hashing. A non-secret cost
   * tunable (raise it as hardware improves); the per-hash salt and iteration
   * count are serialized INTO each stored hash, so raising this never breaks
   * verification of already-stored passwords.
   */
  readonly pbkdf2Iterations: number
  /** Lifetime, in seconds, of a minted session cookie (signed token + cookie Max-Age). */
  readonly sessionTtlSeconds: number
  /**
   * Emails (lowercased) granted access to the admin analytics endpoint. An
   * account whose email is in this set sees `isAdmin: true` from `/api/me` and
   * may read `/api/admin/overview`; every other caller is forbidden. Default
   * empty (no admins) so the surface is closed unless explicitly opened via the
   * `SCANNER_ADMIN_EMAILS` var. The email is NEVER hardcoded in source.
   */
  readonly adminEmails: ReadonlySet<string>
  /**
   * The `From` address two-factor sign-in code emails are sent as. Must be on a
   * domain verified with the email provider (Resend) for delivery to succeed.
   * Non-secret (it is public on every email), so it lives here as a var.
   */
  readonly emailFrom: string
  /** Lifetime, in seconds, of an emailed 2FA challenge (the code's validity window). */
  readonly otpTtlSeconds: number
  /** Max verify attempts per 2FA challenge before it is spent (brute-force cap). */
  readonly otpMaxAttempts: number
  /**
   * Recipients (lowercased, deduped) of a contact-sales inquiry submitted via
   * `POST /api/contact`. These live SERVER-SIDE only — the public form never
   * carries them — so the inbox set can be retuned via the
   * `SCANNER_CONTACT_RECIPIENTS` var without a code edit and without exposing the
   * addresses to the browser. At least one recipient is required (an empty set
   * fails config load closed).
   */
  readonly contactRecipients: readonly string[]
  /**
   * Max contact-sales inquiries accepted per rolling hour per client IP, the
   * abuse bound on the public `POST /api/contact` endpoint. Enforced via KV; when
   * KV is unbound the limit is skipped (the endpoint still functions).
   */
  readonly contactRatePerHour: number
  /**
   * Max auth attempts accepted per rolling hour per client IP, the brute-force
   * bound on `POST /api/login`, `/api/register`, and the OTP verify/resend
   * endpoints (each endpoint gets its own per-IP bucket). Enforced via KV; when
   * KV is unbound the limit is skipped.
   */
  readonly authRatePerHour: number
  /**
   * Minimum distinct character classes (of lowercase / uppercase / digit /
   * symbol) a registration password must mix. The deterministic offline strength
   * gate; password LENGTH is enforced separately by the register schema.
   */
  readonly passwordMinClasses: number
  /**
   * Whether registration runs the online HIBP k-anonymity leaked-password check.
   * Default on; the check fails OPEN (a HIBP outage never blocks signup), and the
   * offline common-password denylist runs regardless of this flag.
   */
  readonly pwnedCheckEnabled: boolean
  /** Hard timeout (ms) for the HIBP range fetch when {@link pwnedCheckEnabled}. */
  readonly pwnedTimeoutMs: number
  /**
   * Whether the per-scan writes (metering + history + detail) run as ONE atomic
   * `Database.batch` (default) or the legacy sequential path. The atomic path also
   * makes a write failure non-fatal to the scan response (logged, the verdict is
   * still returned); set to `false` to fall back if a batch issue is suspected.
   */
  readonly scanWriteAtomic: boolean
  /** Hard timeout (ms) for the Resend email-send fetch. */
  readonly emailTimeoutMs: number
  /** Hard timeout (ms) the Stripe SDK applies to each API call. */
  readonly stripeTimeoutMs: number
  /** Stripe SDK automatic network-retry count (multiplies worst-case wall time). */
  readonly stripeMaxNetworkRetries: number
  /**
   * Circuit-breaker tuning for outbound dependencies (Resend / Stripe / Workers
   * AI). `enabled` off, or KV unbound, yields a pass-through breaker.
   * `failureThreshold` consecutive-ish failures trip it OPEN; it then short-circuits
   * for `cooldownSeconds` before allowing a half-open probe.
   */
  readonly breakerEnabled: boolean
  readonly breakerFailureThreshold: number
  readonly breakerCooldownSeconds: number
  /**
   * Whether reads use D1 read-replication SESSIONS (read-your-writes via a
   * bookmark). Default OFF for safe rollout; when off, every request uses a plain
   * primary binding. Requires the D1 binding; a no-op when DB is unbound.
   */
  readonly dbSessionsEnabled: boolean
  /** TTL (seconds) of the client's `d1b` bookmark cookie when sessions are on. */
  readonly dbBookmarkTtlSeconds: number
  /**
   * Whether full caught-scan content is offloaded to the R2 bucket (the `R2`
   * binding). Default OFF; also a no-op when the bucket is unbound. When on, D1
   * keeps the truncated preview and R2 holds the full payload for admin review.
   */
  readonly r2Enabled: boolean
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
  // Curated known-bad host denylist for the reputation stage. Default empty:
  // an empty denylist is valid (the stage simply flags nothing statically) and
  // hosts can also be added dynamically in KV under `host:<hostname>`.
  const badHosts = readSet(env, 'SCANNER_BAD_HOSTS', '')
  const aiModel = readString(env, 'SCANNER_AI_MODEL', '@cf/meta/llama-3.2-1b-instruct')
  const aiTimeoutMs = readIntInRange(env, 'SCANNER_AI_TIMEOUT_MS', 8000, 100, 60000)
  const reviewThreshold = readFloatInRange(env, 'SCANNER_REVIEW_THRESHOLD', 0.3, 0, 1)
  const blockThreshold = readFloatInRange(env, 'SCANNER_BLOCK_THRESHOLD', 0.7, 0, 1)
  const skillMaxBytes = readIntInRange(env, 'SCANNER_SKILL_MAX_BYTES', 262144, 1, 10485760)
  // Max bytes of caught-scan content persisted for admin review. Default 16 KiB;
  // range 256..262144 (256 B floor so a snippet is always meaningful, 256 KiB
  // ceiling matching the skill byte cap). Only non-ALLOW authenticated scans are
  // stored, truncated to this bound.
  const detailMaxBytes = readIntInRange(env, 'SCANNER_DETAIL_MAX_BYTES', 16384, 256, 262144)
  const subrequestCap = readIntInRange(env, 'SCANNER_SUBREQUEST_CAP', 50, 1, 1000)
  // Per-tier daily caps (accounts layer). Defaults match the free-tier funnel:
  // a small anonymous allowance, a larger free allowance, a high pro allowance.
  const capAnonymousPerDay = readIntInRange(env, 'SCANNER_CAP_ANONYMOUS_PER_DAY', 10, 0, 1000000)
  const capFreePerDay = readIntInRange(env, 'SCANNER_CAP_FREE_PER_DAY', 100, 0, 1000000)
  const capProPerDay = readIntInRange(env, 'SCANNER_CAP_PRO_PER_DAY', 5000, 0, 1000000)
  // Tiers that get the paid AI stage. Comma var, default just `pro`.
  const aiTiers = readSet(env, 'SCANNER_AI_TIERS', 'pro')
  // Edge verdict-cache TTL (seconds). Default 5 minutes; 0 disables the cache;
  // capped at 24h. A repeated identical scan within the window returns the
  // cached result without re-running the redirect trace or the AI stage.
  const verdictCacheTtlSeconds = readIntInRange(
    env,
    'SCANNER_VERDICT_CACHE_TTL_S',
    300,
    0,
    86400,
  )
  // Billing (Stripe). The Pro price id has no safe default — it is account- and
  // mode-specific — so the placeholder is shipped in wrangler.jsonc and must be
  // replaced before the billing routes function. The base URL has a public
  // default. Secrets (STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET) are NOT read
  // here; they are read from env at the route so a missing secret degrades the
  // billing routes to 503 rather than failing config load for every route.
  const stripePricePro = readString(env, 'STRIPE_PRICE_PRO', 'price_REPLACE')
  const appBaseUrl = readString(env, 'SCANNER_APP_BASE_URL', 'https://secureai.zurielst.com')
  // Auth tunables (non-secret). IMPORTANT: the Cloudflare Workers runtime caps
  // crypto.subtle PBKDF2 at 100_000 iterations and THROWS above it (the Node test
  // runtime has no cap, which hid this). So 100k is the platform ceiling and our
  // default; the max is pinned to 100_000 so an out-of-range value fails closed at
  // config load rather than at the first register. (To exceed 100k effective cost
  // on Workers you must chain multiple deriveBits calls — a future hardening.)
  // Session TTL defaults to 7 days (604800s), matching the cookie the frontend expects.
  const pbkdf2Iterations = readIntInRange(env, 'SCANNER_PBKDF2_ITERATIONS', 100000, 10000, 100000)
  const sessionTtlSeconds = readIntInRange(env, 'SCANNER_SESSION_TTL_SECONDS', 604800, 60, 31536000)
  // Admin allowlist (lowercased emails). Default empty: no admins until the var
  // is set, so the analytics surface is closed by default. The email is supplied
  // by SCANNER_ADMIN_EMAILS in wrangler.jsonc, never hardcoded here.
  const adminEmails = readSet(env, 'SCANNER_ADMIN_EMAILS', '')
  // Email 2FA tunables (non-secret). The provider secret RESEND_API_KEY is NOT
  // read here — it is read from env at the route so a missing key degrades login
  // to immediate-session (today's behavior) rather than failing config load for
  // every route. emailFrom must be on a Resend-verified domain. The OTP TTL
  // defaults to 10 minutes; the attempt cap to 5 tries before a code is spent.
  const emailFrom = readString(env, 'SCANNER_EMAIL_FROM', 'SecureAI <noreply@zurielst.com>')
  const otpTtlSeconds = readIntInRange(env, 'SCANNER_OTP_TTL_SECONDS', 600, 60, 3600)
  const otpMaxAttempts = readIntInRange(env, 'SCANNER_OTP_MAX_ATTEMPTS', 5, 1, 20)
  // Contact-sales recipients (server-side only; never sent to the browser). The
  // comma var is trimmed/lowercased/deduped by readSet; an array preserves the
  // configured inbox set for the Resend `to` field. The default seeds the two
  // sales addresses. Per-IP hourly rate limit defaults to 5, range 1..100.
  const contactRecipients = [
    ...readSet(env, 'SCANNER_CONTACT_RECIPIENTS', 'zuriel.shanley@gmail.com,danielwjh04@gmail.com'),
  ]
  const contactRatePerHour = readIntInRange(env, 'SCANNER_CONTACT_RATE_PER_HOUR', 5, 1, 100)
  // Auth hardening tunables. The per-IP hourly auth attempt cap defaults to 20
  // (generous for a human, throttling a brute-forcer); password complexity
  // requires 3 of 4 character classes by default. The HIBP leaked-password check
  // is on by default and fails open; its fetch is bounded by a short timeout.
  const authRatePerHour = readIntInRange(env, 'SCANNER_AUTH_RATE_PER_HOUR', 20, 1, 1000)
  const passwordMinClasses = readIntInRange(env, 'SCANNER_PASSWORD_MIN_CLASSES', 3, 1, 4)
  const pwnedCheckEnabled = readBool(env, 'SCANNER_PWNED_CHECK_ENABLED', true)
  const pwnedTimeoutMs = readIntInRange(env, 'SCANNER_PWNED_TIMEOUT_MS', 2500, 100, 60000)
  // Per-scan writes default to one atomic D1 batch; flip to false to fall back to
  // the legacy sequential path.
  const scanWriteAtomic = readBool(env, 'SCANNER_SCAN_WRITE_ATOMIC', true)
  // Resilience: outbound-dependency timeouts + circuit breaker. Email/Stripe
  // fetches default to a 10s timeout; Stripe retries once. The breaker is on by
  // default, tripping after 5 failures and cooling down 30s.
  const emailTimeoutMs = readIntInRange(env, 'SCANNER_EMAIL_TIMEOUT_MS', 10000, 100, 60000)
  const stripeTimeoutMs = readIntInRange(env, 'SCANNER_STRIPE_TIMEOUT_MS', 10000, 100, 60000)
  const stripeMaxNetworkRetries = readIntInRange(env, 'SCANNER_STRIPE_MAX_NETWORK_RETRIES', 1, 0, 5)
  const breakerEnabled = readBool(env, 'SCANNER_BREAKER_ENABLED', true)
  const breakerFailureThreshold = readIntInRange(env, 'SCANNER_BREAKER_FAILURE_THRESHOLD', 5, 1, 100)
  const breakerCooldownSeconds = readIntInRange(env, 'SCANNER_BREAKER_COOLDOWN_S', 30, 1, 3600)
  // D1 read replication (read-your-writes via session bookmarks). Off by default;
  // the bookmark cookie is short-lived.
  const dbSessionsEnabled = readBool(env, 'SCANNER_DB_SESSIONS_ENABLED', false)
  const dbBookmarkTtlSeconds = readIntInRange(env, 'SCANNER_DB_BOOKMARK_TTL_S', 60, 1, 600)
  // R2 full-content offload (gated; no-op when the bucket is unbound).
  const r2Enabled = readBool(env, 'SCANNER_R2_ENABLED', false)

  // Cross-field invariants (fail-closed).
  if (!(reviewThreshold < blockThreshold)) {
    throw new ConfigError(
      `SCANNER_REVIEW_THRESHOLD (${reviewThreshold}) must be < SCANNER_BLOCK_THRESHOLD (${blockThreshold})`,
    )
  }
  if (allowedSchemes.size === 0) {
    throw new ConfigError('SCANNER_ALLOWED_SCHEMES must list at least one scheme')
  }
  if (contactRecipients.length === 0) {
    throw new ConfigError('SCANNER_CONTACT_RECIPIENTS must list at least one recipient')
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
    badHosts,
    aiModel,
    aiTimeoutMs,
    reviewThreshold,
    blockThreshold,
    skillMaxBytes,
    detailMaxBytes,
    subrequestCap,
    capAnonymousPerDay,
    capFreePerDay,
    capProPerDay,
    aiTiers,
    verdictCacheTtlSeconds,
    stripePricePro,
    appBaseUrl,
    pbkdf2Iterations,
    sessionTtlSeconds,
    adminEmails,
    emailFrom,
    otpTtlSeconds,
    otpMaxAttempts,
    contactRecipients,
    contactRatePerHour,
    authRatePerHour,
    passwordMinClasses,
    pwnedCheckEnabled,
    pwnedTimeoutMs,
    scanWriteAtomic,
    emailTimeoutMs,
    stripeTimeoutMs,
    stripeMaxNetworkRetries,
    breakerEnabled,
    breakerFailureThreshold,
    breakerCooldownSeconds,
    dbSessionsEnabled,
    dbBookmarkTtlSeconds,
    r2Enabled,
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

/**
 * Read a boolean var: exactly `"true"` or `"false"` (case-insensitive, trimmed),
 * or the fallback when unset. Any other value fails closed with a
 * {@link ConfigError} rather than silently coercing — a typo'd flag must not be
 * read as a quiet `false`.
 */
function readBool(env: Env, key: string, fallback: boolean): boolean {
  const raw = readRaw(env, key)
  if (raw === undefined) {
    return fallback
  }
  const value = raw.trim().toLowerCase()
  if (value === 'true') {
    return true
  }
  if (value === 'false') {
    return false
  }
  throw new ConfigError(`${key} must be "true" or "false", got "${raw}"`)
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
