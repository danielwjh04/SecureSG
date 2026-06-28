/**
 * Worker entry point. Routes `/api/*` to handlers; everything else 404s for now
 * (the SPA mounts via the ASSETS binding when the frontend lands).
 *
 * Config is loaded once per API request and fail-closed: any {@link ConfigError}
 * returns 500 before a handler runs, never entering the request path.
 */

import type { Env, ScannerConfig } from './config/env'
import type { Database } from './db/database'
import type { BillingGateway } from './billing/stripe'
import type { AuthDeps } from './routes/auth'
import type { ContactDeps, ContactRateLimitKv } from './routes/contact'
import type { StatsDeps } from './routes/stats'
import type { RecentScansDeps } from './routes/recentScans'
import type { AdminDeps } from './routes/admin'
import type { RateLimitKv } from './middleware/rateLimit'
import { loadConfig } from './config/env'
import { handleGuard } from './routes/guard'
import { handleScan } from './routes/scan'
import { handleSignup } from './routes/signup'
import { handleVerify } from './routes/verify'
import { handleCheckout } from './routes/checkout'
import { handlePortal } from './routes/portal'
import { handleWebhook } from './routes/webhook'
import {
  handleKeyRotate,
  handleLogin,
  handleLoginResend,
  handleLoginVerify,
  handleLogout,
  handleMe,
  handleRegister,
} from './routes/auth'
import { handleContact } from './routes/contact'
import { handleStats } from './routes/stats'
import { handleRecentScans } from './routes/recentScans'
import {
  handleAdminMemberRemove,
  handleAdminMemberRole,
  handleAdminMemberTier,
  handleAdminMembers,
  handleAdminOverview,
  handleAdminScanDetail,
  handleAdminThreats,
} from './routes/admin'
import { d1Database, d1Session, type SessionDatabase } from './db/database'
import { readBookmark, withBookmark } from './db/bookmark'
import type { ObjectStore } from './storage/r2'
import { log, errorClassOf, setLogLevel } from './observability/logger'
import { setMetricsDataset, type MetricsDataset } from './observability/metrics'
import { buildEmailSender } from './email/sender'
import { buildStripe, StripeBillingGateway } from './billing/stripe'
import { BillingError, CircuitOpenError, ParseError, ScannerError } from './errors'
import { breakerFor, type BreakerStore } from './resilience/circuitBreaker'

const ROUTE_SCAN = '/api/scan'
const ROUTE_VERIFY = '/api/verify'
const ROUTE_GUARD = '/api/guard'
const ROUTE_SIGNUP = '/api/signup'
const ROUTE_CONTACT = '/api/contact'
const ROUTE_CHECKOUT = '/api/checkout'
const ROUTE_PORTAL = '/api/portal'
const ROUTE_WEBHOOK = '/api/webhook'
const ROUTE_REGISTER = '/api/register'
const ROUTE_LOGIN = '/api/login'
const ROUTE_LOGIN_VERIFY = '/api/login/verify'
const ROUTE_LOGIN_RESEND = '/api/login/resend'
const ROUTE_LOGOUT = '/api/logout'
const ROUTE_ME = '/api/me'
const ROUTE_STATS = '/api/stats'
const ROUTE_SCANS_RECENT = '/api/scans/recent'
const ROUTE_ADMIN_OVERVIEW = '/api/admin/overview'
const ROUTE_ADMIN_THREATS = '/api/admin/threats'
const ROUTE_ADMIN_MEMBERS = '/api/admin/members'
const ROUTE_ADMIN_MEMBER_ROLE = '/api/admin/members/role'
const ROUTE_ADMIN_MEMBER_TIER = '/api/admin/members/tier'
const ROUTE_ADMIN_MEMBER_REMOVE = '/api/admin/members/remove'
/** Prefix of the caught-scan detail path; the scan id follows as `:id`. */
const ROUTE_ADMIN_SCANS_PREFIX = '/api/admin/scans/'
const ROUTE_KEY_ROTATE = '/api/key/rotate'

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (!url.pathname.startsWith('/api/')) {
      return new Response('Not found', { status: 404 })
    }

    // Correlate every log/response with the Cloudflare invocation id (cf-ray),
    // falling back to a uuid. Echoed as `x-request-id` on DB responses.
    const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID()

    let config
    try {
      config = loadConfig(env)
    } catch (error) {
      log.error('index', 'config load failed', { errorClass: errorClassOf(error), requestId })
      return jsonError('configuration error', 500)
    }

    // Point the module logger + metrics at this request's config/binding once.
    setLogLevel(config.logLevel)
    setMetricsDataset((env.METRICS as MetricsDataset | undefined) ?? null)

    // Per-request DB seam. When D1 read replication is enabled (and DB is bound),
    // open a session seeded with the caller's prior bookmark (read-your-writes):
    // their reads see at least their own writes, while others may hit a replica.
    // `stamp` returns the session's post-request bookmark to the client on every
    // DB-touching response (and tags it with `x-request-id`); a non-session db
    // (replication off) is a plain binding and the bookmark merge is a no-op.
    const session: SessionDatabase | null =
      config.dbSessionsEnabled && env.DB !== undefined && env.DB !== null
        ? d1Session(env.DB, readBookmark(request))
        : null
    const db: Database | null =
      session ?? (env.DB !== undefined && env.DB !== null ? d1Database(env.DB) : null)
    const stamp = async (response: Promise<Response>): Promise<Response> => {
      const stamped = withBookmark(
        await response,
        session?.getBookmark() ?? null,
        config.dbBookmarkTtlSeconds,
      )
      stamped.headers.set('x-request-id', requestId)
      return stamped
    }

    if (url.pathname === ROUTE_SCAN) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleScan owns its own error→status mapping and never throws.
      return await stamp(handleScan(request, env, config, db))
    }

    if (url.pathname === ROUTE_GUARD) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleGuard owns its own error→status mapping and never throws.
      return await stamp(handleGuard(request, env, config, db))
    }

    if (url.pathname === ROUTE_SIGNUP) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleSignup owns its own error→status mapping and never throws.
      return await stamp(handleSignup(request, env, db))
    }

    if (url.pathname === ROUTE_CONTACT) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleContact owns its own error→status mapping and never throws.
      return await handleContact(request, contactDeps(env, config))
    }

    if (url.pathname === ROUTE_VERIFY) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      try {
        return await handleVerify(request, config)
      } catch (error) {
        return errorResponse(error)
      }
    }

    if (url.pathname === ROUTE_CHECKOUT) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleCheckout owns its own error→status mapping and never throws.
      return await stamp(
        handleCheckout(request, db, billingGateway(env, config), config, sessionSecretOf(env)),
      )
    }

    if (url.pathname === ROUTE_PORTAL) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handlePortal owns its own error→status mapping and never throws.
      return await stamp(
        handlePortal(request, db, billingGateway(env, config), config, sessionSecretOf(env)),
      )
    }

    if (url.pathname === ROUTE_WEBHOOK) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleWebhook owns its own error→status mapping and never throws. The
      // ledger day is stamped here, at the edge, so it is deterministic per call.
      const day = new Date().toISOString()
      return await stamp(handleWebhook(request, db, billingGateway(env, config), day))
    }

    if (url.pathname === ROUTE_REGISTER) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleRegister(request, authDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_LOGIN) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleLogin(request, authDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_LOGIN_VERIFY) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleLoginVerify(request, authDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_LOGIN_RESEND) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleLoginResend(request, authDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_LOGOUT) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return handleLogout()
    }

    if (url.pathname === ROUTE_ME) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleMe(request, authDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_STATS) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleStats(request, statsDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_SCANS_RECENT) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleRecentScans(request, recentScansDeps(env, db)))
    }

    if (url.pathname === ROUTE_ADMIN_OVERVIEW) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleAdminOverview(request, adminDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_ADMIN_THREATS) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleAdminThreats(request, adminDeps(env, config, db)))
    }

    // Caught-scan detail: GET /api/admin/scans/:id. The id is the path segment
    // after the prefix; it is URL-decoded and must be non-empty (a bare
    // /api/admin/scans/ with no id is a 404). Matched before the static admin
    // routes since it is a distinct prefix.
    if (url.pathname.startsWith(ROUTE_ADMIN_SCANS_PREFIX)) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      const scanId = decodeURIComponent(url.pathname.slice(ROUTE_ADMIN_SCANS_PREFIX.length))
      if (scanId.length === 0 || scanId.includes('/')) {
        return jsonError('not found', 404)
      }
      return await stamp(handleAdminScanDetail(request, adminDeps(env, config, db), scanId))
    }

    // The role-change path is more specific than the members list path, so it is
    // matched first (an exact-equality match means order is for clarity here).
    if (url.pathname === ROUTE_ADMIN_MEMBER_ROLE) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleAdminMemberRole(request, adminDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_ADMIN_MEMBER_TIER) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleAdminMemberTier(request, adminDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_ADMIN_MEMBER_REMOVE) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleAdminMemberRemove(request, adminDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_ADMIN_MEMBERS) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleAdminMembers(request, adminDeps(env, config, db)))
    }

    if (url.pathname === ROUTE_KEY_ROTATE) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await stamp(handleKeyRotate(request, authDeps(env, config, db)))
    }

    return jsonError('not found', 404)
  },
} satisfies ExportedHandler<Env>

/**
 * Read `SESSION_SECRET` from env, or `null` when unset/empty. Cookie auth is
 * disabled (Bearer still works) when this is `null`; the register/login routes
 * return 503.
 */
function sessionSecretOf(env: Env): string | null {
  const secret = env.SESSION_SECRET
  return typeof secret === 'string' && secret.length > 0 ? secret : null
}

/**
 * Assemble the auth routes' dependencies. The `db` seam is built once per request
 * by `fetch` (session-aware when read replication is enabled) and threaded in.
 * The email sender is `null` unless `RESEND_API_KEY` is set, which is the gate
 * that activates email two-factor on login.
 */
function authDeps(env: Env, config: ScannerConfig, db: Database | null): AuthDeps {
  return {
    db,
    sessionSecret: sessionSecretOf(env),
    config,
    emailSender: buildEmailSender(env, config),
    kv: env.KV !== undefined && env.KV !== null ? (env.KV as RateLimitKv) : null,
  }
}

/**
 * Assemble the contact route's dependencies: the Resend sender (gated on
 * `RESEND_API_KEY`, `null` → 503), the KV rate-limit store (`null` → limit
 * skipped), and config (recipients, from address, rate cap). The recipients stay
 * here, server-side — they are never sent to the browser.
 */
function contactDeps(env: Env, config: ScannerConfig): ContactDeps {
  const kv = env.KV !== undefined && env.KV !== null ? (env.KV as ContactRateLimitKv) : null
  return { emailSender: buildEmailSender(env, config), kv, config }
}

/** Assemble the stats route's dependencies (DB seam threaded from `fetch`). */
function statsDeps(env: Env, config: ScannerConfig, db: Database | null): StatsDeps {
  return { db, sessionSecret: sessionSecretOf(env), config }
}

/** Assemble the recent-scans route's dependencies (DB seam threaded from `fetch`). */
function recentScansDeps(env: Env, db: Database | null): RecentScansDeps {
  return { db, sessionSecret: sessionSecretOf(env) }
}

/** Assemble the admin route's dependencies (DB seam threaded from `fetch`). */
function adminDeps(env: Env, config: ScannerConfig, db: Database | null): AdminDeps {
  const objectStore =
    config.r2Enabled && env.R2 !== undefined && env.R2 !== null ? (env.R2 as ObjectStore) : null
  return { db, sessionSecret: sessionSecretOf(env), config, objectStore }
}

/**
 * Build the {@link BillingGateway} from the Stripe secrets, or `null` when
 * either `STRIPE_SECRET_KEY` or `STRIPE_WEBHOOK_SECRET` is absent. A missing
 * secret degrades the billing routes to 503; it never fails config load for the
 * other routes (the secrets are read here, not in `loadConfig`).
 */
function billingGateway(env: Env, config: ScannerConfig): BillingGateway | null {
  const secret = env.STRIPE_SECRET_KEY
  const webhookSecret = env.STRIPE_WEBHOOK_SECRET
  if (typeof secret !== 'string' || secret.length === 0) {
    return null
  }
  if (typeof webhookSecret !== 'string' || webhookSecret.length === 0) {
    return null
  }
  const store = (env.KV as BreakerStore | undefined) ?? null
  const breaker = breakerFor(store, config, 'stripe', () =>
    new BillingError('payment provider circuit open', {
      cause: new CircuitOpenError('stripe breaker open'),
    }),
  )
  return new StripeBillingGateway(buildStripe(secret, config), webhookSecret, breaker)
}

/** Map a thrown error to an HTTP response, logging its exact class. */
function errorResponse(error: unknown): Response {
  if (error instanceof ParseError) {
    return jsonError(error.message, 422)
  }
  if (error instanceof ScannerError) {
    log.error('index', 'handler fault', { errorClass: error.name })
    return jsonError(error.message, 400)
  }
  log.error('index', 'unexpected fault', { errorClass: errorClassOf(error) })
  return jsonError('internal error', 500)
}

function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status })
}
