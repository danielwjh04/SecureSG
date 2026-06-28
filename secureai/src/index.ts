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
import type { StatsDeps } from './routes/stats'
import type { RecentScansDeps } from './routes/recentScans'
import type { AdminDeps } from './routes/admin'
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
import { d1Database } from './db/database'
import { buildEmailSender } from './email/sender'
import { buildStripe, StripeBillingGateway } from './billing/stripe'
import { ParseError, ScannerError } from './errors'

const ROUTE_SCAN = '/api/scan'
const ROUTE_VERIFY = '/api/verify'
const ROUTE_GUARD = '/api/guard'
const ROUTE_SIGNUP = '/api/signup'
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

    let config
    try {
      config = loadConfig(env)
    } catch (error) {
      console.error(`config load failed: ${errorName(error)}`)
      return jsonError('configuration error', 500)
    }

    if (url.pathname === ROUTE_SCAN) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleScan owns its own error→status mapping and never throws.
      return await handleScan(request, env, config)
    }

    if (url.pathname === ROUTE_GUARD) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleGuard owns its own error→status mapping and never throws.
      return await handleGuard(request, env, config)
    }

    if (url.pathname === ROUTE_SIGNUP) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleSignup owns its own error→status mapping and never throws.
      return await handleSignup(request, env)
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
      return await handleCheckout(
        request,
        billingDatabase(env),
        billingGateway(env),
        config,
        sessionSecretOf(env),
      )
    }

    if (url.pathname === ROUTE_PORTAL) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handlePortal owns its own error→status mapping and never throws.
      return await handlePortal(
        request,
        billingDatabase(env),
        billingGateway(env),
        config,
        sessionSecretOf(env),
      )
    }

    if (url.pathname === ROUTE_WEBHOOK) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      // handleWebhook owns its own error→status mapping and never throws. The
      // ledger day is stamped here, at the edge, so it is deterministic per call.
      const day = new Date().toISOString()
      return await handleWebhook(request, billingDatabase(env), billingGateway(env), day)
    }

    if (url.pathname === ROUTE_REGISTER) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleRegister(request, authDeps(env, config))
    }

    if (url.pathname === ROUTE_LOGIN) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleLogin(request, authDeps(env, config))
    }

    if (url.pathname === ROUTE_LOGIN_VERIFY) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleLoginVerify(request, authDeps(env, config))
    }

    if (url.pathname === ROUTE_LOGIN_RESEND) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleLoginResend(request, authDeps(env, config))
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
      return await handleMe(request, authDeps(env, config))
    }

    if (url.pathname === ROUTE_STATS) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await handleStats(request, statsDeps(env, config))
    }

    if (url.pathname === ROUTE_SCANS_RECENT) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await handleRecentScans(request, recentScansDeps(env))
    }

    if (url.pathname === ROUTE_ADMIN_OVERVIEW) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminOverview(request, adminDeps(env, config))
    }

    if (url.pathname === ROUTE_ADMIN_THREATS) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminThreats(request, adminDeps(env, config))
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
      return await handleAdminScanDetail(request, adminDeps(env, config), scanId)
    }

    // The role-change path is more specific than the members list path, so it is
    // matched first (an exact-equality match means order is for clarity here).
    if (url.pathname === ROUTE_ADMIN_MEMBER_ROLE) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminMemberRole(request, adminDeps(env, config))
    }

    if (url.pathname === ROUTE_ADMIN_MEMBER_TIER) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminMemberTier(request, adminDeps(env, config))
    }

    if (url.pathname === ROUTE_ADMIN_MEMBER_REMOVE) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminMemberRemove(request, adminDeps(env, config))
    }

    if (url.pathname === ROUTE_ADMIN_MEMBERS) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminMembers(request, adminDeps(env, config))
    }

    if (url.pathname === ROUTE_KEY_ROTATE) {
      if (request.method !== 'POST') {
        return jsonError('method not allowed', 405)
      }
      return await handleKeyRotate(request, authDeps(env, config))
    }

    return jsonError('not found', 404)
  },
} satisfies ExportedHandler<Env>

/**
 * Build the {@link Database} seam from the `DB` binding, or `null` when D1 is
 * not bound. The billing routes return 503 on `null` rather than crashing.
 */
function billingDatabase(env: Env): Database | null {
  return env.DB !== undefined && env.DB !== null ? d1Database(env.DB) : null
}

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
 * Assemble the auth routes' dependencies (DB seam, session secret, config, and
 * the email sender). The email sender is `null` unless `RESEND_API_KEY` is set,
 * which is the gate that activates email two-factor on login.
 */
function authDeps(env: Env, config: ScannerConfig): AuthDeps {
  return {
    db: billingDatabase(env),
    sessionSecret: sessionSecretOf(env),
    config,
    emailSender: buildEmailSender(env, config),
  }
}

/** Assemble the stats route's dependencies (DB seam, session secret, config). */
function statsDeps(env: Env, config: ScannerConfig): StatsDeps {
  return { db: billingDatabase(env), sessionSecret: sessionSecretOf(env), config }
}

/** Assemble the recent-scans route's dependencies (DB seam, session secret). */
function recentScansDeps(env: Env): RecentScansDeps {
  return { db: billingDatabase(env), sessionSecret: sessionSecretOf(env) }
}

/** Assemble the admin route's dependencies (DB seam, session secret, config). */
function adminDeps(env: Env, config: ScannerConfig): AdminDeps {
  return { db: billingDatabase(env), sessionSecret: sessionSecretOf(env), config }
}

/**
 * Build the {@link BillingGateway} from the Stripe secrets, or `null` when
 * either `STRIPE_SECRET_KEY` or `STRIPE_WEBHOOK_SECRET` is absent. A missing
 * secret degrades the billing routes to 503; it never fails config load for the
 * other routes (the secrets are read here, not in `loadConfig`).
 */
function billingGateway(env: Env): BillingGateway | null {
  const secret = env.STRIPE_SECRET_KEY
  const webhookSecret = env.STRIPE_WEBHOOK_SECRET
  if (typeof secret !== 'string' || secret.length === 0) {
    return null
  }
  if (typeof webhookSecret !== 'string' || webhookSecret.length === 0) {
    return null
  }
  return new StripeBillingGateway(buildStripe(secret), webhookSecret)
}

/** Map a thrown error to an HTTP response, logging its exact class. */
function errorResponse(error: unknown): Response {
  if (error instanceof ParseError) {
    return jsonError(error.message, 422)
  }
  if (error instanceof ScannerError) {
    console.error(`handler fault: ${error.name}: ${error.message}`)
    return jsonError(error.message, 400)
  }
  console.error(`unexpected fault: ${errorName(error)}`)
  return jsonError('internal error', 500)
}

function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status })
}

function errorName(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error)
}
