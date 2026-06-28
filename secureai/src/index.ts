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
  handleLogout,
  handleMe,
  handleRegister,
} from './routes/auth'
import { handleStats } from './routes/stats'
import { handleAdminOverview } from './routes/admin'
import { d1Database } from './db/database'
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
const ROUTE_LOGOUT = '/api/logout'
const ROUTE_ME = '/api/me'
const ROUTE_STATS = '/api/stats'
const ROUTE_ADMIN_OVERVIEW = '/api/admin/overview'
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

    if (url.pathname === ROUTE_ADMIN_OVERVIEW) {
      if (request.method !== 'GET') {
        return jsonError('method not allowed', 405)
      }
      return await handleAdminOverview(request, adminDeps(env, config))
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

/** Assemble the auth routes' dependencies (DB seam, session secret, config). */
function authDeps(env: Env, config: ScannerConfig): AuthDeps {
  return { db: billingDatabase(env), sessionSecret: sessionSecretOf(env), config }
}

/** Assemble the stats route's dependencies (DB seam, session secret, config). */
function statsDeps(env: Env, config: ScannerConfig): StatsDeps {
  return { db: billingDatabase(env), sessionSecret: sessionSecretOf(env), config }
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
