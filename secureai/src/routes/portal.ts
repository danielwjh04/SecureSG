/**
 * `POST /api/portal` handler — open the Stripe Billing Portal.
 *
 * Authenticated (billing is never anonymous): the caller must present an API key
 * that resolves to a known account; an anonymous/unknown caller is a 401. The
 * account must already have a Stripe customer (i.e. have checked out at least
 * once); without one there is nothing to manage, which is a 422 — the client
 * should run checkout first. On success returns `{ url }` to the hosted portal.
 *
 * Billing requires `env.DB` AND the Stripe seam; either absent → 503.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { BillingGateway } from '../billing/stripe'
import { AuthError, BillingError, ParseError, ScannerError } from '../errors'
import { authenticate } from '../middleware/auth'
import { getUserById } from '../db/billing'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_UNPROCESSABLE = 422
const STATUS_BAD_GATEWAY = 502
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** Path the portal returns the customer to when they leave. */
const RETURN_PATH = '/billing'

/**
 * Resolve the authenticated user id, or throw an {@link AuthError} (→ 401).
 * Billing has no anonymous mode. Accepts a Bearer key or, when `sessionSecret`
 * is set, a session cookie.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
async function requireUserId(
  request: Request,
  db: Database,
  sessionSecret: string | null,
): Promise<string> {
  const ctx = await authenticate(request, db, sessionSecret ?? undefined)
  if (ctx.tier === 'anonymous') {
    throw new AuthError('authentication required for billing')
  }
  return ctx.subject
}

/**
 * Map a billing error to its HTTP status: AuthError → 401; ParseError → 422;
 * BillingError → 502; any other ScannerError → 500.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function statusForError(error: unknown): number {
  if (error instanceof AuthError) {
    return STATUS_UNAUTHORIZED
  }
  if (error instanceof ParseError) {
    return STATUS_UNPROCESSABLE
  }
  if (error instanceof BillingError) {
    return STATUS_BAD_GATEWAY
  }
  if (error instanceof ScannerError) {
    return STATUS_SERVER_ERROR
  }
  return STATUS_SERVER_ERROR
}

/**
 * Handle `POST /api/portal`. Requires `env.DB` AND a billing gateway (else 503).
 * Authenticates the caller (401 if anonymous), requires an existing Stripe
 * customer (422 if none — check out first), creates a Billing Portal Session,
 * and returns `{ url }`.
 *
 * Time complexity: O(1) — one user read, one portal-session create.
 * Space complexity: O(1).
 */
export async function handlePortal(
  request: Request,
  db: Database | null,
  billing: BillingGateway | null,
  config: ScannerConfig,
  sessionSecret: string | null = null,
): Promise<Response> {
  if (db === null || billing === null) {
    return Response.json(
      { error: 'service_unavailable', message: 'billing is not configured' },
      { status: STATUS_SERVICE_UNAVAILABLE },
    )
  }
  try {
    const userId = await requireUserId(request, db, sessionSecret)

    const user = await getUserById(db, userId)
    if (user === null) {
      throw new AuthError('account not found')
    }
    if (user.stripeCustomerId === null) {
      throw new ParseError('no Stripe customer for this account; start a checkout first')
    }

    const url = await billing.createPortalSession({
      customerId: user.stripeCustomerId,
      returnUrl: `${config.appBaseUrl}${RETURN_PATH}`,
    })

    return Response.json({ url }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.error(`[handlePortal] ${className}: ${message}`)
    return Response.json({ error: className, message }, { status: statusForError(error) })
  }
}
