/**
 * `POST /api/checkout` handler, start a paid subscription.
 *
 * Authenticated: the caller must present an `Authorization: Bearer <key>` that
 * resolves to a known account. An anonymous or unknown-key caller is a 401
 * {@link AuthError} (unlike the metering routes, billing is never anonymous
 * there is no account to bill). The handler ensures the account has a Stripe
 * customer (creating and persisting one on first checkout), opens a subscription
 * Checkout Session for the requested paid tier, and returns `{ url }`.
 *
 * Billing requires both the account store (`env.DB`) and the Stripe seam; when
 * either is absent the route returns 503 rather than fabricating a session.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { BillingGateway, PaidCheckoutTier } from '../billing/stripe'
import { AuthError, BillingError, ConfigError, ParseError, ScannerError } from '../errors'
import { authenticate } from '../middleware/auth'
import { getUserById, setStripeCustomerId } from '../db/billing'
import { log } from '../observability/logger'
import { z } from 'zod'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_UNPROCESSABLE = 422
const STATUS_BAD_GATEWAY = 502
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** Path segments appended to the app base URL for post-checkout redirects. */
const SUCCESS_PATH = '/billing/success'
const CANCEL_PATH = '/billing/cancel'

const checkoutSchema = z
  .object({
    tier: z.enum(['personal', 'pro']).optional(),
  })
  .strict()

/**
 * Resolve the Stripe Price id for a paid tier, failing loudly on an unconfigured
 * placeholder (`price_REPLACE...`) so a misconfigured tier is a clear
 * {@link ConfigError} rather than an opaque Stripe fault at session creation.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @throws {ConfigError} When the tier's Price id is still a placeholder.
 */
function priceIdForTier(tier: PaidCheckoutTier, config: ScannerConfig): string {
  const priceId = tier === 'personal' ? config.stripePricePersonal : config.stripePricePro
  if (priceId.startsWith('price_REPLACE')) {
    throw new ConfigError(`Stripe price for the ${tier} tier is not configured`)
  }
  return priceId
}

/**
 * Resolve the authenticated user id, or throw an {@link AuthError}. Billing has
 * no anonymous mode: a caller without a credential, or with an unknown one,
 * resolves to the anonymous pseudo-tier and is rejected here (mapped to 401).
 * Accepts either a Bearer key or, when `sessionSecret` is set, a session cookie.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @throws {AuthError} When the caller is not an authenticated account.
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
 * BillingError → 502 (upstream Stripe fault); any other ScannerError → 500.
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
 * Parse the optional checkout body. For backward compatibility, no JSON body
 * means Pro. When JSON is present, it must be `{ "tier": "personal" }` or
 * `{ "tier": "pro" }`.
 *
 * Time complexity: O(n) in the request body size. Space complexity: O(n).
 *
 * @throws {ParseError} On malformed JSON or an unrecognized tier.
 */
async function readCheckoutTier(request: Request): Promise<PaidCheckoutTier> {
  const contentType = request.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().includes('application/json')) {
    return 'pro'
  }
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('invalid checkout request body', { cause: error })
  }
  const parsed = checkoutSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError('invalid checkout request body')
  }
  return parsed.data.tier ?? 'pro'
}

/**
 * Handle `POST /api/checkout`. Requires `env.DB` AND a billing gateway; without
 * either, returns 503. Authenticates the caller (401 if anonymous), ensures the
 * account has a Stripe customer (persisting a new one on first checkout), opens
 * a subscription Checkout Session for the requested paid tier, and returns
 * `{ url }`.
 *
 * Idempotent customer creation: the gateway keys customer creation on the user
 * id, so a retried checkout reuses one logical customer; the new id is persisted
 * only when the account had none.
 *
 * Time complexity: O(1), at most one user read, one customer create, one
 * session create. Space complexity: O(1).
 */
export async function handleCheckout(
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
    const tier = await readCheckoutTier(request)
    const userId = await requireUserId(request, db, sessionSecret)

    const user = await getUserById(db, userId)
    if (user === null) {
      // The key resolved to a user id, but the row is gone, treat as unauthenticated.
      throw new AuthError('account not found')
    }

    // Resolve the price before any Stripe write so a misconfigured tier fails
    // fast (a clear ConfigError) instead of minting a customer and then a
    // session against a placeholder price.
    const priceId = priceIdForTier(tier, config)

    let customerId = user.stripeCustomerId
    if (customerId === null) {
      customerId = await billing.ensureCustomer(userId, user.email)
      await setStripeCustomerId(db, userId, customerId)
    }

    const base = config.appBaseUrl
    const url = await billing.createCheckoutSession({
      customerId,
      priceId,
      tier,
      successUrl: `${base}${SUCCESS_PATH}`,
      cancelUrl: `${base}${CANCEL_PATH}`,
    })

    return Response.json({ url }, { status: STATUS_OK })
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    log.error('handleCheckout', 'request failed', { errorClass: className })
    return Response.json({ error: className, message }, { status: statusForError(error) })
  }
}
