/**
 * In-app plan management: change (upgrade/downgrade) and cancel a subscription
 * without leaving the site, plus a read of the current subscription snapshot the
 * dynamic pricing page renders.
 *   - POST /api/billing/change  { tier }  → swap the subscription's price in place
 *   - POST /api/billing/cancel            → schedule cancellation at period end
 *   - GET  /api/billing/subscription      → { hasSubscription, cancelAtPeriodEnd, currentPeriodEnd }
 *
 * Authenticated (Bearer key OR session cookie); an anonymous caller is 401.
 *
 * Tier authority (CLAUDE.md §6): the granted tier lives on `users.tier`. A change
 * optimistically sets it and the `customer.subscription.updated` webhook re-affirms
 * it (idempotent). A cancel NEVER downgrades now, access is kept until period end
 * and the `customer.subscription.deleted` webhook downgrades to free then.
 *
 * The mutating routes require `env.DB` AND the Stripe seam (503 otherwise); the
 * subscription read degrades to "no subscription" so the pricing page still works.
 */

import type { ScannerConfig } from '../config/env'
import type { Database } from '../db/database'
import type { BillingGateway, PaidCheckoutTier } from '../billing/stripe'
import { AuthError, BillingError, ParseError, ScannerError } from '../errors'
import { getUserById } from '../db/billing'
import { setUserTier } from '../db/accounts'
import { priceIdForTier, requireUserId } from './checkout'
import { billingChangeSchema } from '../schemas/validate'
import { log } from '../observability/logger'

const STATUS_OK = 200
const STATUS_UNAUTHORIZED = 401
const STATUS_UNPROCESSABLE = 422
const STATUS_BAD_GATEWAY = 502
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/**
 * The 200 body of `GET /api/billing/subscription` (and the `POST .../cancel`
 * result): whether the account has an active subscription, whether a cancellation
 * is already scheduled, and the ISO end of the current period (or `null`).
 */
export interface SubscriptionStatusResponse {
  readonly hasSubscription: boolean
  readonly cancelAtPeriodEnd: boolean
  readonly currentPeriodEnd: string | null
}

/** The benign "no subscription" snapshot returned when billing is unavailable. */
const NO_SUBSCRIPTION: SubscriptionStatusResponse = {
  hasSubscription: false,
  cancelAtPeriodEnd: false,
  currentPeriodEnd: null,
}

/** 503 body when the account store or Stripe seam is not configured. */
function serviceUnavailable(): Response {
  return Response.json(
    { error: 'service_unavailable', message: 'billing is not configured' },
    { status: STATUS_SERVICE_UNAVAILABLE },
  )
}

/** 422 body for a business-rule rejection (no subscription / already on plan). */
function unprocessable(error: string, message: string): Response {
  return Response.json({ error, message }, { status: STATUS_UNPROCESSABLE })
}

/**
 * Map a billing error to its HTTP status: AuthError → 401; ParseError → 422;
 * BillingError → 502 (upstream Stripe fault); any other ScannerError (e.g. a
 * misconfigured price) → 500.
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

/** Log the error CLASS (never the message/body) and build the mapped response. */
function errorResponse(operation: string, error: unknown): Response {
  const className = error instanceof Error ? error.constructor.name : typeof error
  const message = error instanceof Error ? error.message : String(error)
  log.error(operation, 'request failed', { errorClass: className })
  return Response.json({ error: className, message }, { status: statusForError(error) })
}

/**
 * Parse + Zod-validate the change-plan body, or throw {@link ParseError} (→ 422).
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 */
async function readChangeTier(request: Request): Promise<PaidCheckoutTier> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('invalid change-plan request body', { cause: error })
  }
  const parsed = billingChangeSchema.safeParse(raw)
  if (!parsed.success) {
    throw new ParseError('invalid change-plan request body')
  }
  return parsed.data.tier
}

/**
 * Handle `POST /api/billing/change`. Authenticates the caller (401 anon), resolves
 * their active subscription, and swaps its price to the requested paid tier in
 * place (422 when there is no active subscription or it is already on that plan).
 * Optimistically sets `users.tier`; the webhook re-affirms it. Requires `env.DB`
 * AND the Stripe seam (503 otherwise).
 *
 * Time complexity: O(1), a bounded set of Stripe/DB round-trips. Space: O(1).
 */
export async function handleChangePlan(
  request: Request,
  db: Database | null,
  billing: BillingGateway | null,
  config: ScannerConfig,
  sessionSecret: string | null = null,
): Promise<Response> {
  if (db === null || billing === null) {
    return serviceUnavailable()
  }
  try {
    const tier = await readChangeTier(request)
    const userId = await requireUserId(request, db, sessionSecret)
    const user = await getUserById(db, userId)
    if (user === null) {
      throw new AuthError('account not found')
    }
    if (user.stripeCustomerId === null) {
      return unprocessable('no_subscription', 'start a subscription before changing plan')
    }
    const newPriceId = priceIdForTier(tier, config)
    const active = await billing.getActiveSubscription(user.stripeCustomerId)
    if (active === null) {
      return unprocessable('no_subscription', 'no active subscription to change')
    }
    if (active.priceId === newPriceId) {
      return unprocessable('already_on_plan', 'this plan is already active')
    }
    await billing.changeSubscriptionPrice({
      subscriptionId: active.subscriptionId,
      itemId: active.itemId,
      newPriceId,
      tier,
      prorationBehavior: config.stripeProrationBehavior,
    })
    await setUserTier(db, userId, tier)
    return Response.json({ tier }, { status: STATUS_OK })
  } catch (error: unknown) {
    return errorResponse('handleChangePlan', error)
  }
}

/**
 * Handle `POST /api/billing/cancel`. Authenticates the caller (401 anon), resolves
 * their active subscription, and schedules it to cancel at period end (422 when
 * there is no active subscription). Does NOT downgrade now: access is kept until
 * period end, and the deletion webhook downgrades to free then. Returns the
 * updated snapshot so the client can show the effective date. Requires `env.DB`
 * AND the Stripe seam (503 otherwise).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export async function handleCancelPlan(
  request: Request,
  db: Database | null,
  billing: BillingGateway | null,
  sessionSecret: string | null = null,
): Promise<Response> {
  if (db === null || billing === null) {
    return serviceUnavailable()
  }
  try {
    const userId = await requireUserId(request, db, sessionSecret)
    const user = await getUserById(db, userId)
    if (user === null) {
      throw new AuthError('account not found')
    }
    if (user.stripeCustomerId === null) {
      return unprocessable('no_subscription', 'no active subscription to cancel')
    }
    const active = await billing.getActiveSubscription(user.stripeCustomerId)
    if (active === null) {
      return unprocessable('no_subscription', 'no active subscription to cancel')
    }
    const updated = await billing.cancelSubscription(active.subscriptionId)
    const body: SubscriptionStatusResponse = {
      hasSubscription: true,
      cancelAtPeriodEnd: updated.cancelAtPeriodEnd,
      currentPeriodEnd: updated.currentPeriodEnd,
    }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    return errorResponse('handleCancelPlan', error)
  }
}

/**
 * Handle `GET /api/billing/subscription`. Authenticates the caller (401 anon) and
 * returns their live subscription snapshot for the dynamic pricing page. Degrades
 * to "no subscription" (200) when the store/gateway is absent or the account has
 * no Stripe customer / active subscription, so the page always renders.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export async function handleSubscriptionStatus(
  request: Request,
  db: Database | null,
  billing: BillingGateway | null,
  sessionSecret: string | null = null,
): Promise<Response> {
  if (db === null) {
    return Response.json(NO_SUBSCRIPTION, { status: STATUS_OK })
  }
  try {
    const userId = await requireUserId(request, db, sessionSecret)
    const user = await getUserById(db, userId)
    if (user === null || user.stripeCustomerId === null || billing === null) {
      return Response.json(NO_SUBSCRIPTION, { status: STATUS_OK })
    }
    const active = await billing.getActiveSubscription(user.stripeCustomerId)
    if (active === null) {
      return Response.json(NO_SUBSCRIPTION, { status: STATUS_OK })
    }
    const body: SubscriptionStatusResponse = {
      hasSubscription: true,
      cancelAtPeriodEnd: active.cancelAtPeriodEnd,
      currentPeriodEnd: active.currentPeriodEnd,
    }
    return Response.json(body, { status: STATUS_OK })
  } catch (error: unknown) {
    return errorResponse('handleSubscriptionStatus', error)
  }
}
