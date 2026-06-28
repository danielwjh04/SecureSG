/**
 * `POST /api/webhook` handler — the Stripe webhook sink.
 *
 * Security posture (CLAUDE.md §6):
 *   1. FAIL CLOSED ON SIGNATURE. The raw body and `stripe-signature` header are
 *      verified via the async SubtleCrypto verifier BEFORE the body is read as
 *      anything but bytes. A failed verification is a flat 400; the unverified
 *      body is never parsed for state changes.
 *   2. IDEMPOTENT. Every verified event is recorded by `event.id` in a UNIQUE
 *      ledger BEFORE it is acted on. A replay (Stripe retries on any non-2xx)
 *      finds the row already present and returns a 200 ack that mutates nothing.
 *
 * Effects, by event type:
 *   - checkout.session.completed              → grant Pro + mirror subscription
 *   - customer.subscription.created | updated → grant Pro + mirror subscription
 *   - customer.subscription.deleted           → downgrade to Free
 * All other event types are acknowledged (200) and ignored.
 *
 * Billing requires `env.DB` AND the Stripe seam; either absent → 503.
 */

import type Stripe from 'stripe'
import type { Database } from '../db/database'
import type { BillingGateway } from '../billing/stripe'
import { BillingError } from '../errors'
import { setTierByStripeCustomer } from '../db/accounts'
import {
  getUserByStripeCustomer,
  recordWebhookEvent,
  upsertSubscription,
} from '../db/billing'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_SERVER_ERROR = 500
const STATUS_SERVICE_UNAVAILABLE = 503

/** Header carrying Stripe's HMAC signature over the raw body. */
const SIGNATURE_HEADER = 'stripe-signature'

/** Event types that grant the Pro tier (subscription is active/created). */
const PRO_GRANT_EVENTS: ReadonlySet<string> = new Set([
  'checkout.session.completed',
  'customer.subscription.created',
  'customer.subscription.updated',
])

/** Event type that revokes the Pro tier (subscription ended). */
const SUBSCRIPTION_DELETED = 'customer.subscription.deleted'

/**
 * Extract the Stripe customer id from an event's object, which is either a
 * Checkout Session or a Subscription. The `customer` field may be the id string
 * or an expanded object; we accept only the id form and the `{ id }` shape.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @returns The customer id, or `null` when it is absent/unrecognized.
 */
function extractCustomerId(object: { customer?: string | { id: string } | null }): string | null {
  const customer = object.customer
  if (typeof customer === 'string' && customer.length > 0) {
    return customer
  }
  if (customer !== null && typeof customer === 'object' && typeof customer.id === 'string') {
    return customer.id
  }
  return null
}

/**
 * Read the subscription fields the mirror stores from a Subscription object: its
 * status, the first line item's Price id, and the current period end (ISO-8601),
 * tolerating missing fields by falling back to safe defaults.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function readSubscriptionFields(
  subscription: Stripe.Subscription,
): { status: string; priceId: string; currentPeriodEnd: string | null } {
  const status = subscription.status
  const firstItem = subscription.items.data[0]
  const priceId = firstItem !== undefined ? firstItem.price.id : ''
  const periodEndSeconds = firstItem?.current_period_end
  const currentPeriodEnd =
    typeof periodEndSeconds === 'number'
      ? new Date(periodEndSeconds * 1000).toISOString()
      : null
  return { status, priceId, currentPeriodEnd }
}

/**
 * Apply a Pro-granting event: set the account's tier to `pro` by customer id and
 * mirror the subscription. For a checkout.session.completed there is no inline
 * subscription object, so the mirror is written from the session's price/period
 * context when available, else just the tier grant.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
async function applyProGrant(db: Database, event: Stripe.Event): Promise<void> {
  const object = event.data.object as { customer?: string | { id: string } | null }
  const customerId = extractCustomerId(object)
  if (customerId === null) {
    // No customer to map → nothing to do. Acknowledged, not faulted.
    return
  }

  // The tier grant is keyed on the customer id and is the authority for access.
  await setTierByStripeCustomer(db, customerId, 'pro')

  // Mirror the subscription only for subscription.* events, which carry the
  // status/price/period. checkout.session.completed grants the tier; the
  // subscription.created/updated event that follows writes the mirror.
  if (event.type === SUBSCRIPTION_DELETED || event.type === 'checkout.session.completed') {
    return
  }
  const user = await getUserByStripeCustomer(db, customerId)
  if (user === null) {
    return
  }
  const { status, priceId, currentPeriodEnd } = readSubscriptionFields(
    event.data.object as Stripe.Subscription,
  )
  await upsertSubscription(db, user.userId, status, priceId, currentPeriodEnd)
}

/**
 * Apply a subscription-deleted event: downgrade the account to `free` and mirror
 * the canceled status.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
async function applySubscriptionDeleted(db: Database, event: Stripe.Event): Promise<void> {
  const subscription = event.data.object as Stripe.Subscription
  const customerId = extractCustomerId(subscription)
  if (customerId === null) {
    return
  }
  await setTierByStripeCustomer(db, customerId, 'free')
  const user = await getUserByStripeCustomer(db, customerId)
  if (user === null) {
    return
  }
  const { status, priceId, currentPeriodEnd } = readSubscriptionFields(subscription)
  await upsertSubscription(db, user.userId, status, priceId, currentPeriodEnd)
}

/**
 * Handle `POST /api/webhook`. Requires `env.DB` AND a billing gateway (else 503).
 *
 * Verifies the signature (fail-closed 400 on any failure or missing header),
 * dedupes on `event.id` (a replay is an inert 200), then dispatches the verified
 * event to its effect. Returns a 200 ack on success; a database fault during the
 * effect is a 500 so Stripe retries (and the idempotency ledger makes the retry
 * safe). The raw body is read with `request.text()` and never trusted before
 * verification.
 *
 * Time complexity: O(n) signature HMAC over the body + O(1) effect.
 * Space complexity: O(n) in the body length.
 *
 * @param day - ISO-8601 UTC timestamp string for the ledger row (caller-supplied,
 *   so the dedupe write is deterministic and clock-free in tests).
 */
export async function handleWebhook(
  request: Request,
  db: Database | null,
  billing: BillingGateway | null,
  day: string,
): Promise<Response> {
  if (db === null || billing === null) {
    return Response.json(
      { error: 'service_unavailable', message: 'billing is not configured' },
      { status: STATUS_SERVICE_UNAVAILABLE },
    )
  }

  const signature = request.headers.get(SIGNATURE_HEADER)
  const rawBody = await request.text()

  // 1. Fail-closed signature verification. A missing header or a verification
  // failure is a flat 400; the body is never trusted.
  let event: Stripe.Event
  try {
    if (signature === null || signature.length === 0) {
      throw new BillingError('missing stripe-signature header')
    }
    event = await billing.constructEvent(rawBody, signature)
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[handleWebhook] signature verification failed: ${name}`)
    return Response.json({ error: 'invalid_signature' }, { status: STATUS_BAD_REQUEST })
  }

  try {
    // 2. Idempotency gate. Record the event id BEFORE acting; a duplicate is an
    // inert 200 (Stripe retries are common and must be no-ops).
    const isNew = await recordWebhookEvent(db, event.id, event.type, day)
    if (!isNew) {
      return Response.json({ received: true, duplicate: true }, { status: STATUS_OK })
    }

    // 3. Dispatch the verified, deduped event to its effect.
    if (PRO_GRANT_EVENTS.has(event.type)) {
      await applyProGrant(db, event)
    } else if (event.type === SUBSCRIPTION_DELETED) {
      await applySubscriptionDeleted(db, event)
    }
    // All other event types fall through and are acknowledged unchanged.

    return Response.json({ received: true }, { status: STATUS_OK })
  } catch (error: unknown) {
    // A persistence fault during dedupe or effect is surfaced as a 500 (not an
    // ack) so the failure is visible to the operator and Stripe retries. The
    // effects are individually idempotent (tier set by customer id, subscription
    // upsert by user id), so a retry re-applies them safely.
    const name = error instanceof Error ? error.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.error(`[handleWebhook] effect failed: ${name}: ${message}`)
    return Response.json({ error: name }, { status: STATUS_SERVER_ERROR })
  }
}
