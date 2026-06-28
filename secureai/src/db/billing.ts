/**
 * Billing repository: webhook idempotency, the subscription mirror, and the
 * user↔Stripe-customer link, all over the narrow {@link Database} seam.
 *
 * Idempotency (CLAUDE.md §2): {@link recordWebhookEvent} is the dedupe gate. It
 * inserts the Stripe `event.id` with `ON CONFLICT DO NOTHING` and reports
 * whether the row was new, so a webhook is acted on AT MOST ONCE no matter how
 * many times Stripe retries it.
 *
 * Every write fails loudly: a database fault raises {@link BillingError} rather
 * than being swallowed, so the webhook returns non-2xx and Stripe retries.
 */

import type { Database, Row } from './database'
import { BillingError } from '../errors'

/** A user's Stripe customer id, or `null` when none has been provisioned. */
export interface StripeCustomerLink {
  readonly userId: string
  readonly email: string | null
  readonly stripeCustomerId: string | null
}

/** Read a column as a string, or `null` when absent/non-string. */
function readNullableString(row: Row, column: string): string | null {
  const value = row[column]
  return typeof value === 'string' && value.length > 0 ? value : null
}

/** Read a column as a non-empty string, failing closed on a malformed record. */
function requireString(row: Row, column: string): string {
  const value = row[column]
  if (typeof value !== 'string' || value.length === 0) {
    throw new BillingError(`stored billing record missing string column: ${column}`)
  }
  return value
}

/**
 * Record a webhook event id for idempotency, returning whether it was NEW.
 *
 * Uses `INSERT ... ON CONFLICT (event_id) DO NOTHING` and detects a duplicate by
 * inspecting the write's `meta.changes`: a fresh insert reports 1 changed row, a
 * conflict reports 0. The caller acts on the event ONLY when this returns `true`;
 * a `false` is a replay and must be a no-op 200 (CLAUDE.md §2, idempotency).
 *
 * This is the first statement the webhook runs, BEFORE any tier mutation, so the
 * mutation can never be applied twice for one Stripe event.
 *
 * Time complexity: O(1) — single primary-key insert. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param eventId - Stripe's `event.id` (globally unique per event).
 * @param type - The Stripe event type, stored for audit/debug.
 * @param day - ISO-8601 UTC timestamp string, supplied by the caller.
 * @returns `true` if the event was newly recorded, `false` if already seen.
 * @throws {BillingError} On a database failure.
 */
export async function recordWebhookEvent(
  db: Database,
  eventId: string,
  type: string,
  day: string,
): Promise<boolean> {
  try {
    const result = await db.execute(
      'INSERT INTO webhook_events (event_id, type, created_at) VALUES (?, ?, ?) ' +
        'ON CONFLICT (event_id) DO NOTHING',
      [eventId, type, day],
    )
    return result.changes > 0
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[billing] recordWebhookEvent failed: ${name}`)
    throw new BillingError('failed to record webhook event', { cause: error })
  }
}

/**
 * Upsert the local mirror of a user's Stripe subscription state.
 *
 * Idempotent on `user_id`: replaying the same `(status, priceId, periodEnd)`
 * leaves the row identical, and a status change (e.g. `active` → `canceled`)
 * overwrites in place. The mirror is auditable against Stripe but is never the
 * authority for access — the granted tier on `users.tier` is.
 *
 * Time complexity: O(1) — single primary-key upsert. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param userId - The account the subscription belongs to.
 * @param status - The Stripe subscription status (e.g. `active`, `canceled`).
 * @param priceId - The subscribed Price id.
 * @param currentPeriodEnd - ISO-8601 end of the current period, or `null`.
 * @throws {BillingError} On a database failure.
 */
export async function upsertSubscription(
  db: Database,
  userId: string,
  status: string,
  priceId: string,
  currentPeriodEnd: string | null,
): Promise<void> {
  try {
    await db.execute(
      'INSERT INTO subscriptions (user_id, status, price_id, current_period_end) ' +
        'VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT (user_id) DO UPDATE SET ' +
        'status = excluded.status, price_id = excluded.price_id, ' +
        'current_period_end = excluded.current_period_end',
      [userId, status, priceId, currentPeriodEnd],
    )
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[billing] upsertSubscription failed: ${name}`)
    throw new BillingError('failed to upsert subscription', { cause: error })
  }
}

/**
 * Persist a user's Stripe customer id (the user↔customer link).
 *
 * Idempotent for the same `(userId, customerId)`. Writing an unknown user id is
 * a zero-row no-op rather than an error.
 *
 * Time complexity: O(1) — primary-key update. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param userId - The account to link.
 * @param customerId - The Stripe customer id to persist.
 * @throws {BillingError} On a database failure.
 */
export async function setStripeCustomerId(
  db: Database,
  userId: string,
  customerId: string,
): Promise<void> {
  try {
    await db.execute('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [
      customerId,
      userId,
    ])
  } catch (error: unknown) {
    const name = error instanceof Error ? error.name : typeof error
    console.error(`[billing] setStripeCustomerId failed: ${name}`)
    throw new BillingError('failed to set Stripe customer id', { cause: error })
  }
}

/**
 * Read a user by id, returning the fields the checkout flow needs (email and the
 * current Stripe customer link), or `null` when the id is unknown.
 *
 * Time complexity: O(1) — primary-key lookup. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param userId - The account id.
 * @returns The user's billing link, or `null` on a miss.
 * @throws {BillingError} If a matched record is structurally corrupt.
 */
export async function getUserById(
  db: Database,
  userId: string,
): Promise<StripeCustomerLink | null> {
  const row = await db.queryOne(
    'SELECT id, email, stripe_customer_id FROM users WHERE id = ?',
    [userId],
  )
  if (row === null) {
    return null
  }
  return {
    userId: requireString(row, 'id'),
    email: readNullableString(row, 'email'),
    stripeCustomerId: readNullableString(row, 'stripe_customer_id'),
  }
}

/**
 * Resolve the user behind a Stripe customer id, or `null` when none matches.
 *
 * Used by the webhook to map a Stripe customer back to an account. A customer id
 * that matches no user resolves to `null` — an event for an unknown customer is
 * acknowledged, not faulted.
 *
 * Time complexity: O(1) — indexed lookup on `stripe_customer_id`.
 * Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @param customerId - The Stripe customer id from the event.
 * @returns The owning user's link, or `null` on a miss.
 * @throws {BillingError} If a matched record is structurally corrupt.
 */
export async function getUserByStripeCustomer(
  db: Database,
  customerId: string,
): Promise<StripeCustomerLink | null> {
  const row = await db.queryOne(
    'SELECT id, email, stripe_customer_id FROM users WHERE stripe_customer_id = ?',
    [customerId],
  )
  if (row === null) {
    return null
  }
  return {
    userId: requireString(row, 'id'),
    email: readNullableString(row, 'email'),
    stripeCustomerId: readNullableString(row, 'stripe_customer_id'),
  }
}
