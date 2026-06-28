import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser, findUserByApiKey } from '../db/accounts'
import { setStripeCustomerId } from '../db/billing'
import {
  FakeBillingGateway,
  stripeEvent,
  subscriptionObject,
} from '../billing/fake.test'
import { handleWebhook } from './webhook'

const DAY = '2026-06-28T00:00:00.000Z'
const PERIOD_END_SECONDS = 1_800_000_000

function post(signature?: string): Request {
  const headers: Record<string, string> = {}
  if (signature !== undefined) {
    headers['stripe-signature'] = signature
  }
  return new Request('https://secureai.test/api/webhook', {
    method: 'POST',
    headers,
    body: '{"raw":"stripe-payload"}',
  })
}

describe('handleWebhook signature', () => {
  it('rejects an invalid signature with 400 and does not act', async () => {
    const { db, store } = memoryDatabase()
    const gw = new FakeBillingGateway() // event stays null → constructEvent rejects

    const res = await handleWebhook(post('bad-sig'), db, gw, DAY)
    expect(res.status).toBe(400)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('invalid_signature')
    expect(store.webhookEvents.size).toBe(0)
  })

  it('rejects a missing signature header with 400', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent('evt_x', 'checkout.session.completed', { customer: 'cus_1' })

    const res = await handleWebhook(post(), db, gw, DAY)
    expect(res.status).toBe(400)
    // constructEvent must never run when the signature header is absent.
    expect(gw.calls).not.toContain('constructEvent')
  })

  it('returns 503 when billing is not configured', async () => {
    const res = await handleWebhook(post('sig'), null, null, DAY)
    expect(res.status).toBe(503)
  })
})

describe('handleWebhook effects', () => {
  it('grants pro and mirrors the subscription on subscription.updated', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'sub@example.com')
    await setStripeCustomerId(db, user.id, 'cus_sub')

    const gw = new FakeBillingGateway()
    gw.event = stripeEvent(
      'evt_sub_updated',
      'customer.subscription.updated',
      subscriptionObject('cus_sub', 'active', 'price_pro_12', PERIOD_END_SECONDS),
    )

    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { received: boolean }
    expect(body.received).toBe(true)

    // Tier upgraded to pro.
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'pro' })
    // Subscription mirrored with the price and ISO period end.
    expect(store.subscriptions.get(user.id)).toEqual({
      user_id: user.id,
      status: 'active',
      price_id: 'price_pro_12',
      current_period_end: new Date(PERIOD_END_SECONDS * 1000).toISOString(),
    })
  })

  it('grants pro on checkout.session.completed (tier set; mirror written by the sub event)', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'checkout@example.com')
    await setStripeCustomerId(db, user.id, 'cus_chk')

    const gw = new FakeBillingGateway()
    gw.event = stripeEvent('evt_checkout', 'checkout.session.completed', {
      customer: 'cus_chk',
      subscription: 'sub_123',
    })

    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'pro' })
  })

  it('dedupes a replayed event id as an inert 200 (no second effect)', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'dup@example.com')
    await setStripeCustomerId(db, user.id, 'cus_dup')

    const gw = new FakeBillingGateway()
    gw.event = stripeEvent(
      'evt_once',
      'customer.subscription.updated',
      subscriptionObject('cus_dup', 'active', 'price_pro_12', PERIOD_END_SECONDS),
    )

    const first = await handleWebhook(post('sig'), db, gw, DAY)
    expect(first.status).toBe(200)
    expect((await first.json()) as { duplicate?: boolean }).not.toHaveProperty('duplicate')

    // Downgrade the user out-of-band; a replay of the SAME event id must NOT
    // re-apply the pro grant.
    const stored = store.users.get(user.id)
    if (stored !== undefined) {
      stored.tier = 'free'
    }

    const second = await handleWebhook(post('sig'), db, gw, DAY)
    expect(second.status).toBe(200)
    const body = (await second.json()) as { duplicate: boolean }
    expect(body.duplicate).toBe(true)
    // The replay was inert: the out-of-band downgrade still stands.
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'free' })
  })

  it('downgrades to free on customer.subscription.deleted', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'cancel@example.com')
    await setStripeCustomerId(db, user.id, 'cus_cancel')
    // Pre-grant pro so the downgrade is observable.
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent(
      'evt_active',
      'customer.subscription.updated',
      subscriptionObject('cus_cancel', 'active', 'price_pro_12', PERIOD_END_SECONDS),
    )
    await handleWebhook(post('sig'), db, gw, DAY)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'pro' })

    gw.event = stripeEvent(
      'evt_deleted',
      'customer.subscription.deleted',
      subscriptionObject('cus_cancel', 'canceled', 'price_pro_12', PERIOD_END_SECONDS),
    )
    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'free' })
  })

  it('acknowledges a subscription event for an unknown customer without faulting', async () => {
    const { db, store } = memoryDatabase()
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent(
      'evt_unknown_cust',
      'customer.subscription.updated',
      subscriptionObject('cus_nobody', 'active', 'price_pro_12', PERIOD_END_SECONDS),
    )
    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
    // No user matched the customer → no subscription mirror written.
    expect(store.subscriptions.size).toBe(0)
  })

  it('acknowledges a Pro-grant event with no customer id without faulting', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent('evt_no_cust', 'customer.subscription.updated', {
      status: 'active',
      items: { data: [] },
    })
    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
  })

  it('acknowledges a delete event with no customer id without faulting', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent('evt_del_no_cust', 'customer.subscription.deleted', {
      items: { data: [] },
    })
    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
  })

  it('accepts an expanded customer object (customer.id) on the event', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'expanded@example.com')
    await setStripeCustomerId(db, user.id, 'cus_expanded')
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent('evt_expanded', 'customer.subscription.updated', {
      customer: { id: 'cus_expanded' },
      status: 'active',
      items: { data: [{ price: { id: 'price_pro_12' }, current_period_end: null }] },
    })
    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'pro' })
  })

  it('acknowledges an unhandled event type without acting (200)', async () => {
    const { db, store } = memoryDatabase()
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent('evt_other', 'invoice.paid', { customer: 'cus_x' })

    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(200)
    // Recorded for idempotency, but no tier/subscription mutation occurred.
    expect(store.webhookEvents.has('evt_other')).toBe(true)
    expect(store.subscriptions.size).toBe(0)
  })

  it('returns 500 when the effect hits a persistence fault', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createFreeUser(db, 'fault@example.com')
    await setStripeCustomerId(db, user.id, 'cus_fault')
    const gw = new FakeBillingGateway()
    gw.event = stripeEvent(
      'evt_fault',
      'customer.subscription.updated',
      subscriptionObject('cus_fault', 'active', 'price_pro_12', PERIOD_END_SECONDS),
    )
    // Arm the fault: the FIRST write after verification is recordWebhookEvent.
    store.failNext = true
    const res = await handleWebhook(post('sig'), db, gw, DAY)
    expect(res.status).toBe(500)
  })
})
