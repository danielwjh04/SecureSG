import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { createFreeUser } from './accounts'
import { BillingError } from '../errors'
import {
  getUserById,
  getUserByStripeCustomer,
  recordWebhookEvent,
  setStripeCustomerId,
  upsertSubscription,
} from './billing'

const DAY = '2026-06-28T00:00:00.000Z'

describe('recordWebhookEvent', () => {
  it('records a new event id (true) and dedupes a replay (false)', async () => {
    const { db, store } = memoryDatabase()
    const first = await recordWebhookEvent(db, 'evt_1', 'checkout.session.completed', DAY)
    const second = await recordWebhookEvent(db, 'evt_1', 'checkout.session.completed', DAY)
    expect(first).toBe(true)
    expect(second).toBe(false)
    expect(store.webhookEvents.size).toBe(1)
  })

  it('treats distinct event ids as independent', async () => {
    const { db } = memoryDatabase()
    expect(await recordWebhookEvent(db, 'evt_a', 't', DAY)).toBe(true)
    expect(await recordWebhookEvent(db, 'evt_b', 't', DAY)).toBe(true)
  })

  it('wraps a database failure as a BillingError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(recordWebhookEvent(db, 'evt_x', 't', DAY)).rejects.toBeInstanceOf(BillingError)
  })
})

describe('upsertSubscription', () => {
  it('inserts then overwrites the mirror in place (idempotent on user_id)', async () => {
    const { db, store } = memoryDatabase()
    await upsertSubscription(db, 'u1', 'active', 'price_pro', DAY)
    await upsertSubscription(db, 'u1', 'canceled', 'price_pro', null)
    expect(store.subscriptions.get('u1')).toEqual({
      user_id: 'u1',
      status: 'canceled',
      price_id: 'price_pro',
      current_period_end: null,
    })
  })

  it('wraps a database failure as a BillingError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(
      upsertSubscription(db, 'u1', 'active', 'price_pro', DAY),
    ).rejects.toBeInstanceOf(BillingError)
  })
})

describe('setStripeCustomerId / getUserById', () => {
  it('persists and reads back the customer link', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'link@example.com')
    expect((await getUserById(db, user.id))?.stripeCustomerId).toBeNull()

    await setStripeCustomerId(db, user.id, 'cus_123')
    const read = await getUserById(db, user.id)
    expect(read).toEqual({
      userId: user.id,
      email: 'link@example.com',
      stripeCustomerId: 'cus_123',
    })
  })

  it('returns null for an unknown user id', async () => {
    const { db } = memoryDatabase()
    expect(await getUserById(db, 'nope')).toBeNull()
  })

  it('wraps a setStripeCustomerId failure as a BillingError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(setStripeCustomerId(db, 'u1', 'cus_1')).rejects.toBeInstanceOf(BillingError)
  })
})

describe('getUserByStripeCustomer', () => {
  it('resolves the user behind a customer id', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'cust@example.com')
    await setStripeCustomerId(db, user.id, 'cus_abc')

    const resolved = await getUserByStripeCustomer(db, 'cus_abc')
    expect(resolved).toEqual({
      userId: user.id,
      email: 'cust@example.com',
      stripeCustomerId: 'cus_abc',
    })
  })

  it('returns null when no user matches the customer id', async () => {
    const { db } = memoryDatabase()
    await createFreeUser(db, 'other@example.com')
    expect(await getUserByStripeCustomer(db, 'cus_missing')).toBeNull()
  })
})
