import { describe, expect, it } from 'vitest'
import type { ActiveSubscription } from '../billing/stripe'
import type { Database } from '../db/database'
import type { MemoryStore } from '../db/memory.test'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { FakeBillingGateway } from '../billing/fake.test'
import { loadConfig } from '../config/env'
import { SESSION_COOKIE_NAME, signSession } from '../auth/session'
import { handleCancelPlan, handleChangePlan, handleSubscriptionStatus } from './billing'

const config = loadConfig({
  STRIPE_PRICE_PERSONAL: 'price_personal_12',
  STRIPE_PRICE_PRO: 'price_pro_12',
})
const SESSION_SECRET = 'billing-cookie-secret'

function changeReq(apiKey: string, tier: 'personal' | 'pro'): Request {
  return new Request('https://secureai.test/api/billing/change', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ tier }),
  })
}

function bearer(url: string, method: string, apiKey?: string): Request {
  const headers: Record<string, string> = {}
  if (apiKey !== undefined) {
    headers['Authorization'] = `Bearer ${apiKey}`
  }
  return new Request(url, { method, headers })
}

const cancelReq = (apiKey?: string): Request =>
  bearer('https://secureai.test/api/billing/cancel', 'POST', apiKey)
const statusReq = (apiKey?: string): Request =>
  bearer('https://secureai.test/api/billing/subscription', 'GET', apiKey)

function activeSub(priceId: string, overrides: Partial<ActiveSubscription> = {}): ActiveSubscription {
  return {
    subscriptionId: 'sub_1',
    itemId: 'si_1',
    priceId,
    cancelAtPeriodEnd: false,
    currentPeriodEnd: '2026-08-01T00:00:00.000Z',
    ...overrides,
  }
}

/** Create an account with a Stripe customer id + a paid tier already set. */
async function payingUser(
  db: Database,
  store: MemoryStore,
  email: string,
  tier: 'personal' | 'pro' = 'personal',
): Promise<{ userId: string; apiKey: string }> {
  const { user, apiKey } = await createFreeUser(db, email)
  const stored = store.users.get(user.id)
  if (stored !== undefined) {
    stored.stripe_customer_id = 'cus_x'
    stored.tier = tier
  }
  return { userId: user.id, apiKey }
}

describe('handleChangePlan', () => {
  it('swaps the price in place and reflects the new tier', async () => {
    const { db, store } = memoryDatabase()
    const { userId, apiKey } = await payingUser(db, store, 'change@example.com', 'personal')
    const gw = new FakeBillingGateway()
    gw.activeSubscription = activeSub('price_personal_12')

    const res = await handleChangePlan(changeReq(apiKey, 'pro'), db, gw, config)
    expect(res.status).toBe(200)
    expect(gw.lastChange).toMatchObject({
      subscriptionId: 'sub_1',
      itemId: 'si_1',
      newPriceId: 'price_pro_12',
      tier: 'pro',
      prorationBehavior: 'create_prorations',
    })
    // Optimistically reflected on the account (webhook re-affirms).
    expect(store.users.get(userId)?.tier).toBe('pro')
  })

  it('rejects a change with no active subscription (422)', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await payingUser(db, store, 'nosub@example.com')
    const gw = new FakeBillingGateway() // activeSubscription = null

    const res = await handleChangePlan(changeReq(apiKey, 'pro'), db, gw, config)
    expect(res.status).toBe(422)
    expect(gw.calls).not.toContain('changeSubscriptionPrice')
  })

  it('rejects a no-op change to the already-active plan (422)', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await payingUser(db, store, 'sameplan@example.com', 'pro')
    const gw = new FakeBillingGateway()
    gw.activeSubscription = activeSub('price_pro_12')

    const res = await handleChangePlan(changeReq(apiKey, 'pro'), db, gw, config)
    expect(res.status).toBe(422)
    expect(gw.calls).not.toContain('changeSubscriptionPrice')
  })

  it('rejects a change when the account has no Stripe customer (422)', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'nocust@example.com')
    const gw = new FakeBillingGateway()

    const res = await handleChangePlan(changeReq(apiKey, 'pro'), db, gw, config)
    expect(res.status).toBe(422)
    expect(gw.calls).not.toContain('getActiveSubscription')
  })

  it('rejects an anonymous caller (401)', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    const req = new Request('https://secureai.test/api/billing/change', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tier: 'pro' }),
    })
    const res = await handleChangePlan(req, db, gw, config)
    expect(res.status).toBe(401)
  })

  it('rejects an invalid tier body (422), before touching Stripe', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await payingUser(db, store, 'badtier@example.com')
    const gw = new FakeBillingGateway()
    const req = new Request('https://secureai.test/api/billing/change', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ tier: 'enterprise' }),
    })
    const res = await handleChangePlan(req, db, gw, config)
    expect(res.status).toBe(422)
    expect(gw.calls).toEqual([])
  })

  it('returns 503 when billing is not configured', async () => {
    const res = await handleChangePlan(changeReq('whatever', 'pro'), null, null, config)
    expect(res.status).toBe(503)
  })
})

describe('handleCancelPlan', () => {
  it('schedules cancellation at period end without downgrading now', async () => {
    const { db, store } = memoryDatabase()
    const { userId, apiKey } = await payingUser(db, store, 'cancel@example.com', 'pro')
    const gw = new FakeBillingGateway()
    gw.activeSubscription = activeSub('price_pro_12', { currentPeriodEnd: '2026-09-01T00:00:00.000Z' })

    const res = await handleCancelPlan(cancelReq(apiKey), db, gw)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { cancelAtPeriodEnd: boolean; currentPeriodEnd: string | null }
    expect(body.cancelAtPeriodEnd).toBe(true)
    expect(body.currentPeriodEnd).toBe('2026-09-01T00:00:00.000Z')
    expect(gw.lastCancelId).toBe('sub_1')
    // Access is kept until period end: the tier is unchanged here.
    expect(store.users.get(userId)?.tier).toBe('pro')
  })

  it('rejects a cancel with no active subscription (422)', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await payingUser(db, store, 'nocancel@example.com')
    const gw = new FakeBillingGateway()

    const res = await handleCancelPlan(cancelReq(apiKey), db, gw)
    expect(res.status).toBe(422)
    expect(gw.calls).not.toContain('cancelSubscription')
  })

  it('rejects an anonymous caller (401)', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    const res = await handleCancelPlan(cancelReq(), db, gw)
    expect(res.status).toBe(401)
  })

  it('returns 503 when billing is not configured', async () => {
    const res = await handleCancelPlan(cancelReq('whatever'), null, null)
    expect(res.status).toBe(503)
  })
})

describe('handleSubscriptionStatus', () => {
  it('reports an active subscription with its cancel state', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await payingUser(db, store, 'status@example.com', 'pro')
    const gw = new FakeBillingGateway()
    gw.activeSubscription = activeSub('price_pro_12', {
      cancelAtPeriodEnd: true,
      currentPeriodEnd: '2026-10-01T00:00:00.000Z',
    })

    const res = await handleSubscriptionStatus(statusReq(apiKey), db, gw)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      hasSubscription: true,
      cancelAtPeriodEnd: true,
      currentPeriodEnd: '2026-10-01T00:00:00.000Z',
    })
  })

  it('reports no subscription for a free account with no customer', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'freestatus@example.com')
    const gw = new FakeBillingGateway()

    const res = await handleSubscriptionStatus(statusReq(apiKey), db, gw)
    expect(await res.json()).toEqual({
      hasSubscription: false,
      cancelAtPeriodEnd: false,
      currentPeriodEnd: null,
    })
  })

  it('rejects an anonymous caller (401)', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    const res = await handleSubscriptionStatus(statusReq(), db, gw)
    expect(res.status).toBe(401)
  })

  it('degrades to no-subscription (200) when the store is absent', async () => {
    const gw = new FakeBillingGateway()
    const res = await handleSubscriptionStatus(statusReq('whatever'), null, gw)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      hasSubscription: false,
      cancelAtPeriodEnd: false,
      currentPeriodEnd: null,
    })
  })

  it('authenticates via a session cookie too', async () => {
    const { db, store } = memoryDatabase()
    const { userId } = await payingUser(db, store, 'cookiestatus@example.com', 'pro')
    const gw = new FakeBillingGateway()
    gw.activeSubscription = activeSub('price_pro_12')
    const token = await signSession(userId, Math.floor(Date.now() / 1000), 3600, SESSION_SECRET)

    const req = new Request('https://secureai.test/api/billing/subscription', {
      headers: { Cookie: `${SESSION_COOKIE_NAME}=${token}` },
    })
    const res = await handleSubscriptionStatus(req, db, gw, SESSION_SECRET)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { hasSubscription: boolean }
    expect(body.hasSubscription).toBe(true)
  })
})
