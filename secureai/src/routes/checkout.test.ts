import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { getUserById } from '../db/billing'
import { FakeBillingGateway } from '../billing/fake.test'
import { loadConfig } from '../config/env'
import { handleCheckout } from './checkout'

const config = loadConfig({ STRIPE_PRICE_PRO: 'price_pro_12' })

function post(apiKey?: string): Request {
  const headers: Record<string, string> = {}
  if (apiKey !== undefined) {
    headers['Authorization'] = `Bearer ${apiKey}`
  }
  return new Request('https://secureai.test/api/checkout', { method: 'POST', headers })
}

describe('handleCheckout', () => {
  it('creates a session for an authed user and persists a new customer id', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'pay@example.com')
    const gw = new FakeBillingGateway()
    gw.ensuredCustomerId = 'cus_new'

    const res = await handleCheckout(post(apiKey), db, gw, config)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { url: string }
    expect(body.url).toBe(gw.checkoutUrl)

    // A customer was minted with the user's id/email and persisted.
    expect(gw.lastEnsure).toEqual({ userId: user.id, email: 'pay@example.com' })
    expect((await getUserById(db, user.id))?.stripeCustomerId).toBe('cus_new')

    // The checkout used the Pro price and the configured base URL.
    expect(gw.lastCheckout?.priceId).toBe('price_pro_12')
    expect(gw.lastCheckout?.customerId).toBe('cus_new')
    expect(gw.lastCheckout?.successUrl).toContain(config.appBaseUrl)
  })

  it('reuses an existing customer id without re-creating one', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'existing@example.com')
    const stored = store.users.get(user.id)
    if (stored !== undefined) {
      stored.stripe_customer_id = 'cus_existing'
    }
    const gw = new FakeBillingGateway()

    const res = await handleCheckout(post(apiKey), db, gw, config)
    expect(res.status).toBe(200)
    expect(gw.calls).not.toContain('ensureCustomer')
    expect(gw.lastCheckout?.customerId).toBe('cus_existing')
  })

  it('rejects an anonymous caller with 401', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    const res = await handleCheckout(post(), db, gw, config)
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('AuthError')
  })

  it('rejects an unknown API key with 401 (anonymous downgrade)', async () => {
    const { db } = memoryDatabase()
    const gw = new FakeBillingGateway()
    const res = await handleCheckout(post('sk_secureai_unknown'), db, gw, config)
    expect(res.status).toBe(401)
  })

  it('returns 503 when billing is not configured (no DB or gateway)', async () => {
    const res = await handleCheckout(post('whatever'), null, null, config)
    expect(res.status).toBe(503)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('service_unavailable')
  })

  it('rejects with 401 when the key resolves but the user row is gone', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'ghost@example.com')
    // Drop the user row while leaving the (now-dangling) key — auth resolves the
    // id from the join, but getUserById then misses.
    store.users.delete(user.id)
    const gw = new FakeBillingGateway()
    const res = await handleCheckout(post(apiKey), db, gw, config)
    expect(res.status).toBe(401)
  })

  it('maps a Stripe failure to 502 (BillingError)', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'gw502@example.com')
    const gw = new FakeBillingGateway()
    gw.failSessions = true

    const res = await handleCheckout(post(apiKey), db, gw, config)
    expect(res.status).toBe(502)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('BillingError')
  })
})
