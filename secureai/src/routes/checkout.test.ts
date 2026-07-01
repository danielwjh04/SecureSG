import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { getUserById } from '../db/billing'
import { FakeBillingGateway } from '../billing/fake.test'
import { loadConfig } from '../config/env'
import { SESSION_COOKIE_NAME, signSession } from '../auth/session'
import { handleCheckout } from './checkout'

const config = loadConfig({
  STRIPE_PRICE_PERSONAL: 'price_personal_12',
  STRIPE_PRICE_PRO: 'price_pro_12',
})
const SESSION_SECRET = 'checkout-cookie-secret'

function post(apiKey?: string): Request {
  const headers: Record<string, string> = {}
  if (apiKey !== undefined) {
    headers['Authorization'] = `Bearer ${apiKey}`
  }
  return new Request('https://secureai.test/api/checkout', { method: 'POST', headers })
}

function postTier(apiKey: string, tier: 'personal' | 'pro'): Request {
  return new Request('https://secureai.test/api/checkout', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tier }),
  })
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
    expect(gw.lastCheckout?.tier).toBe('pro')
    expect(gw.lastCheckout?.customerId).toBe('cus_new')
    expect(gw.lastCheckout?.successUrl).toContain(config.appBaseUrl)
  })

  it('creates a Personal checkout session when requested', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'personal-pay@example.com')
    const gw = new FakeBillingGateway()

    const res = await handleCheckout(postTier(apiKey, 'personal'), db, gw, config)
    expect(res.status).toBe(200)
    expect(gw.lastCheckout?.priceId).toBe('price_personal_12')
    expect(gw.lastCheckout?.tier).toBe('personal')
  })

  it('rejects a checkout when the tier price is an unconfigured placeholder', async () => {
    const placeholderConfig = loadConfig({
      STRIPE_PRICE_PERSONAL: 'price_REPLACE_PERSONAL',
      STRIPE_PRICE_PRO: 'price_pro_12',
    })
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'placeholder-price@example.com')
    const gw = new FakeBillingGateway()

    const res = await handleCheckout(postTier(apiKey, 'personal'), db, gw, placeholderConfig)
    expect(res.status).toBe(500)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('ConfigError')
    // The unconfigured price never reached Stripe: no customer, no session.
    expect(gw.calls).toEqual([])
  })

  it('rejects an unknown checkout tier with 422', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'bad-tier@example.com')
    const gw = new FakeBillingGateway()
    const req = new Request('https://secureai.test/api/checkout', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ tier: 'enterprise' }),
    })

    const res = await handleCheckout(req, db, gw, config)
    expect(res.status).toBe(422)
    expect(gw.calls).toEqual([])
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
    // Drop the user row while leaving the (now-dangling) key, auth resolves the
    // id from the join, but getUserById then misses.
    store.users.delete(user.id)
    const gw = new FakeBillingGateway()
    const res = await handleCheckout(post(apiKey), db, gw, config)
    expect(res.status).toBe(401)
  })

  it('authenticates via a session cookie when a secret is supplied', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'cookie-checkout@example.com')
    const gw = new FakeBillingGateway()
    gw.ensuredCustomerId = 'cus_cookie'
    const token = await signSession(user.id, Math.floor(Date.now() / 1000), 3600, SESSION_SECRET)

    const req = new Request('https://secureai.test/api/checkout', {
      method: 'POST',
      headers: { Cookie: `${SESSION_COOKIE_NAME}=${token}` },
    })
    const res = await handleCheckout(req, db, gw, config, SESSION_SECRET)
    expect(res.status).toBe(200)
    expect(gw.lastEnsure?.userId).toBe(user.id)
  })

  it('rejects a session cookie with 401 when no secret is supplied', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'no-secret-checkout@example.com')
    const gw = new FakeBillingGateway()
    const token = await signSession(user.id, Math.floor(Date.now() / 1000), 3600, SESSION_SECRET)
    const req = new Request('https://secureai.test/api/checkout', {
      method: 'POST',
      headers: { Cookie: `${SESSION_COOKIE_NAME}=${token}` },
    })
    // No sessionSecret passed → cookie ignored → anonymous → 401.
    const res = await handleCheckout(req, db, gw, config)
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
