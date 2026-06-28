import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { setStripeCustomerId } from '../db/billing'
import { FakeBillingGateway } from '../billing/fake.test'
import { loadConfig } from '../config/env'
import { handlePortal } from './portal'

const config = loadConfig({})

function post(apiKey?: string): Request {
  const headers: Record<string, string> = {}
  if (apiKey !== undefined) {
    headers['Authorization'] = `Bearer ${apiKey}`
  }
  return new Request('https://secureai.test/api/portal', { method: 'POST', headers })
}

describe('handlePortal', () => {
  it('returns a portal url for an authed user with a customer', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'portal@example.com')
    await setStripeCustomerId(db, user.id, 'cus_portal')
    const gw = new FakeBillingGateway()

    const res = await handlePortal(post(apiKey), db, gw, config)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { url: string }
    expect(body.url).toBe(gw.portalUrl)
    expect(gw.lastPortal?.customerId).toBe('cus_portal')
    expect(gw.lastPortal?.returnUrl).toContain(config.appBaseUrl)
  })

  it('returns 422 when the user has no Stripe customer yet', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'nocust@example.com')
    const gw = new FakeBillingGateway()

    const res = await handlePortal(post(apiKey), db, gw, config)
    expect(res.status).toBe(422)
    expect(gw.calls).not.toContain('createPortalSession')
  })

  it('rejects an anonymous caller with 401', async () => {
    const { db } = memoryDatabase()
    const res = await handlePortal(post(), db, new FakeBillingGateway(), config)
    expect(res.status).toBe(401)
  })

  it('returns 503 when billing is not configured', async () => {
    const res = await handlePortal(post('x'), null, null, config)
    expect(res.status).toBe(503)
  })

  it('maps a Stripe failure to 502 (BillingError)', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'p502@example.com')
    await setStripeCustomerId(db, user.id, 'cus_502')
    const gw = new FakeBillingGateway()
    gw.failSessions = true

    const res = await handlePortal(post(apiKey), db, gw, config)
    expect(res.status).toBe(502)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('BillingError')
  })
})
