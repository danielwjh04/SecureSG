import { describe, expect, it } from 'vitest'
import type { AdminDeps, AdminOverview } from './admin'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser, setUserTier } from '../db/accounts'
import { recordVerdict } from '../db/usage'
import { upsertSubscription } from '../db/billing'
import { loadConfig } from '../config/env'
import { signSession, SESSION_COOKIE_NAME } from '../auth/session'
import { handleAdminOverview } from './admin'

const ADMIN_EMAIL = 'owner@example.com'
const SECRET = 'admin-route-test-secret'
const config = loadConfig({ SCANNER_ADMIN_EMAILS: ADMIN_EMAIL })

function deps(db: AdminDeps['db'], sessionSecret: string | null = SECRET): AdminDeps {
  return { db, sessionSecret, config }
}

function getReq(headers: Record<string, string> = {}): Request {
  return new Request('https://secureai.test/api/admin/overview', { headers })
}

/** Provision an account at a tier and return a Bearer-auth request for it. */
async function adminBearer(db: AdminDeps['db']): Promise<string> {
  if (db === null) throw new Error('db required')
  const { apiKey } = await createFreeUser(db, ADMIN_EMAIL)
  return apiKey
}

describe('handleAdminOverview', () => {
  it('returns 200 with the full overview for an admin email', async () => {
    const { db, store } = memoryDatabase()
    const apiKey = await adminBearer(db)
    // A second (non-admin) pro account + a usage row + an active subscription.
    const { user: pro } = await createFreeUser(db, 'paid@example.com')
    await setUserTier(db, pro.id, 'pro')
    const day = new Date().toISOString().slice(0, 10)
    await recordVerdict(db, pro.id, day, 'BLOCK', 4, { ai: true })
    await upsertSubscription(db, pro.id, 'active', 'price_pro', null)
    // Stamp both signups to today so they fall in the 30-day window.
    for (const u of store.users.values()) {
      u.created_at = `${day}T08:00:00.000Z`
    }

    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as AdminOverview
    expect(body.totalUsers).toBe(2)
    expect(body.usersByTier).toEqual({ free: 1, pro: 1, enterprise: 0 })
    expect(body.usageTotals).toEqual({ scans: 1, allows: 0, reviews: 0, blocks: 1, flagged: 4 })
    expect(body.activeSubscriptions).toBe(1)
    expect(body.signupsDaily).toEqual([{ day, count: 2 }])
    expect(typeof body.generatedAt).toBe('string')
    expect(Number.isNaN(Date.parse(body.generatedAt))).toBe(false)
  })

  it('authenticates an admin via a session cookie too', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, ADMIN_EMAIL)
    const token = await signSession(user.id, Math.floor(Date.now() / 1000), 3600, SECRET)
    const res = await handleAdminOverview(
      getReq({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }),
      deps(db),
    )
    expect(res.status).toBe(200)
  })

  it('returns 403 for an authenticated non-admin account', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'notadmin@example.com')
    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(403)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('forbidden')
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const res = await handleAdminOverview(getReq(), deps(db))
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleAdminOverview(getReq(), deps(null))
    expect(res.status).toBe(503)
  })

  it('returns an all-zero overview when there is no data beyond the admin', async () => {
    const { db } = memoryDatabase()
    const apiKey = await adminBearer(db)
    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as AdminOverview
    expect(body.totalUsers).toBe(1)
    expect(body.usageTotals).toEqual({ scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 })
    expect(body.activeSubscriptions).toBe(0)
  })

  it('maps a persistence fault during aggregation to 500', async () => {
    const { db, store } = memoryDatabase()
    const apiKey = await adminBearer(db)
    // Auth + profile reads succeed; the user-count aggregate read throws.
    const original = store.queryOne.bind(store)
    store.queryOne = (sql: string, params: readonly unknown[]) => {
      if (sql.includes('COUNT(*) AS total FROM users')) {
        throw new Error('injected admin failure')
      }
      return original(sql, params)
    }
    const res = await handleAdminOverview(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(500)
  })
})
