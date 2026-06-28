import { describe, expect, it } from 'vitest'
import type { StatsDeps } from './stats'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { recordVerdict } from '../db/usage'
import { loadConfig } from '../config/env'
import { signSession, SESSION_COOKIE_NAME } from '../auth/session'
import { handleStats } from './stats'

const config = loadConfig({})
const SECRET = 'stats-test-secret'

function deps(db: StatsDeps['db'], sessionSecret: string | null = SECRET): StatsDeps {
  return { db, sessionSecret, config }
}

function getReq(headers: Record<string, string> = {}): Request {
  return new Request('https://secureai.test/api/stats', { headers })
}

/** Today's UTC YYYY-MM-DD, the day recordVerdict would stamp at the edge. */
function today(): string {
  return new Date().toISOString().slice(0, 10)
}

interface StatsBody {
  tier: string
  totals: { scans: number; allows: number; reviews: number; blocks: number; flagged: number }
  daily: { day: string; scans: number; allows: number; reviews: number; blocks: number; flagged: number }[]
}

describe('handleStats', () => {
  it('aggregates totals and the per-day series for the authenticated subject', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'stats@example.com')
    const day = today()
    await recordVerdict(db, user.id, day, 'ALLOW', 0, { ai: false })
    await recordVerdict(db, user.id, day, 'BLOCK', 2, { ai: true })
    await recordVerdict(db, user.id, day, 'HUMAN_APPROVAL_REQUIRED', 1, { ai: false })

    const res = await handleStats(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as StatsBody
    expect(body.tier).toBe('free')
    expect(body.totals).toEqual({ scans: 3, allows: 1, reviews: 1, blocks: 1, flagged: 3 })
    expect(body.daily).toHaveLength(1)
    expect(body.daily[0]).toMatchObject({ day, scans: 3, blocks: 1, flagged: 3 })
  })

  it('authenticates via a session cookie too', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'cookie-stats@example.com')
    await recordVerdict(db, user.id, today(), 'ALLOW', 0, { ai: false })
    const token = await signSession(user.id, Math.floor(Date.now() / 1000), 3600, SECRET)

    const res = await handleStats(getReq({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as StatsBody
    expect(body.totals.scans).toBe(1)
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const res = await handleStats(getReq(), deps(db))
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleStats(getReq(), deps(null))
    expect(res.status).toBe(503)
  })

  it('returns zeroed stats for an account with no activity', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'empty-stats@example.com')
    const res = await handleStats(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as StatsBody
    expect(body.totals).toEqual({ scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 })
    expect(body.daily).toEqual([])
  })

  it('maps a persistence fault during the range read to 500', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'fault-stats@example.com')
    // Auth succeeds (first read), then the stats range read throws.
    let calls = 0
    const original = store.queryAll.bind(store)
    store.queryAll = (sql: string, params: readonly unknown[]) => {
      calls += 1
      if (calls === 1) {
        throw new Error('injected stats failure')
      }
      return original(sql, params)
    }
    const res = await handleStats(getReq({ Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(500)
  })
})
