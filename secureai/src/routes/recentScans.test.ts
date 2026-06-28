import { describe, expect, it } from 'vitest'
import type { RecentScansDeps } from './recentScans'
import type { ScanHistoryRow } from '../db/scans'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { insertScan } from '../db/scans'
import { signSession, SESSION_COOKIE_NAME } from '../auth/session'
import { handleRecentScans } from './recentScans'

const SECRET = 'recent-scans-test-secret'

function deps(db: RecentScansDeps['db'], sessionSecret: string | null = SECRET): RecentScansDeps {
  return { db, sessionSecret }
}

function getReq(query = '', headers: Record<string, string> = {}): Request {
  return new Request(`https://secureai.test/api/scans/recent${query}`, { headers })
}

/** Build a scan-history row for `userId` at a given timestamp. */
function row(userId: string, scannedAt: string, overrides: Partial<ScanHistoryRow> = {}): ScanHistoryRow {
  return {
    id: crypto.randomUUID(),
    userId,
    verdict: 'ALLOW',
    sourceKind: 'paste',
    sourceRef: 'paste',
    flagged: 0,
    headHash: `head-${scannedAt}`,
    scannedAt,
    ...overrides,
  }
}

interface RecentBody {
  scans: {
    id: string
    verdict: string
    source: { kind: string; ref: string }
    flagged: number
    headHash: string
    scannedAt: string
  }[]
}

describe('handleRecentScans', () => {
  it('returns the caller own scans newest-first, default limit 3', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'recent@example.com')
    await insertScan(db, row(user.id, '2026-06-28T01:00:00.000Z'))
    await insertScan(db, row(user.id, '2026-06-28T02:00:00.000Z'))
    await insertScan(db, row(user.id, '2026-06-28T03:00:00.000Z'))
    await insertScan(db, row(user.id, '2026-06-28T04:00:00.000Z'))

    const res = await handleRecentScans(getReq('', { Authorization: `Bearer ${apiKey}` }), deps(db))
    expect(res.status).toBe(200)
    const body = (await res.json()) as RecentBody
    // Default limit 3, newest first.
    expect(body.scans.map((s) => s.scannedAt)).toEqual([
      '2026-06-28T04:00:00.000Z',
      '2026-06-28T03:00:00.000Z',
      '2026-06-28T02:00:00.000Z',
    ])
  })

  it('only returns the authenticated subject own scans', async () => {
    const { db } = memoryDatabase()
    const mine = await createFreeUser(db, 'mine@example.com')
    const other = await createFreeUser(db, 'other@example.com')
    await insertScan(db, row(mine.user.id, '2026-06-28T01:00:00.000Z'))
    await insertScan(db, row(other.user.id, '2026-06-28T02:00:00.000Z'))

    const res = await handleRecentScans(
      getReq('', { Authorization: `Bearer ${mine.apiKey}` }),
      deps(db),
    )
    const body = (await res.json()) as RecentBody
    expect(body.scans).toHaveLength(1)
    expect(body.scans[0]?.headHash).toBe('head-2026-06-28T01:00:00.000Z')
  })

  it('respects an explicit limit and surfaces the full shape', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'shape@example.com')
    await insertScan(
      db,
      row(user.id, '2026-06-28T01:00:00.000Z', {
        verdict: 'BLOCK',
        sourceKind: 'url',
        sourceRef: 'https://evil.test/skill',
        flagged: 2,
        headHash: 'abc123',
      }),
    )
    await insertScan(db, row(user.id, '2026-06-28T02:00:00.000Z'))

    const res = await handleRecentScans(
      getReq('?limit=1', { Authorization: `Bearer ${apiKey}` }),
      deps(db),
    )
    const body = (await res.json()) as RecentBody
    expect(body.scans).toHaveLength(1)
    // limit=1 → newest only (the 02:00 ALLOW row).
    expect(body.scans[0]).toMatchObject({
      verdict: 'ALLOW',
      source: { kind: 'paste', ref: 'paste' },
      flagged: 0,
    })
  })

  it('clamps a too-large limit to the max (20)', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'clamp@example.com')
    for (let i = 0; i < 25; i += 1) {
      await insertScan(db, row(user.id, `2026-06-28T${String(i).padStart(2, '0')}:00:00.000Z`))
    }
    const res = await handleRecentScans(
      getReq('?limit=1000', { Authorization: `Bearer ${apiKey}` }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as RecentBody
    expect(body.scans).toHaveLength(20)
  })

  it('rejects a non-integer limit with 422', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'badlimit@example.com')
    const res = await handleRecentScans(
      getReq('?limit=abc', { Authorization: `Bearer ${apiKey}` }),
      deps(db),
    )
    expect(res.status).toBe(422)
  })

  it('authenticates via a session cookie too', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'cookie-recent@example.com')
    await insertScan(db, row(user.id, '2026-06-28T01:00:00.000Z'))
    const token = await signSession(user.id, Math.floor(Date.now() / 1000), 3600, SECRET)

    const res = await handleRecentScans(
      getReq('', { Cookie: `${SESSION_COOKIE_NAME}=${token}` }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as RecentBody
    expect(body.scans).toHaveLength(1)
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const res = await handleRecentScans(getReq(), deps(db))
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleRecentScans(getReq(), deps(null))
    expect(res.status).toBe(503)
  })
})
