import { describe, expect, it } from 'vitest'
import type { ScanDetailDeps } from './scanDetail'
import type { Database } from '../db/database'
import type { ScanHistoryRow } from '../db/scans'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { insertScan, insertScanDetail } from '../db/scans'
import { signSession, SESSION_COOKIE_NAME } from '../auth/session'
import { handleScanDetail } from './scanDetail'

const SECRET = 'scan-detail-test-secret'
const SCAN_ID = 'scan-1'

function deps(db: ScanDetailDeps['db'], sessionSecret: string | null = SECRET): ScanDetailDeps {
  return { db, sessionSecret }
}

function req(headers: Record<string, string> = {}): Request {
  return new Request(`https://secureai.test/api/scans/${SCAN_ID}`, { headers })
}

function blockRow(userId: string): ScanHistoryRow {
  return {
    id: SCAN_ID,
    userId,
    verdict: 'BLOCK',
    sourceKind: 'url',
    sourceRef: 'https://evil.test/skill',
    flagged: 2,
    headHash: 'head-detail',
    scannedAt: '2026-06-28T01:00:00.000Z',
  }
}

interface DetailBody {
  id: string
  verdict: string
  source: { kind: string; ref: string }
  scannedAt: string
  flagged: number
  headHash: string
  content: string | null
  findings: unknown[]
  chains: unknown[]
  injections: unknown[]
  reputation: unknown[]
}

/** Seed an owner + a BLOCK scan + its detail row; return the owner's credentials. */
async function seedCaughtScan(
  db: Database,
  email: string,
): Promise<{ apiKey: string; userId: string }> {
  const { user, apiKey } = await createFreeUser(db, email)
  await insertScan(db, blockRow(user.id))
  await insertScanDetail(db, {
    scanId: SCAN_ID,
    content: 'malicious skill body',
    resultJson: JSON.stringify({
      findings: [{ ruleId: 'r1' }],
      chains: [],
      injections: [],
      reputation: [],
    }),
    createdAt: '2026-06-28T01:00:00.000Z',
  })
  return { apiKey, userId: user.id }
}

describe('handleScanDetail', () => {
  it('returns the caller own scan detail with the parsed evidence', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await seedCaughtScan(db, 'owner@example.com')

    const res = await handleScanDetail(
      req({ Authorization: `Bearer ${apiKey}` }),
      deps(db),
      SCAN_ID,
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as DetailBody
    expect(body).toMatchObject({
      id: SCAN_ID,
      verdict: 'BLOCK',
      source: { kind: 'url', ref: 'https://evil.test/skill' },
      scannedAt: '2026-06-28T01:00:00.000Z',
      flagged: 2,
      headHash: 'head-detail',
      content: 'malicious skill body',
    })
    expect(body.findings).toHaveLength(1)
    expect(body.chains).toEqual([])
    expect(body.injections).toEqual([])
    expect(body.reputation).toEqual([])
  })

  it('authenticates via a session cookie too', async () => {
    const { db } = memoryDatabase()
    const { userId } = await seedCaughtScan(db, 'cookie@example.com')
    const token = await signSession(userId, Math.floor(Date.now() / 1000), 3600, SECRET)

    const res = await handleScanDetail(
      req({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }),
      deps(db),
      SCAN_ID,
    )
    expect(res.status).toBe(200)
  })

  it('returns 404 when the scan belongs to another account (no peer leak)', async () => {
    const { db } = memoryDatabase()
    await seedCaughtScan(db, 'owner@example.com')
    const { apiKey: peerKey } = await createFreeUser(db, 'peer@example.com')

    const res = await handleScanDetail(
      req({ Authorization: `Bearer ${peerKey}` }),
      deps(db),
      SCAN_ID,
    )
    expect(res.status).toBe(404)
  })

  it('returns 404 for an unknown / clean (never-detailed) scan id', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'clean@example.com')

    const res = await handleScanDetail(
      req({ Authorization: `Bearer ${apiKey}` }),
      deps(db),
      SCAN_ID,
    )
    expect(res.status).toBe(404)
  })

  it('returns 401 for an anonymous caller', async () => {
    const { db } = memoryDatabase()
    const res = await handleScanDetail(req(), deps(db), SCAN_ID)
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleScanDetail(req(), deps(null), SCAN_ID)
    expect(res.status).toBe(503)
  })
})
