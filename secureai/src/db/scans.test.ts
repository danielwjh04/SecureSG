import { describe, expect, it } from 'vitest'
import type { ScanHistoryRow } from './scans'
import { memoryDatabase } from './memory.test'
import { insertScan, listRecentScans } from './scans'

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

describe('scan-history repository', () => {
  it('inserts a row and reads it back with the full mapped shape', async () => {
    const { db } = memoryDatabase()
    await insertScan(
      db,
      row('u1', '2026-06-28T01:00:00.000Z', {
        verdict: 'BLOCK',
        sourceKind: 'url',
        sourceRef: 'https://evil.test/skill',
        flagged: 3,
        headHash: 'abcdef',
      }),
    )
    const recent = await listRecentScans(db, 'u1', 5)
    expect(recent).toHaveLength(1)
    expect(recent[0]).toEqual({
      id: expect.any(String),
      verdict: 'BLOCK',
      source: { kind: 'url', ref: 'https://evil.test/skill' },
      flagged: 3,
      headHash: 'abcdef',
      scannedAt: '2026-06-28T01:00:00.000Z',
    })
  })

  it('returns rows newest-first and caps at the limit', async () => {
    const { db } = memoryDatabase()
    await insertScan(db, row('u1', '2026-06-28T01:00:00.000Z'))
    await insertScan(db, row('u1', '2026-06-28T03:00:00.000Z'))
    await insertScan(db, row('u1', '2026-06-28T02:00:00.000Z'))

    const recent = await listRecentScans(db, 'u1', 2)
    expect(recent.map((r) => r.scannedAt)).toEqual([
      '2026-06-28T03:00:00.000Z',
      '2026-06-28T02:00:00.000Z',
    ])
  })

  it('scopes the read to the given user', async () => {
    const { db } = memoryDatabase()
    await insertScan(db, row('u1', '2026-06-28T01:00:00.000Z'))
    await insertScan(db, row('u2', '2026-06-28T02:00:00.000Z'))
    expect(await listRecentScans(db, 'u1', 5)).toHaveLength(1)
    expect(await listRecentScans(db, 'u3', 5)).toEqual([])
  })

  it('propagates a store fault from insertScan (caller is best-effort)', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(insertScan(db, row('u1', '2026-06-28T01:00:00.000Z'))).rejects.toThrow()
  })
})
