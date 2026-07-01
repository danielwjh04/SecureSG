import { describe, expect, it } from 'vitest'
import type { Database } from './database'
import type { ScanHistoryRow } from './scans'
import { memoryDatabase } from './memory.test'
import { createFreeUser } from './accounts'
import {
  getScanDetail,
  getUserScanDetail,
  insertScan,
  insertScanDetail,
  listRecentScans,
  parseScanEvidence,
  scanDetailStatement,
  scanHistoryStatement,
} from './scans'

describe('statement builders', () => {
  it('scanHistoryStatement emits the scan_history insert with positional params in column order', () => {
    const stmt = scanHistoryStatement({
      id: 's1',
      userId: 'u1',
      verdict: 'BLOCK',
      sourceKind: 'url',
      sourceRef: 'https://evil.test',
      flagged: 2,
      headHash: 'h1',
      scannedAt: '2026-06-28T00:00:00.000Z',
    })
    expect(stmt.sql).toContain('INSERT INTO scan_history')
    expect(stmt.params).toEqual([
      's1',
      'u1',
      'BLOCK',
      'url',
      'https://evil.test',
      2,
      'h1',
      '2026-06-28T00:00:00.000Z',
    ])
  })

  it('scanDetailStatement emits the idempotent (ON CONFLICT DO NOTHING) detail insert', () => {
    const stmt = scanDetailStatement({
      scanId: 's1',
      content: 'malicious body',
      resultJson: '{"findings":[]}',
      createdAt: '2026-06-28T00:00:00.000Z',
    })
    expect(stmt.sql).toContain('INSERT INTO scan_details')
    expect(stmt.sql).toContain('ON CONFLICT (scan_id) DO NOTHING')
    expect(stmt.params).toEqual(['s1', 'malicious body', '{"findings":[]}', '2026-06-28T00:00:00.000Z'])
  })
})

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

describe('scan-details repository', () => {
  /** Seed an owner + a BLOCK scan-history row, returning their ids. */
  async function seedCaughtScan(
    db: Database,
    email = 'detail-owner@example.com',
  ): Promise<{ userId: string; scanId: string }> {
    const { user } = await createFreeUser(db, email)
    const scanId = crypto.randomUUID()
    await insertScan(
      db,
      row(user.id, '2026-06-28T01:00:00.000Z', {
        id: scanId,
        verdict: 'BLOCK',
        sourceKind: 'url',
        sourceRef: 'https://evil.test/skill',
        flagged: 2,
        headHash: 'head-detail',
      }),
    )
    return { userId: user.id, scanId }
  }

  it('inserts a detail row and joins it back with the owner email + parsed shape', async () => {
    const { db } = memoryDatabase()
    const { scanId } = await seedCaughtScan(db)
    await insertScanDetail(db, {
      scanId,
      content: 'malicious skill body',
      resultJson: '{"findings":[{"ruleId":"r"}]}',
      createdAt: '2026-06-28T01:00:00.000Z',
    })
    const detail = await getScanDetail(db, scanId)
    expect(detail).toEqual({
      id: scanId,
      email: 'detail-owner@example.com',
      verdict: 'BLOCK',
      source: { kind: 'url', ref: 'https://evil.test/skill' },
      flagged: 2,
      headHash: 'head-detail',
      scannedAt: '2026-06-28T01:00:00.000Z',
      content: 'malicious skill body',
      resultJson: '{"findings":[{"ruleId":"r"}]}',
    })
  })

  it('preserves a NULL content as null (cache-hit case), distinct from empty string', async () => {
    const { db } = memoryDatabase()
    const { scanId } = await seedCaughtScan(db, 'null-content@example.com')
    await insertScanDetail(db, {
      scanId,
      content: null,
      resultJson: '{}',
      createdAt: '2026-06-28T01:00:00.000Z',
    })
    const detail = await getScanDetail(db, scanId)
    expect(detail?.content).toBeNull()
  })

  it('is idempotent for the same scan_id (ON CONFLICT DO NOTHING keeps the first)', async () => {
    const { db } = memoryDatabase()
    const { scanId } = await seedCaughtScan(db, 'idem@example.com')
    await insertScanDetail(db, { scanId, content: 'first', resultJson: '{"a":1}', createdAt: 't1' })
    await insertScanDetail(db, { scanId, content: 'second', resultJson: '{"b":2}', createdAt: 't2' })
    const detail = await getScanDetail(db, scanId)
    expect(detail?.content).toBe('first')
    expect(detail?.resultJson).toBe('{"a":1}')
  })

  it('returns null for an unknown scan id', async () => {
    const { db } = memoryDatabase()
    expect(await getScanDetail(db, 'no-such-scan')).toBeNull()
  })

  it('propagates a store fault from insertScanDetail (caller is best-effort)', async () => {
    const { db, store } = memoryDatabase()
    const { scanId } = await seedCaughtScan(db, 'fault@example.com')
    store.failNext = true
    await expect(
      insertScanDetail(db, { scanId, content: 'x', resultJson: '{}', createdAt: 't' }),
    ).rejects.toThrow()
  })

  it('reads back the caller own detail owner-scoped, without the owner email', async () => {
    const { db } = memoryDatabase()
    const { userId, scanId } = await seedCaughtScan(db, 'owner-scoped@example.com')
    await insertScanDetail(db, {
      scanId,
      content: 'malicious skill body',
      resultJson: '{"findings":[{"ruleId":"r"}]}',
      createdAt: '2026-06-28T01:00:00.000Z',
    })
    expect(await getUserScanDetail(db, scanId, userId)).toEqual({
      id: scanId,
      verdict: 'BLOCK',
      source: { kind: 'url', ref: 'https://evil.test/skill' },
      flagged: 2,
      headHash: 'head-detail',
      scannedAt: '2026-06-28T01:00:00.000Z',
      content: 'malicious skill body',
      resultJson: '{"findings":[{"ruleId":"r"}]}',
    })
  })

  it('returns null when the scan belongs to another account (no peer leak)', async () => {
    const { db } = memoryDatabase()
    const { scanId } = await seedCaughtScan(db, 'owner@example.com')
    await insertScanDetail(db, { scanId, content: 'x', resultJson: '{}', createdAt: 't' })
    const { user: peer } = await createFreeUser(db, 'peer@example.com')
    expect(await getUserScanDetail(db, scanId, peer.id)).toBeNull()
  })

  it('returns null for an unknown scan id (owner-scoped)', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'nobody@example.com')
    expect(await getUserScanDetail(db, 'no-such-scan', user.id)).toBeNull()
  })
})

describe('parseScanEvidence', () => {
  it('parses each evidence array from a well-formed payload', () => {
    const parsed = parseScanEvidence(
      JSON.stringify({
        findings: [{ ruleId: 'r1' }],
        chains: [{ origin: 'https://a.test' }],
        injections: [{ label: 'i' }],
        reputation: [{ source: 'feed' }],
      }),
    )
    expect(parsed.findings).toHaveLength(1)
    expect(parsed.chains).toHaveLength(1)
    expect(parsed.injections).toHaveLength(1)
    expect(parsed.reputation).toHaveLength(1)
  })

  it('yields all-empty arrays for an unparseable payload rather than throwing', () => {
    expect(parseScanEvidence('{not json')).toEqual({
      findings: [],
      chains: [],
      injections: [],
      reputation: [],
    })
  })

  it('yields all-empty arrays for a non-object / missing-field payload', () => {
    expect(parseScanEvidence('42')).toEqual({
      findings: [],
      chains: [],
      injections: [],
      reputation: [],
    })
    expect(parseScanEvidence('{}')).toEqual({
      findings: [],
      chains: [],
      injections: [],
      reputation: [],
    })
  })
})
