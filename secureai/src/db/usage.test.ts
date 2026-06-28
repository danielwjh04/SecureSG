import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { getStats, getUsage, incrementUsage, recordVerdict } from './usage'

describe('getUsage', () => {
  it('returns zero counters for a subject with no activity', async () => {
    const { db } = memoryDatabase()
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 0, aiScans: 0 })
  })

  it('coerces a corrupted (non-numeric) stored counter to zero', async () => {
    const { db, store } = memoryDatabase()
    store.usage.set('u1 2026-06-28', {
      subject: 'u1',
      day: '2026-06-28',
      // A corrupted store value must not crash the cap check; it floors to 0.
      scans: 'oops' as unknown as number,
      ai_scans: -5,
      allows: 0,
      reviews: 0,
      blocks: 0,
      flagged: 0,
    })
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 0, aiScans: 0 })
  })
})

describe('incrementUsage', () => {
  it('creates the row on first scan, then upserts on subsequent scans', async () => {
    const { db } = memoryDatabase()
    await incrementUsage(db, 'u1', '2026-06-28', { ai: false })
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 1, aiScans: 0 })

    await incrementUsage(db, 'u1', '2026-06-28', { ai: true })
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 2, aiScans: 1 })
  })

  it('counts ai_scans only when the AI stage ran', async () => {
    const { db } = memoryDatabase()
    await incrementUsage(db, 'u1', '2026-06-28', { ai: true })
    await incrementUsage(db, 'u1', '2026-06-28', { ai: true })
    await incrementUsage(db, 'u1', '2026-06-28', { ai: false })
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 3, aiScans: 2 })
  })

  it('isolates counters per subject', async () => {
    const { db } = memoryDatabase()
    await incrementUsage(db, 'u1', '2026-06-28', { ai: false })
    await incrementUsage(db, 'anon:1.2.3.4', '2026-06-28', { ai: false })
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 1, aiScans: 0 })
    expect(await getUsage(db, 'anon:1.2.3.4', '2026-06-28')).toEqual({ scans: 1, aiScans: 0 })
  })

  it('isolates counters per day', async () => {
    const { db } = memoryDatabase()
    await incrementUsage(db, 'u1', '2026-06-28', { ai: false })
    await incrementUsage(db, 'u1', '2026-06-29', { ai: false })
    expect(await getUsage(db, 'u1', '2026-06-28')).toEqual({ scans: 1, aiScans: 0 })
    expect(await getUsage(db, 'u1', '2026-06-29')).toEqual({ scans: 1, aiScans: 0 })
  })
})

describe('recordVerdict', () => {
  it('bumps scans + the matching verdict column on the first record', async () => {
    const { db, store } = memoryDatabase()
    await recordVerdict(db, 'u1', '2026-06-28', 'BLOCK', 2, { ai: true })
    expect(store.usage.get('u1 2026-06-28')).toMatchObject({
      scans: 1,
      ai_scans: 1,
      allows: 0,
      reviews: 0,
      blocks: 1,
      flagged: 2,
    })
  })

  it('routes each verdict to the right column and accumulates flagged', async () => {
    const { db, store } = memoryDatabase()
    await recordVerdict(db, 'u1', '2026-06-28', 'ALLOW', 0, { ai: false })
    await recordVerdict(db, 'u1', '2026-06-28', 'HUMAN_APPROVAL_REQUIRED', 1, { ai: false })
    await recordVerdict(db, 'u1', '2026-06-28', 'BLOCK', 3, { ai: true })
    expect(store.usage.get('u1 2026-06-28')).toMatchObject({
      scans: 3,
      ai_scans: 1,
      allows: 1,
      reviews: 1,
      blocks: 1,
      flagged: 4,
    })
  })

  it('floors a negative/non-integer flagged count to 0', async () => {
    const { db, store } = memoryDatabase()
    await recordVerdict(db, 'u1', '2026-06-28', 'ALLOW', -5, { ai: false })
    expect(store.usage.get('u1 2026-06-28')?.flagged).toBe(0)
  })
})

describe('getStats', () => {
  it('returns zeroed totals and an empty series for a subject with no activity', async () => {
    const { db } = memoryDatabase()
    const stats = await getStats(db, 'u1', '2026-06-01')
    expect(stats.totals).toEqual({ scans: 0, allows: 0, reviews: 0, blocks: 0, flagged: 0 })
    expect(stats.daily).toEqual([])
  })

  it('aggregates totals and returns an ascending per-day series', async () => {
    const { db } = memoryDatabase()
    await recordVerdict(db, 'u1', '2026-06-26', 'ALLOW', 0, { ai: false })
    await recordVerdict(db, 'u1', '2026-06-28', 'BLOCK', 2, { ai: true })
    await recordVerdict(db, 'u1', '2026-06-28', 'HUMAN_APPROVAL_REQUIRED', 1, { ai: false })

    const stats = await getStats(db, 'u1', '2026-06-01')
    expect(stats.totals).toEqual({ scans: 3, allows: 1, reviews: 1, blocks: 1, flagged: 3 })
    expect(stats.daily.map((d) => d.day)).toEqual(['2026-06-26', '2026-06-28'])
    expect(stats.daily[0]).toMatchObject({ day: '2026-06-26', scans: 1, allows: 1 })
    expect(stats.daily[1]).toMatchObject({ day: '2026-06-28', scans: 2, blocks: 1, reviews: 1, flagged: 3 })
  })

  it('excludes days before the sinceDay lower bound', async () => {
    const { db } = memoryDatabase()
    await recordVerdict(db, 'u1', '2026-05-01', 'ALLOW', 0, { ai: false })
    await recordVerdict(db, 'u1', '2026-06-15', 'ALLOW', 0, { ai: false })
    const stats = await getStats(db, 'u1', '2026-06-01')
    expect(stats.daily.map((d) => d.day)).toEqual(['2026-06-15'])
    expect(stats.totals.scans).toBe(1)
  })

  it('isolates stats per subject', async () => {
    const { db } = memoryDatabase()
    await recordVerdict(db, 'u1', '2026-06-10', 'ALLOW', 0, { ai: false })
    await recordVerdict(db, 'u2', '2026-06-10', 'BLOCK', 1, { ai: false })
    const stats = await getStats(db, 'u1', '2026-06-01')
    expect(stats.totals.scans).toBe(1)
    expect(stats.totals.blocks).toBe(0)
  })
})
