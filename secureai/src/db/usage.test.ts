import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { getUsage, incrementUsage } from './usage'

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
