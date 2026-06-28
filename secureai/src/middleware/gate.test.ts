import { describe, expect, it } from 'vitest'
import { loadConfig } from '../config/env'
import { memoryDatabase } from '../db/memory.test'
import { incrementUsage } from '../db/usage'
import { QuotaExceededError } from '../errors'
import { aiAllowedForTier, capForTier, enforceDailyCap, UNLIMITED } from './gate'

const config = loadConfig({})

describe('capForTier', () => {
  it('returns the configured per-tier caps', () => {
    expect(capForTier('anonymous', config)).toBe(10)
    expect(capForTier('free', config)).toBe(100)
    expect(capForTier('pro', config)).toBe(5000)
  })

  it('treats enterprise as unmetered', () => {
    expect(capForTier('enterprise', config)).toBe(UNLIMITED)
  })

  it('honors overridden caps from config vars', () => {
    const tuned = loadConfig({ SCANNER_CAP_ANONYMOUS_PER_DAY: '3', SCANNER_CAP_FREE_PER_DAY: '7' })
    expect(capForTier('anonymous', tuned)).toBe(3)
    expect(capForTier('free', tuned)).toBe(7)
  })
})

describe('aiAllowedForTier', () => {
  it('grants AI only to tiers in config.aiTiers (default: pro)', () => {
    expect(aiAllowedForTier('pro', config)).toBe(true)
    expect(aiAllowedForTier('free', config)).toBe(false)
    expect(aiAllowedForTier('enterprise', config)).toBe(false)
    expect(aiAllowedForTier('anonymous', config)).toBe(false)
  })

  it('never grants AI to anonymous even when listed', () => {
    const tuned = loadConfig({ SCANNER_AI_TIERS: 'anonymous,pro,enterprise' })
    expect(aiAllowedForTier('anonymous', tuned)).toBe(false)
    expect(aiAllowedForTier('enterprise', tuned)).toBe(true)
  })
})

describe('enforceDailyCap', () => {
  it('allows when under the cap', async () => {
    const { db } = memoryDatabase()
    await expect(enforceDailyCap(db, 'anon:1', 'anonymous', '2026-06-28', config)).resolves.toBeUndefined()
  })

  it('throws QuotaExceededError exactly at the cap', async () => {
    const { db } = memoryDatabase()
    for (let i = 0; i < 10; i += 1) {
      await incrementUsage(db, 'anon:1', '2026-06-28', { ai: false })
    }
    await expect(
      enforceDailyCap(db, 'anon:1', 'anonymous', '2026-06-28', config),
    ).rejects.toBeInstanceOf(QuotaExceededError)
  })

  it('never reads usage for an unmetered enterprise tier', async () => {
    const { db, store } = memoryDatabase()
    // Arm a failure: enterprise must short-circuit before any DB read.
    store.failNext = true
    await expect(
      enforceDailyCap(db, 'u1', 'enterprise', '2026-06-28', config),
    ).resolves.toBeUndefined()
    expect(store.failNext).toBe(true) // never consumed → no read happened
  })
})
