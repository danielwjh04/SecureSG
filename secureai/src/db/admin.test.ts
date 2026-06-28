import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import type { MemoryStore } from './memory.test'
import { createFreeUser, setUserTier } from './accounts'
import { recordVerdict } from './usage'
import { upsertSubscription } from './billing'
import { AdminError } from '../errors'
import {
  activeSubscriptions,
  countUsers,
  signupsByDay,
  usageTotals,
  usersByTier,
} from './admin'

/**
 * Seed a user at a fixed tier and signup day. `createFreeUser` always stamps
 * `now` and the `free` tier, so the tier is promoted and the `created_at` day is
 * overwritten directly on the store to model historical signups.
 */
async function seedUser(
  db: Parameters<typeof setUserTier>[0],
  store: MemoryStore,
  email: string,
  tier: 'free' | 'pro' | 'enterprise',
  day: string,
): Promise<string> {
  const { user } = await createFreeUser(db, email)
  if (tier !== 'free') {
    await setUserTier(db, user.id, tier)
  }
  const record = store.users.get(user.id)
  if (record !== undefined) {
    record.created_at = `${day}T12:00:00.000Z`
  }
  return user.id
}

describe('countUsers', () => {
  it('counts all registered accounts', async () => {
    const { db, store } = memoryDatabase()
    expect(await countUsers(db)).toBe(0)
    await seedUser(db, store, 'a@example.com', 'free', '2026-06-01')
    await seedUser(db, store, 'b@example.com', 'pro', '2026-06-02')
    expect(await countUsers(db)).toBe(2)
  })

  it('wraps a database failure as an AdminError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(countUsers(db)).rejects.toBeInstanceOf(AdminError)
  })
})

describe('usersByTier', () => {
  it('groups accounts by tier, zero-filling absent tiers', async () => {
    const { db, store } = memoryDatabase()
    await seedUser(db, store, 'f1@example.com', 'free', '2026-06-01')
    await seedUser(db, store, 'f2@example.com', 'free', '2026-06-01')
    await seedUser(db, store, 'p1@example.com', 'pro', '2026-06-01')
    expect(await usersByTier(db)).toEqual({ free: 2, pro: 1, enterprise: 0 })
  })

  it('returns all zeros for an empty store', async () => {
    const { db } = memoryDatabase()
    expect(await usersByTier(db)).toEqual({ free: 0, pro: 0, enterprise: 0 })
  })

  it('wraps a database failure as an AdminError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(usersByTier(db)).rejects.toBeInstanceOf(AdminError)
  })
})

describe('signupsByDay', () => {
  it('returns ascending daily signup counts from sinceDay onward', async () => {
    const { db, store } = memoryDatabase()
    await seedUser(db, store, 'd1@example.com', 'free', '2026-06-10')
    await seedUser(db, store, 'd2@example.com', 'free', '2026-06-10')
    await seedUser(db, store, 'd3@example.com', 'pro', '2026-06-12')
    // Before the window — excluded.
    await seedUser(db, store, 'old@example.com', 'free', '2026-05-01')

    const series = await signupsByDay(db, '2026-06-01')
    expect(series).toEqual([
      { day: '2026-06-10', count: 2 },
      { day: '2026-06-12', count: 1 },
    ])
  })

  it('returns an empty series when no signups fall in the window', async () => {
    const { db } = memoryDatabase()
    expect(await signupsByDay(db, '2026-06-01')).toEqual([])
  })

  it('wraps a database failure as an AdminError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(signupsByDay(db, '2026-06-01')).rejects.toBeInstanceOf(AdminError)
  })
})

describe('usageTotals', () => {
  it('sums verdict and indicator counters across every subject', async () => {
    const { db, store } = memoryDatabase()
    const day = '2026-06-28'
    const u1 = await seedUser(db, store, 'u1@example.com', 'free', day)
    const u2 = await seedUser(db, store, 'u2@example.com', 'pro', day)
    await recordVerdict(db, u1, day, 'ALLOW', 0, { ai: false })
    await recordVerdict(db, u1, day, 'BLOCK', 3, { ai: true })
    await recordVerdict(db, u2, day, 'HUMAN_APPROVAL_REQUIRED', 1, { ai: false })
    await recordVerdict(db, u2, day, 'BLOCK', 2, { ai: true })

    expect(await usageTotals(db)).toEqual({
      scans: 4,
      allows: 1,
      reviews: 1,
      blocks: 2,
      flagged: 6,
    })
  })

  it('returns all zeros (not nulls) for an empty usage table', async () => {
    const { db } = memoryDatabase()
    expect(await usageTotals(db)).toEqual({
      scans: 0,
      allows: 0,
      reviews: 0,
      blocks: 0,
      flagged: 0,
    })
  })

  it('wraps a database failure as an AdminError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(usageTotals(db)).rejects.toBeInstanceOf(AdminError)
  })
})

describe('activeSubscriptions', () => {
  it('counts only active and trialing subscriptions', async () => {
    const { db } = memoryDatabase()
    await upsertSubscription(db, 'u1', 'active', 'price_pro', null)
    await upsertSubscription(db, 'u2', 'trialing', 'price_pro', null)
    await upsertSubscription(db, 'u3', 'canceled', 'price_pro', null)
    await upsertSubscription(db, 'u4', 'past_due', 'price_pro', null)
    expect(await activeSubscriptions(db)).toBe(2)
  })

  it('returns 0 with no subscriptions', async () => {
    const { db } = memoryDatabase()
    expect(await activeSubscriptions(db)).toBe(0)
  })

  it('wraps a database failure as an AdminError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(activeSubscriptions(db)).rejects.toBeInstanceOf(AdminError)
  })
})
