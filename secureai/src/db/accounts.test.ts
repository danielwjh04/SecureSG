import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { AuthError } from '../errors'
import {
  createFreeUser,
  findUserByApiKey,
  setTierByStripeCustomer,
  setUserTier,
  sha256Hex,
} from './accounts'

describe('createFreeUser', () => {
  it('mints a free user and a one-time API key', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'a@example.com')

    expect(user.tier).toBe('free')
    expect(user.email).toBe('a@example.com')
    expect(user.id).toMatch(/^[0-9a-f-]{36}$/)
    expect(user.stripeCustomerId).toBeNull()
    expect(apiKey).toMatch(/^sk_secureai_[0-9a-f]{64}$/)
  })

  it('stores ONLY the SHA-256 of the key — the raw key is never persisted', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'b@example.com')

    const expectedHash = await sha256Hex(apiKey)
    // The stored row is keyed by the hash, and the hash is the only credential
    // material in the record.
    expect(store.apiKeys.has(expectedHash)).toBe(true)
    const stored = JSON.stringify([...store.apiKeys.entries()])
    expect(stored).not.toContain(apiKey)
    expect(stored).toContain(expectedHash)
  })

  it('rejects a duplicate email as an AuthError', async () => {
    const { db } = memoryDatabase()
    await createFreeUser(db, 'dup@example.com')
    await expect(createFreeUser(db, 'dup@example.com')).rejects.toBeInstanceOf(AuthError)
  })

  it('wraps a persistence failure as an AuthError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(createFreeUser(db, 'fail@example.com')).rejects.toBeInstanceOf(AuthError)
  })
})

describe('findUserByApiKey', () => {
  it('resolves a valid active key to its user id and tier (hit)', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'hit@example.com')

    const resolved = await findUserByApiKey(db, apiKey)
    expect(resolved).toEqual({ userId: user.id, tier: 'free' })
  })

  it('returns null for an unknown key (miss)', async () => {
    const { db } = memoryDatabase()
    await createFreeUser(db, 'x@example.com')
    expect(await findUserByApiKey(db, 'sk_secureai_deadbeef')).toBeNull()
  })

  it('returns null for a revoked (inactive) key', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'revoked@example.com')
    const hash = await sha256Hex(apiKey)
    const record = store.apiKeys.get(hash)
    if (record !== undefined) {
      record.status = 'revoked'
    }
    expect(await findUserByApiKey(db, apiKey)).toBeNull()
  })

  it('reflects an upgraded tier after setUserTier', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'up@example.com')
    await setUserTier(db, user.id, 'pro')
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'pro' })
  })

  it('fails closed on a corrupted stored tier', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'corrupt@example.com')
    const stored = store.users.get(user.id)
    if (stored !== undefined) {
      stored.tier = 'platinum'
    }
    await expect(findUserByApiKey(db, apiKey)).rejects.toBeInstanceOf(AuthError)
  })

  it('fails closed when the joined user id column is corrupt (empty)', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'badid@example.com')
    const stored = store.users.get(user.id)
    if (stored !== undefined) {
      stored.id = '' // a structurally-corrupt record must not resolve silently
    }
    await expect(findUserByApiKey(db, apiKey)).rejects.toBeInstanceOf(AuthError)
  })
})

describe('tier mutation', () => {
  it('setTierByStripeCustomer updates the matching user (idempotent)', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'stripe@example.com')
    const stored = store.users.get(user.id)
    if (stored !== undefined) {
      stored.stripe_customer_id = 'cus_123'
    }

    await setTierByStripeCustomer(db, 'cus_123', 'enterprise')
    await setTierByStripeCustomer(db, 'cus_123', 'enterprise') // replay → no change
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'enterprise' })
  })

  it('setTierByStripeCustomer on an unknown customer is a no-op', async () => {
    const { db } = memoryDatabase()
    await expect(setTierByStripeCustomer(db, 'cus_none', 'pro')).resolves.toBeUndefined()
  })

  it('wraps a tier-update failure as an AuthError', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    await expect(setUserTier(db, 'whatever', 'pro')).rejects.toBeInstanceOf(AuthError)
    store.failNext = true
    await expect(setTierByStripeCustomer(db, 'cus_x', 'pro')).rejects.toBeInstanceOf(AuthError)
  })
})
