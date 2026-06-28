import { describe, expect, it } from 'vitest'
import { memoryDatabase } from './memory.test'
import { AuthError } from '../errors'
import {
  createFreeUser,
  createUserWithPassword,
  deactivateApiKeys,
  findTierByUserId,
  findUserByApiKey,
  findUserByEmail,
  getAccountProfile,
  isEmailVerified,
  markEmailVerified,
  rotateApiKey,
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

describe('createUserWithPassword', () => {
  it('provisions a free user with a stored password hash and a one-time key', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createUserWithPassword(db, 'pw@example.com', 'pbkdf2$1$a$b', true)

    expect(user.tier).toBe('free')
    expect(user.email).toBe('pw@example.com')
    expect(apiKey).toMatch(/^sk_secureai_[0-9a-f]{64}$/)
    expect(store.users.get(user.id)?.password_hash).toBe('pbkdf2$1$a$b')
    // The new account also has an active API key.
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'free' })
  })

  it('rejects a duplicate email as an AuthError', async () => {
    const { db } = memoryDatabase()
    await createUserWithPassword(db, 'dup2@example.com', 'pbkdf2$1$a$b', true)
    await expect(
      createUserWithPassword(db, 'dup2@example.com', 'pbkdf2$1$c$d', true),
    ).rejects.toBeInstanceOf(AuthError)
  })

  it('persists email_verified=0 when created unverified, and its key does NOT resolve', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createUserWithPassword(db, 'unv@example.com', 'pbkdf2$1$a$b', false)
    expect(store.users.get(user.id)?.email_verified).toBe(0)
    // The account has an active key row, but the verified gate withholds it.
    expect(await findUserByApiKey(db, apiKey)).toBeNull()
  })

  it('persists email_verified=1 when created verified, and its key resolves', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createUserWithPassword(db, 'ver@example.com', 'pbkdf2$1$a$b', true)
    expect(store.users.get(user.id)?.email_verified).toBe(1)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'free' })
  })
})

describe('email verification (isEmailVerified / markEmailVerified)', () => {
  it('createFreeUser provisions a VERIFIED account (no email step) whose key resolves', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'apikeyacct@example.com')
    // The API-key signup path has no verification step → verified at birth.
    expect(store.users.get(user.id)?.email_verified).toBe(1)
    expect(await isEmailVerified(db, user.id)).toBe(true)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'free' })
  })

  it('isEmailVerified is false for an unverified account and true after marking', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createUserWithPassword(db, 'mark@example.com', 'pbkdf2$1$a$b', false)
    expect(await isEmailVerified(db, user.id)).toBe(false)
    // The key does not authenticate while unverified...
    expect(await findUserByApiKey(db, apiKey)).toBeNull()

    await markEmailVerified(db, user.id)
    expect(await isEmailVerified(db, user.id)).toBe(true)
    // ...and authenticates once verified.
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user.id, tier: 'free' })
  })

  it('markEmailVerified is idempotent and a no-op for an unknown id', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'idem@example.com', 'pbkdf2$1$a$b', false)
    await markEmailVerified(db, user.id)
    // Replaying leaves it verified (idempotent), and an unknown id does not throw.
    await expect(markEmailVerified(db, user.id)).resolves.toBeUndefined()
    await expect(markEmailVerified(db, 'no-such-user')).resolves.toBeUndefined()
    expect(await isEmailVerified(db, user.id)).toBe(true)
  })

  it('isEmailVerified is false for an unknown user id (fail closed)', async () => {
    const { db } = memoryDatabase()
    expect(await isEmailVerified(db, 'ghost')).toBe(false)
  })

  it('wraps a markEmailVerified persistence failure as an AuthError', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'markfail@example.com', 'pbkdf2$1$a$b', false)
    store.failNext = true
    await expect(markEmailVerified(db, user.id)).rejects.toBeInstanceOf(AuthError)
  })
})

describe('findUserByEmail', () => {
  it('resolves an account by email with its password hash', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'find@example.com', 'pbkdf2$1$a$b', true)
    const found = await findUserByEmail(db, 'find@example.com')
    expect(found).toEqual({
      id: user.id,
      email: 'find@example.com',
      tier: 'free',
      passwordHash: 'pbkdf2$1$a$b',
    })
  })

  it('returns a null password hash for an API-key-only account (no password)', async () => {
    const { db } = memoryDatabase()
    await createFreeUser(db, 'keyonly@example.com')
    const found = await findUserByEmail(db, 'keyonly@example.com')
    expect(found?.passwordHash).toBeNull()
  })

  it('returns null on an unknown email (miss, not an error)', async () => {
    const { db } = memoryDatabase()
    expect(await findUserByEmail(db, 'nobody@example.com')).toBeNull()
  })
})

describe('findTierByUserId', () => {
  it('resolves a known user id to its tier', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'tier@example.com')
    expect(await findTierByUserId(db, user.id)).toBe('free')
    await setUserTier(db, user.id, 'pro')
    expect(await findTierByUserId(db, user.id)).toBe('pro')
  })

  it('returns null for an unknown user id', async () => {
    const { db } = memoryDatabase()
    expect(await findTierByUserId(db, 'no-such-user')).toBeNull()
  })
})

describe('getAccountProfile', () => {
  it('returns the profile with the brand prefix when an active key exists', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'prof@example.com', 'pbkdf2$1$a$b', true)
    const profile = await getAccountProfile(db, user.id)
    expect(profile?.email).toBe('prof@example.com')
    expect(profile?.tier).toBe('free')
    expect(profile?.createdAt).toBe(user.createdAt)
    expect(profile?.apiKeyPrefix).toBe('sk_secureai_')
  })

  it('reports a null apiKeyPrefix when the account has no active key', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'nokey@example.com')
    await deactivateApiKeys(db, user.id)
    const profile = await getAccountProfile(db, user.id)
    expect(profile?.apiKeyPrefix).toBeNull()
  })

  it('returns null for an unknown user id', async () => {
    const { db } = memoryDatabase()
    expect(await getAccountProfile(db, 'ghost')).toBeNull()
  })
})

describe('rotateApiKey / deactivateApiKeys', () => {
  it('mints a new working key and deactivates the previous one', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey: oldKey } = await createFreeUser(db, 'rotate@example.com')
    expect(await findUserByApiKey(db, oldKey)).not.toBeNull()

    const newKey = await rotateApiKey(db, user.id)
    expect(newKey).toMatch(/^sk_secureai_[0-9a-f]{64}$/)
    expect(newKey).not.toBe(oldKey)
    // The old key no longer authenticates; the new one does.
    expect(await findUserByApiKey(db, oldKey)).toBeNull()
    expect(await findUserByApiKey(db, newKey)).toEqual({ userId: user.id, tier: 'free' })
  })

  it('deactivateApiKeys on a user with no active keys is a no-op', async () => {
    const { db } = memoryDatabase()
    const { user } = await createFreeUser(db, 'noop@example.com')
    await deactivateApiKeys(db, user.id)
    await expect(deactivateApiKeys(db, user.id)).resolves.toBeUndefined()
  })
})
