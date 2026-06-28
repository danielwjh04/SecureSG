import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser, createUserWithPassword, markEmailVerified } from '../db/accounts'
import { SESSION_COOKIE_NAME, signSession } from '../auth/session'
import { authenticate } from './auth'

const SECRET = 'auth-test-secret'

function request(headers: Record<string, string>): Request {
  return new Request('https://secureai.test/api/scan', { method: 'POST', headers })
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

describe('authenticate', () => {
  it('resolves a valid bearer key to the user id and tier', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'auth@example.com')

    const ctx = await authenticate(request({ Authorization: `Bearer ${apiKey}` }), db)
    expect(ctx).toEqual({ subject: user.id, tier: 'free' })
  })

  it('falls back to anonymous keyed by CF-Connecting-IP when no key is present', async () => {
    const { db } = memoryDatabase()
    const ctx = await authenticate(request({ 'CF-Connecting-IP': '203.0.113.7' }), db)
    expect(ctx).toEqual({ subject: 'anon:203.0.113.7', tier: 'anonymous' })
  })

  it('uses anon:unknown when no client IP header is present', async () => {
    const { db } = memoryDatabase()
    const ctx = await authenticate(request({}), db)
    expect(ctx).toEqual({ subject: 'anon:unknown', tier: 'anonymous' })
  })

  it('treats a present-but-unknown key as anonymous, never an error', async () => {
    const { db } = memoryDatabase()
    const ctx = await authenticate(
      request({ Authorization: 'Bearer sk_secureai_unknown', 'CF-Connecting-IP': '198.51.100.9' }),
      db,
    )
    expect(ctx).toEqual({ subject: 'anon:198.51.100.9', tier: 'anonymous' })
  })

  it('treats a malformed Authorization header as anonymous', async () => {
    const { db } = memoryDatabase()
    const ctx = await authenticate(
      request({ Authorization: 'Basic abc', 'CF-Connecting-IP': '198.51.100.1' }),
      db,
    )
    expect(ctx).toEqual({ subject: 'anon:198.51.100.1', tier: 'anonymous' })
  })

  it('treats a Bearer scheme with an empty key as anonymous', async () => {
    const { db } = memoryDatabase()
    const ctx = await authenticate(
      request({ Authorization: 'Bearer    ', 'CF-Connecting-IP': '198.51.100.2' }),
      db,
    )
    expect(ctx).toEqual({ subject: 'anon:198.51.100.2', tier: 'anonymous' })
  })

  it('treats a blank CF-Connecting-IP as anon:unknown', async () => {
    const { db } = memoryDatabase()
    const ctx = await authenticate(request({ 'CF-Connecting-IP': '   ' }), db)
    expect(ctx).toEqual({ subject: 'anon:unknown', tier: 'anonymous' })
  })

  it('carries an upgraded tier from the resolved account', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'pro@example.com')
    const stored = store.users.get(user.id)
    if (stored !== undefined) {
      stored.tier = 'pro'
    }
    const ctx = await authenticate(request({ Authorization: `Bearer ${apiKey}` }), db)
    expect(ctx).toEqual({ subject: user.id, tier: 'pro' })
  })

  it('resolves a valid session cookie to its user when a secret is supplied', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'cookie@example.com', 'pbkdf2$1$a$b', true)
    const token = await signSession(user.id, nowSeconds(), 3600, SECRET)
    const ctx = await authenticate(
      request({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }),
      db,
      SECRET,
    )
    expect(ctx).toEqual({ subject: user.id, tier: 'free' })
  })

  it('ignores a session cookie when no secret is configured (anonymous)', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'nosecret@example.com', 'pbkdf2$1$a$b', true)
    const token = await signSession(user.id, nowSeconds(), 3600, SECRET)
    const ctx = await authenticate(
      request({ Cookie: `${SESSION_COOKIE_NAME}=${token}`, 'CF-Connecting-IP': '1.1.1.1' }),
      db,
    )
    expect(ctx).toEqual({ subject: 'anon:1.1.1.1', tier: 'anonymous' })
  })

  it('downgrades an expired session cookie to anonymous', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'expired@example.com', 'pbkdf2$1$a$b', true)
    // Issued an hour ago with a 1s TTL → long expired by now.
    const token = await signSession(user.id, nowSeconds() - 3600, 1, SECRET)
    const ctx = await authenticate(
      request({ Cookie: `${SESSION_COOKIE_NAME}=${token}`, 'CF-Connecting-IP': '2.2.2.2' }),
      db,
      SECRET,
    )
    expect(ctx).toEqual({ subject: 'anon:2.2.2.2', tier: 'anonymous' })
  })

  it('prefers a valid Bearer key over a session cookie', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createUserWithPassword(db, 'both@example.com', 'pbkdf2$1$a$b', true)
    const token = await signSession('some-other-user', nowSeconds(), 3600, SECRET)
    const ctx = await authenticate(
      request({ Authorization: `Bearer ${apiKey}`, Cookie: `${SESSION_COOKIE_NAME}=${token}` }),
      db,
      SECRET,
    )
    expect(ctx).toEqual({ subject: user.id, tier: 'free' })
  })

  it('downgrades a cookie whose user no longer exists to anonymous', async () => {
    const { db, store } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'gone@example.com', 'pbkdf2$1$a$b', true)
    const token = await signSession(user.id, nowSeconds(), 3600, SECRET)
    store.users.delete(user.id)
    const ctx = await authenticate(
      request({ Cookie: `${SESSION_COOKIE_NAME}=${token}`, 'CF-Connecting-IP': '3.3.3.3' }),
      db,
      SECRET,
    )
    expect(ctx).toEqual({ subject: 'anon:3.3.3.3', tier: 'anonymous' })
  })

  it('downgrades a valid session for an UNVERIFIED account to anonymous', async () => {
    const { db } = memoryDatabase()
    // Created unverified (email provider active at register), so the session
    // subject must NOT authenticate until the emailed code is verified.
    const { user } = await createUserWithPassword(db, 'unverified@example.com', 'pbkdf2$1$a$b', false)
    const token = await signSession(user.id, nowSeconds(), 3600, SECRET)
    const ctx = await authenticate(
      request({ Cookie: `${SESSION_COOKIE_NAME}=${token}`, 'CF-Connecting-IP': '4.4.4.4' }),
      db,
      SECRET,
    )
    expect(ctx).toEqual({ subject: 'anon:4.4.4.4', tier: 'anonymous' })
  })

  it('authenticates the same session once the account is verified', async () => {
    const { db } = memoryDatabase()
    const { user } = await createUserWithPassword(db, 'becomes-verified@example.com', 'pbkdf2$1$a$b', false)
    const token = await signSession(user.id, nowSeconds(), 3600, SECRET)
    // Unverified → anonymous.
    const before = await authenticate(request({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }), db, SECRET)
    expect(before.tier).toBe('anonymous')
    // After verification the very same cookie resolves to the account.
    await markEmailVerified(db, user.id)
    const after = await authenticate(request({ Cookie: `${SESSION_COOKIE_NAME}=${token}` }), db, SECRET)
    expect(after).toEqual({ subject: user.id, tier: 'free' })
  })
})
