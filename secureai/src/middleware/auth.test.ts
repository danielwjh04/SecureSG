import { describe, expect, it } from 'vitest'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { authenticate } from './auth'

function request(headers: Record<string, string>): Request {
  return new Request('https://secureai.test/api/scan', { method: 'POST', headers })
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
})
