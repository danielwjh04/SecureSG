import { describe, expect, it } from 'vitest'
import { MemoryStore, MemoryD1 } from '../db/memory.test'
import { d1Database } from '../db/database'
import { findUserByApiKey } from '../db/accounts'
import { handleSignup } from './signup'

function post(body: unknown, raw?: string): Request {
  return new Request('https://secureai.test/api/signup', {
    method: 'POST',
    body: raw ?? JSON.stringify(body),
  })
}

function fixture(): { d1: D1Database } {
  const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
  return { d1 }
}

describe('handleSignup', () => {
  it('creates a free user and returns the API key once (201)', async () => {
    const { d1 } = fixture()
    const res = await handleSignup(post({ email: 'new@example.com' }), { DB: d1 })
    expect(res.status).toBe(201)
    const body = (await res.json()) as { apiKey: string; tier: string }
    expect(body.tier).toBe('free')
    expect(body.apiKey).toMatch(/^sk_secureai_[0-9a-f]{64}$/)

    // The returned key actually resolves to the new account.
    const resolved = await findUserByApiKey(d1Database(d1), body.apiKey)
    expect(resolved?.tier).toBe('free')
  })

  it('returns 503 when no account store is configured', async () => {
    const res = await handleSignup(post({ email: 'x@example.com' }), {})
    expect(res.status).toBe(503)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('service_unavailable')
  })

  it('maps invalid JSON to 422', async () => {
    const { d1 } = fixture()
    const res = await handleSignup(post(undefined, '{bad'), { DB: d1 })
    expect(res.status).toBe(422)
  })

  it('maps a missing/invalid email to 422', async () => {
    const { d1 } = fixture()
    const res = await handleSignup(post({ email: 'not-an-email' }), { DB: d1 })
    expect(res.status).toBe(422)
  })

  it('maps a duplicate email to a 500 (provision failure, store kept opaque)', async () => {
    const { d1 } = fixture()
    await handleSignup(post({ email: 'dup@example.com' }), { DB: d1 })
    const res = await handleSignup(post({ email: 'dup@example.com' }), { DB: d1 })
    expect(res.status).toBe(500)
  })
})
