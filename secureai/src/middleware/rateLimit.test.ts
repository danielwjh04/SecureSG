import { describe, expect, it } from 'vitest'
import { clientIp, withinHourlyLimit } from './rateLimit'
import type { RateLimitKv } from './rateLimit'

/** A tiny in-memory KV fake exposing its store for assertions. */
function fakeKv(): RateLimitKv & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    get: async (key) => store.get(key) ?? null,
    put: async (key, value) => {
      store.set(key, value)
    },
  }
}

const PREFIX = 'auth:login:v1:'
const NOW = 1_700_000_000 // fixed edge time (seconds)

describe('withinHourlyLimit', () => {
  it('allows up to the limit, then blocks within the same hour bucket', async () => {
    const kv = fakeKv()
    expect(await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 3, NOW)).toBe(true)
    expect(await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 3, NOW)).toBe(true)
    expect(await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 3, NOW)).toBe(true)
    // The 4th in the same hour is over budget.
    expect(await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 3, NOW)).toBe(false)
  })

  it('keys buckets by prefix + identity + clock hour, so they are independent', async () => {
    const kv = fakeKv()
    // Exhaust one identity.
    await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 1, NOW)
    expect(await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 1, NOW)).toBe(false)
    // A different IP, a different endpoint prefix, and the next hour all have
    // their own budget.
    expect(await withinHourlyLimit(kv, PREFIX, '2.2.2.2', 1, NOW)).toBe(true)
    expect(await withinHourlyLimit(kv, 'auth:register:v1:', '1.1.1.1', 1, NOW)).toBe(true)
    expect(await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 1, NOW + 3600)).toBe(true)
  })

  it('fails closed on a corrupt (non-numeric) counter', async () => {
    const kv = fakeKv()
    const bucket = Math.floor(NOW / 3600)
    kv.store.set(`${PREFIX}9.9.9.9:${bucket}`, 'not-a-number')
    expect(await withinHourlyLimit(kv, PREFIX, '9.9.9.9', 5, NOW)).toBe(false)
  })

  it('writes the counter with a one-hour TTL', async () => {
    let ttl: number | undefined
    const kv: RateLimitKv = {
      get: async () => null,
      put: async (_key, _value, options) => {
        ttl = options?.expirationTtl
      },
    }
    await withinHourlyLimit(kv, PREFIX, '1.1.1.1', 5, NOW)
    expect(ttl).toBe(3600)
  })
})

describe('clientIp', () => {
  it('reads CF-Connecting-IP, trimming whitespace', () => {
    const req = new Request('https://x.test', { headers: { 'CF-Connecting-IP': ' 8.8.8.8 ' } })
    expect(clientIp(req)).toBe('8.8.8.8')
  })

  it('falls back to a shared unknown bucket when the header is absent', () => {
    expect(clientIp(new Request('https://x.test'))).toBe('unknown')
  })
})
