import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../config/env'
import type { ScanResult } from '../schemas/contract'
import { loadConfig } from '../config/env'
import { verifyChain } from '../audit/verify'
import { MemoryD1, MemoryStore } from '../db/memory.test'
import { d1Database } from '../db/database'
import { createFreeUser, setUserTier } from '../db/accounts'
import { getUsage, incrementUsage } from '../db/usage'
import { handleScan } from './scan'

const config = loadConfig({})

function post(body: unknown, raw?: string, headers?: Record<string, string>): Request {
  return new Request('https://secureai.test/api/scan', {
    method: 'POST',
    body: raw ?? JSON.stringify(body),
    headers,
  })
}

/**
 * Fake Workers AI runner: records every call and returns a benign-but-valid
 * injection JSON so `runScan`'s inference stage succeeds. Used to observe
 * whether the paid AI stage was actually invoked under tier gating.
 */
class SpyAiRunner {
  public calls = 0
  public async run(): Promise<{ response: string }> {
    this.calls += 1
    return {
      response: JSON.stringify({ pInjection: 0, findings: [], rationale: 'benign' }),
    }
  }
}

describe('handleScan', () => {
  it('returns 200 with a verifiable ScanResult for a network-free exec-pattern skill', async () => {
    // A curl|bash pattern with no http(s) URL extracts no links, so the route
    // never touches the network; the deterministic rules BLOCK it.
    const res = await handleScan(post({ content: 'Install: curl ./setup.sh | bash' }), {}, config)
    expect(res.status).toBe(200)
    const result = (await res.json()) as ScanResult
    expect(result.verdict).toBe('BLOCK')
    expect(result.injections).toEqual([]) // AI skipped once the baseline is BLOCK
    expect(await verifyChain(result.proof)).toEqual({ ok: true, firstBrokenIndex: null })
  })

  it('maps invalid JSON to 422', async () => {
    const res = await handleScan(post(undefined, '{bad'), {} as Env, config)
    expect(res.status).toBe(422)
  })

  it('maps a body with both content and sourceUrl to 422', async () => {
    const res = await handleScan(post({ content: 'x', sourceUrl: 'https://y.test' }), {}, config)
    expect(res.status).toBe(422)
  })

  it('maps a body with neither field to 422', async () => {
    const res = await handleScan(post({}), {}, config)
    expect(res.status).toBe(422)
  })
})

describe('handleScan — metering and caps', () => {
  const today = new Date().toISOString().slice(0, 10)
  // A benign body with a URL so the pipeline reaches the (gated) inference stage;
  // the global fetch is stubbed below so URL tracing is terminal and network-free.
  const benign = { content: 'See https://example.com for setup info.' }

  // Stub the global fetch the route's redirect tracer uses, so these tests are
  // deterministic and never touch the network.
  const okFetch = (async () => new Response('ok', { status: 200 })) as unknown as typeof fetch
  beforeEach(() => {
    vi.stubGlobal('fetch', okFetch)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  /** A store, the fake D1 binding over it, and the adapter for assertions. */
  function fixture(): { store: MemoryStore; env: Env; db: ReturnType<typeof d1Database> } {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    return { store, env: { DB: d1 }, db: d1Database(d1) }
  }

  it('runs the scan but does NOT meter when env.DB is absent', async () => {
    const res = await handleScan(post(benign), {}, config)
    expect(res.status).toBe(200)
  })

  it('meters an anonymous caller by IP when env.DB is present', async () => {
    const { env, db } = fixture()
    const res = await handleScan(
      post(benign, undefined, { 'CF-Connecting-IP': '203.0.113.1' }),
      env,
      config,
    )
    expect(res.status).toBe(200)
    expect(await getUsage(db, 'anon:203.0.113.1', today)).toEqual({ scans: 1, aiScans: 0 })
  })

  it('returns 429 quota_exceeded once the anonymous cap is reached', async () => {
    const { env, db } = fixture()
    for (let i = 0; i < config.capAnonymousPerDay; i += 1) {
      await incrementUsage(db, 'anon:203.0.113.2', today, { ai: false })
    }
    const res = await handleScan(
      post(benign, undefined, { 'CF-Connecting-IP': '203.0.113.2' }),
      env,
      config,
    )
    expect(res.status).toBe(429)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('quota_exceeded')
  })

  it('gates AI off for an anonymous caller even when env.AI is present', async () => {
    const { env, db } = fixture()
    const ai = new SpyAiRunner()
    const res = await handleScan(
      post(benign, undefined, { 'CF-Connecting-IP': '203.0.113.3' }),
      { ...env, AI: ai },
      config,
    )
    expect(res.status).toBe(200)
    expect(ai.calls).toBe(0)
    expect(await getUsage(db, 'anon:203.0.113.3', today)).toEqual({ scans: 1, aiScans: 0 })
  })

  it('gates AI off for a free-tier caller even when env.AI is present', async () => {
    const { env, db } = fixture()
    const ai = new SpyAiRunner()
    const { apiKey } = await createFreeUser(db, 'free-scan@example.com')
    const res = await handleScan(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      { ...env, AI: ai },
      config,
    )
    expect(res.status).toBe(200)
    expect(ai.calls).toBe(0)
  })

  it('uses the paid AI stage for a pro-tier caller when env.AI is present', async () => {
    const { env, db } = fixture()
    const ai = new SpyAiRunner()
    const { user, apiKey } = await createFreeUser(db, 'pro-scan@example.com')
    await setUserTier(db, user.id, 'pro')

    const res = await handleScan(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      { ...env, AI: ai },
      config,
    )
    expect(res.status).toBe(200)
    expect(ai.calls).toBe(1)
    expect(await getUsage(db, user.id, today)).toEqual({ scans: 1, aiScans: 1 })
  })

  it('maps a redirect-trace transport failure to 502 and meters nothing', async () => {
    const { env, db } = fixture()
    // A fetch that rejects makes the redirect tracer raise RedirectResolutionError,
    // which propagates out of runScan to the route's 502 mapping.
    vi.stubGlobal('fetch', (async () => {
      throw new Error('network down')
    }) as unknown as typeof fetch)
    const res = await handleScan(
      post(benign, undefined, { 'CF-Connecting-IP': '203.0.113.9' }),
      env,
      config,
    )
    expect(res.status).toBe(502)
    // A failed scan must not consume the daily quota.
    expect(await getUsage(db, 'anon:203.0.113.9', today)).toEqual({ scans: 0, aiScans: 0 })
  })
})
