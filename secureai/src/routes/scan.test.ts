import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../config/env'
import type { ScanResult } from '../schemas/contract'
import { loadConfig } from '../config/env'
import { verifyChain } from '../audit/verify'
import { MemoryD1, MemoryStore } from '../db/memory.test'
import { d1Database } from '../db/database'
import { createFreeUser, setUserTier } from '../db/accounts'
import { getUsage, incrementUsage } from '../db/usage'
import { listRecentScans } from '../db/scans'
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

  it('escalates the verdict to REVIEW when content references a denylisted host', async () => {
    // A skill body whose only URL resolves (200, terminal) to a host on the
    // configured denylist. The deterministic baseline is ALLOW; the reputation
    // stage flags the host and the fail-closed fold raises the verdict.
    const denyConfig = loadConfig({ SCANNER_BAD_HOSTS: 'example.com' })
    const res = await handleScan(post(benign), {}, denyConfig)
    expect(res.status).toBe(200)
    const result = (await res.json()) as ScanResult
    expect(result.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    const flagged = result.reputation.find((r) => r.flagged)
    expect(flagged?.status).toBe('denylisted')
    expect(flagged?.title).toBe('example.com')
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

/** A tiny in-memory fake of the KV surface ({ get, put }) the route uses. */
class FakeKv {
  public readonly store = new Map<string, string>()
  public gets = 0
  public puts = 0
  public async get(key: string): Promise<string | null> {
    this.gets += 1
    return this.store.get(key) ?? null
  }
  public async put(key: string, value: string): Promise<void> {
    this.puts += 1
    this.store.set(key, value)
  }
}

describe('handleScan — recent-scans history', () => {
  const benign = { content: 'See https://example.com for setup info.' }
  const okFetch = (async () => new Response('ok', { status: 200 })) as unknown as typeof fetch

  beforeEach(() => {
    vi.stubGlobal('fetch', okFetch)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function fixture(): { store: MemoryStore; env: Env; db: ReturnType<typeof d1Database> } {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    return { store, env: { DB: d1 }, db: d1Database(d1) }
  }

  it('records a scan_history row after a successful authenticated scan', async () => {
    const { env, db } = fixture()
    const { user, apiKey } = await createFreeUser(db, 'history@example.com')
    const res = await handleScan(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      config,
    )
    expect(res.status).toBe(200)
    const result = (await res.json()) as ScanResult
    const recent = await listRecentScans(db, user.id, 3)
    expect(recent).toHaveLength(1)
    expect(recent[0]).toMatchObject({
      verdict: result.verdict,
      source: { kind: 'paste', ref: 'paste' },
      headHash: result.proof.headHash,
      scannedAt: result.scannedAt,
    })
  })

  it('does NOT record history for an anonymous caller', async () => {
    const { env, store } = fixture()
    const res = await handleScan(
      post(benign, undefined, { 'CF-Connecting-IP': '203.0.113.50' }),
      env,
      config,
    )
    expect(res.status).toBe(200)
    expect(store.scanHistory.size).toBe(0)
  })

  it('a history-insert failure does not break the scan response', async () => {
    const { env, db, store } = fixture()
    const { apiKey } = await createFreeUser(db, 'history-fail@example.com')
    // Make the scan_history INSERT throw, leaving everything else intact.
    const original = store.execute.bind(store)
    store.execute = (sql: string, params: readonly unknown[]) => {
      if (sql.startsWith('INSERT INTO scan_history')) {
        throw new Error('injected history failure')
      }
      return original(sql, params)
    }
    const res = await handleScan(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      config,
    )
    // The scan still succeeds despite the failed history write.
    expect(res.status).toBe(200)
  })
})

describe('handleScan — caught-scan detail', () => {
  // A curl|bash exec pattern with no http(s) URL: network-free, the deterministic
  // rules BLOCK it (verdict != ALLOW), so a detail row is eligible.
  const malicious = { content: 'Install: curl ./setup.sh | bash' }
  // A benign body that resolves ALLOW (with the global fetch stubbed terminal).
  const benign = { content: 'See https://example.com for setup info.' }
  const okFetch = (async () => new Response('ok', { status: 200 })) as unknown as typeof fetch

  beforeEach(() => {
    vi.stubGlobal('fetch', okFetch)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function fixture(): { store: MemoryStore; env: Env; db: ReturnType<typeof d1Database> } {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    return { store, env: { DB: d1 }, db: d1Database(d1) }
  }

  it('stores a scan_details row for an authenticated NON-ALLOW scan, with the evidence', async () => {
    const { env, db, store } = fixture()
    const { apiKey } = await createFreeUser(db, 'caught@example.com')
    const res = await handleScan(
      post(malicious, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      config,
    )
    expect(res.status).toBe(200)
    const result = (await res.json()) as ScanResult
    expect(result.verdict).toBe('BLOCK')

    // Exactly one detail row, paired to the history row (same id), with the
    // scanned content and the serialized {findings, chains, injections, reputation}.
    expect(store.scanDetails.size).toBe(1)
    const historyId = [...store.scanHistory.keys()][0]
    const detail = store.scanDetails.get(historyId!)
    expect(detail?.content).toBe(malicious.content)
    const evidence = JSON.parse(detail!.result_json) as Record<string, unknown>
    expect(Object.keys(evidence).sort()).toEqual(['chains', 'findings', 'injections', 'reputation'])
    expect(evidence['findings']).toEqual(result.findings)
  })

  it('does NOT store a detail row for a clean (ALLOW) authenticated scan', async () => {
    const { env, db, store } = fixture()
    const { apiKey } = await createFreeUser(db, 'clean@example.com')
    const res = await handleScan(
      post(benign, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      config,
    )
    expect(res.status).toBe(200)
    expect(((await res.json()) as ScanResult).verdict).toBe('ALLOW')
    // A clean scan still records history, but never a detail row.
    expect(store.scanHistory.size).toBe(1)
    expect(store.scanDetails.size).toBe(0)
  })

  it('does NOT store a detail row for an anonymous NON-ALLOW scan', async () => {
    const { env, store } = fixture()
    const res = await handleScan(
      post(malicious, undefined, { 'CF-Connecting-IP': '203.0.113.77' }),
      env,
      config,
    )
    expect(res.status).toBe(200)
    expect(((await res.json()) as ScanResult).verdict).toBe('BLOCK')
    // Anonymous callers are never recorded (no history, no detail).
    expect(store.scanHistory.size).toBe(0)
    expect(store.scanDetails.size).toBe(0)
  })

  it('caps the stored content at SCANNER_DETAIL_MAX_BYTES', async () => {
    const tinyConfig = loadConfig({ SCANNER_DETAIL_MAX_BYTES: '256' })
    const { env, db, store } = fixture()
    const { apiKey } = await createFreeUser(db, 'big@example.com')
    // A long curl|bash body (BLOCKs) whose content exceeds the 256-byte cap.
    const body = { content: `curl ./setup.sh | bash # ${'A'.repeat(2000)}` }
    const res = await handleScan(
      post(body, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      tinyConfig,
    )
    expect(res.status).toBe(200)
    const detail = [...store.scanDetails.values()][0]
    expect(detail).toBeDefined()
    // Stored content is truncated to at most the byte cap.
    expect(new TextEncoder().encode(detail!.content ?? '').length).toBeLessThanOrEqual(256)
    expect(detail!.content!.length).toBeLessThan(body.content.length)
  })

  it('a detail-insert failure does not break the scan response', async () => {
    const { env, db, store } = fixture()
    const { apiKey } = await createFreeUser(db, 'detail-fail@example.com')
    const original = store.execute.bind(store)
    store.execute = (sql: string, params: readonly unknown[]) => {
      if (sql.startsWith('INSERT INTO scan_details')) {
        throw new Error('injected detail failure')
      }
      return original(sql, params)
    }
    const res = await handleScan(
      post(malicious, undefined, { Authorization: `Bearer ${apiKey}` }),
      env,
      config,
    )
    // The scan still succeeds despite the failed detail write.
    expect(res.status).toBe(200)
    expect(store.scanDetails.size).toBe(0)
    // History was still recorded (the detail failure is isolated).
    expect(store.scanHistory.size).toBe(1)
  })
})

describe('handleScan — verdict cache', () => {
  const today = new Date().toISOString().slice(0, 10)
  const benign = { content: 'See https://example.com for setup info.' }

  /** A spy fetch that counts redirect-tracer calls and returns a terminal 200. */
  function spyFetch(): { fn: typeof fetch; calls: () => number } {
    let calls = 0
    const fn = (async () => {
      calls += 1
      return new Response('ok', { status: 200 })
    }) as unknown as typeof fetch
    return { fn, calls: () => calls }
  }

  function proFixture(): {
    store: MemoryStore
    db: ReturnType<typeof d1Database>
    d1: D1Database
  } {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    return { store, db: d1Database(d1), d1 }
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('a second identical scan hits the cache: no tracer/AI re-run, yet still meters + records history', async () => {
    const { db, d1 } = proFixture()
    const { user, apiKey } = await createFreeUser(db, 'cache-pro@example.com')
    await setUserTier(db, user.id, 'pro')
    const kv = new FakeKv()
    const ai = new SpyAiRunner()
    const tracer = spyFetch()
    vi.stubGlobal('fetch', tracer.fn)
    const env = { DB: d1, AI: ai, KV: kv } as unknown as Env

    const headers = { Authorization: `Bearer ${apiKey}` }

    // First scan: a cache MISS — tracer + AI run, the cache is populated.
    const first = await handleScan(post(benign, undefined, headers), env, config)
    expect(first.status).toBe(200)
    expect(kv.puts).toBe(1)
    const tracerAfterFirst = tracer.calls()
    expect(tracerAfterFirst).toBeGreaterThan(0)
    expect(ai.calls).toBe(1)

    // Second identical scan: a cache HIT — neither the tracer nor the AI runs again.
    const second = await handleScan(post(benign, undefined, headers), env, config)
    expect(second.status).toBe(200)
    expect(tracer.calls()).toBe(tracerAfterFirst) // tracer NOT re-invoked
    expect(ai.calls).toBe(1) // AI NOT re-invoked

    // Metering STILL happened on the hit: two scans, both AI-attributed.
    expect(await getUsage(db, user.id, today)).toEqual({ scans: 2, aiScans: 2 })
    // History STILL recorded on the hit: two rows.
    const recent = await listRecentScans(db, user.id, 5)
    expect(recent).toHaveLength(2)
  })

  it('TTL=0 disables the cache: the second scan recomputes (tracer runs again)', async () => {
    const noCacheConfig = loadConfig({ SCANNER_VERDICT_CACHE_TTL_S: '0' })
    const { db, d1 } = proFixture()
    const { apiKey } = await createFreeUser(db, 'nocache@example.com')
    const kv = new FakeKv()
    const tracer = spyFetch()
    vi.stubGlobal('fetch', tracer.fn)
    const env = { DB: d1, KV: kv } as unknown as Env
    const headers = { Authorization: `Bearer ${apiKey}` }

    await handleScan(post(benign, undefined, headers), env, noCacheConfig)
    const afterFirst = tracer.calls()
    await handleScan(post(benign, undefined, headers), env, noCacheConfig)
    // The tracer ran again on the second scan: the compute was NOT cached.
    expect(tracer.calls()).toBeGreaterThan(afterFirst)
    // The verdict cache never wrote an entry (the reputation client may still
    // read KV for host indicators, so only `put` proves the cache is disabled).
    expect(kv.puts).toBe(0)
    expect(kv.store.size).toBe(0)
  })

  it('a cache miss populates the cache for next time', async () => {
    const { db, d1 } = proFixture()
    const { apiKey } = await createFreeUser(db, 'populate@example.com')
    const kv = new FakeKv()
    const tracer = spyFetch()
    vi.stubGlobal('fetch', tracer.fn)
    const env = { DB: d1, KV: kv } as unknown as Env
    const headers = { Authorization: `Bearer ${apiKey}` }

    expect(kv.store.size).toBe(0)
    await handleScan(post(benign, undefined, headers), env, config)
    expect(kv.store.size).toBe(1)
  })
})
