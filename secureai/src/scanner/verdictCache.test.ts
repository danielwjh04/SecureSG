import { describe, expect, it } from 'vitest'
import type { ScanRequest, ScanResult } from '../schemas/contract'
import type { ScanOutcome } from './runScan'
import type { VerdictCacheKv } from './verdictCache'
import { cacheKeyForRequest, resolveCachedScan } from './verdictCache'

/** A tiny in-memory fake of the KV surface the cache uses ({ get, put }). */
class FakeKv implements VerdictCacheKv {
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

/** A minimal but well-formed ScanResult, with the given scannedAt. */
function fakeResult(scannedAt: string): ScanResult {
  return {
    verdict: 'ALLOW',
    chains: [],
    reputation: [],
    injections: [],
    findings: [],
    proof: {
      genesisHash: 'g',
      steps: [{ index: 0, kind: 'VERDICT', payload: { verdict: 'ALLOW' }, prevHash: 'g', currHash: 'h' }],
      headHash: 'h',
    },
    scannedAt,
    source: { kind: 'paste', ref: 'paste' },
  }
}

/** Wrap a {@link fakeResult} into the {@link ScanOutcome} `compute` now returns. */
function fakeOutcome(scannedAt: string, scannedText = 'some skill body'): ScanOutcome {
  return { result: fakeResult(scannedAt), scannedText }
}

const REQ: ScanRequest = { content: 'some skill body' }

describe('cacheKeyForRequest', () => {
  it('is stable for identical scannable input and namespaced/versioned', async () => {
    const a = await cacheKeyForRequest({ content: 'x' })
    const b = await cacheKeyForRequest({ content: 'x' })
    expect(a).toBe(b)
    expect(a.startsWith('scan:v1:')).toBe(true)
  })

  it('differs for different scannable input', async () => {
    const a = await cacheKeyForRequest({ content: 'x' })
    const b = await cacheKeyForRequest({ content: 'y' })
    expect(a).not.toBe(b)
  })
})

describe('resolveCachedScan', () => {
  it('computes and populates the cache on a miss, returning the fresh scannedText', async () => {
    const kv = new FakeKv()
    let computed = 0
    const out = await resolveCachedScan(REQ, kv, 300, '2026-06-28T00:00:00.000Z', async () => {
      computed += 1
      return fakeOutcome('2026-06-28T00:00:00.000Z', 'caught body')
    })
    expect(computed).toBe(1)
    expect(out.cached).toBe(false)
    // The freshly-scanned text flows through on a miss (for detail persistence).
    expect(out.scannedText).toBe('caught body')
    expect(kv.puts).toBe(1)
    expect(kv.store.size).toBe(1)
    // The cache stores ONLY the serialized ScanResult, never the scanned text.
    expect(kv.store.get([...kv.store.keys()][0]!)).not.toContain('caught body')
  })

  it('serves a second identical scan from the cache WITHOUT recomputing (no scannedText)', async () => {
    const kv = new FakeKv()
    let computed = 0
    const compute = async (): Promise<ScanOutcome> => {
      computed += 1
      return fakeOutcome('2026-06-28T00:00:00.000Z')
    }
    await resolveCachedScan(REQ, kv, 300, '2026-06-28T00:00:00.000Z', compute)
    const second = await resolveCachedScan(REQ, kv, 300, '2026-06-28T09:09:09.000Z', compute)
    expect(computed).toBe(1) // compute ran once, the hit skipped it
    expect(second.cached).toBe(true)
    // A hit recomputes no text, so no detail is re-persisted from a cache hit.
    expect(second.scannedText).toBeNull()
    // A fresh scannedAt is stamped at the edge; the proof headHash is unchanged.
    expect(second.result.scannedAt).toBe('2026-06-28T09:09:09.000Z')
    expect(second.result.proof.headHash).toBe('h')
  })

  it('TTL=0 disables the cache: always computes, never touches KV', async () => {
    const kv = new FakeKv()
    let computed = 0
    const compute = async (): Promise<ScanOutcome> => {
      computed += 1
      return fakeOutcome('2026-06-28T00:00:00.000Z')
    }
    await resolveCachedScan(REQ, kv, 0, '2026-06-28T00:00:00.000Z', compute)
    const second = await resolveCachedScan(REQ, kv, 0, '2026-06-28T00:00:00.000Z', compute)
    expect(computed).toBe(2)
    expect(second.cached).toBe(false)
    expect(second.scannedText).toBe('some skill body')
    expect(kv.gets).toBe(0)
    expect(kv.puts).toBe(0)
  })

  it('with no KV bound, always computes', async () => {
    let computed = 0
    const out = await resolveCachedScan(REQ, null, 300, '2026-06-28T00:00:00.000Z', async () => {
      computed += 1
      return fakeOutcome('2026-06-28T00:00:00.000Z')
    })
    expect(computed).toBe(1)
    expect(out.cached).toBe(false)
    expect(out.scannedText).toBe('some skill body')
  })

  it('treats a corrupt cache entry as a miss and recomputes', async () => {
    const kv = new FakeKv()
    const key = await cacheKeyForRequest(REQ)
    kv.store.set(key, '{not valid json')
    let computed = 0
    const out = await resolveCachedScan(REQ, kv, 300, '2026-06-28T00:00:00.000Z', async () => {
      computed += 1
      return fakeOutcome('2026-06-28T00:00:00.000Z')
    })
    expect(computed).toBe(1)
    expect(out.cached).toBe(false)
  })
})
