import { describe, expect, it } from 'vitest'
import {
  canonicalJson,
  canonicalPayload,
  computeLinkHash,
  deriveGenesisHash,
  hexEncode,
  ProofBuilder,
} from './chain'
import { CanonicalizationError, ProofError } from '../errors'

describe('canonicalJson', () => {
  it('sorts object keys at every level with compact separators', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}')
  })

  it('preserves array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]')
  })

  it('throws on non-finite numbers', () => {
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(CanonicalizationError)
    expect(() => canonicalJson(Number.NaN)).toThrow(CanonicalizationError)
  })

  it('throws on undefined and functions', () => {
    expect(() => canonicalJson(undefined)).toThrow(CanonicalizationError)
    expect(() => canonicalJson(() => 0)).toThrow(CanonicalizationError)
  })
})

describe('hash primitives', () => {
  it('deriveGenesisHash is deterministic and 64 hex chars', async () => {
    const a = await deriveGenesisHash('seed-x')
    const b = await deriveGenesisHash('seed-x')
    expect(a).toBe(b)
    expect(a).toMatch(/^[0-9a-f]{64}$/)
  })

  it('different seeds derive different genesis hashes', async () => {
    expect(await deriveGenesisHash('a')).not.toBe(await deriveGenesisHash('b'))
  })

  it('computeLinkHash changes with prevHash or payload', async () => {
    const payload = new TextEncoder().encode('p')
    const h1 = await computeLinkHash('aa', payload)
    const h2 = await computeLinkHash('bb', payload)
    const h3 = await computeLinkHash('aa', new TextEncoder().encode('q'))
    expect(h1).not.toBe(h2)
    expect(h1).not.toBe(h3)
  })

  it('hexEncode pads each byte to two chars', () => {
    expect(hexEncode(new Uint8Array([0x0a, 0xff, 0x00]))).toBe('0aff00')
  })
})

describe('canonicalPayload', () => {
  it('hashes only index, kind, and payload (never linkage fields)', () => {
    const a = canonicalPayload({ index: 0, kind: 'SKILL_INPUT', payload: { x: '1' } })
    const decoded = new TextDecoder().decode(a)
    expect(decoded).toBe('{"index":0,"kind":"SKILL_INPUT","payload":{"x":"1"}}')
    expect(decoded).not.toContain('prevHash')
    expect(decoded).not.toContain('currHash')
  })
})

describe('ProofBuilder', () => {
  it('links steps and tracks the head in order', async () => {
    const genesis = await deriveGenesisHash('seed')
    const builder = new ProofBuilder(genesis)
    const h0 = await builder.append('SKILL_INPUT', { hash: 'abc' })
    const h1 = await builder.append('VERDICT', { verdict: 'ALLOW' })

    const proof = builder.toProof()
    expect(proof.genesisHash).toBe(genesis)
    expect(proof.headHash).toBe(h1)
    expect(proof.steps).toHaveLength(2)
    expect(proof.steps[0]?.index).toBe(0)
    expect(proof.steps[0]?.prevHash).toBe(genesis)
    expect(proof.steps[0]?.currHash).toBe(h0)
    expect(proof.steps[1]?.prevHash).toBe(h0)
    expect(proof.steps[1]?.currHash).toBe(h1)
  })

  it('produces an identical chain when the append sequence is replayed', async () => {
    const genesis = await deriveGenesisHash('seed')
    const build = async (): Promise<string> => {
      const b = new ProofBuilder(genesis)
      await b.append('SKILL_INPUT', { hash: 'abc' })
      await b.append('VERDICT', { verdict: 'BLOCK' })
      return b.headHash
    }
    expect(await build()).toBe(await build())
  })

  it('throws when snapshotting an empty proof', async () => {
    const genesis = await deriveGenesisHash('seed')
    expect(() => new ProofBuilder(genesis).toProof()).toThrow(ProofError)
  })

  it('exposes a defensive copy of steps', async () => {
    const genesis = await deriveGenesisHash('seed')
    const builder = new ProofBuilder(genesis)
    await builder.append('SKILL_INPUT', { hash: 'abc' })
    const steps = builder.steps
    steps.pop()
    expect(builder.steps).toHaveLength(1)
  })
})
