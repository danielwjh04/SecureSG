import { beforeAll, describe, expect, it } from 'vitest'
import type { Proof } from '../schemas/contract'
import { deriveGenesisHash, ProofBuilder } from './chain'
import { verifyChain } from './verify'

/** Build a fresh three-step proof for tampering tests. */
async function buildProof(): Promise<Proof> {
  const genesis = await deriveGenesisHash('verify-seed')
  const builder = new ProofBuilder(genesis)
  await builder.append('SKILL_INPUT', { hash: 'h0' })
  await builder.append('REDIRECT_HOP', { from: 'a', to: 'b', status: 301 })
  await builder.append('VERDICT', { verdict: 'BLOCK' })
  return builder.toProof()
}

/** Deep-clone a proof so each test mutates an isolated copy. */
function clone(proof: Proof): Proof {
  return JSON.parse(JSON.stringify(proof)) as Proof
}

describe('verifyChain', () => {
  let intact: Proof
  beforeAll(async () => {
    intact = await buildProof()
  })

  it('accepts an intact chain', async () => {
    expect(await verifyChain(intact)).toEqual({ ok: true, firstBrokenIndex: null })
  })

  it('detects a tampered first step (payload)', async () => {
    const p = clone(intact)
    p.steps[0]!.payload = { hash: 'tampered' }
    expect(await verifyChain(p)).toEqual({ ok: false, firstBrokenIndex: 0 })
  })

  it('detects a tampered middle step (payload)', async () => {
    const p = clone(intact)
    p.steps[1]!.payload = { from: 'evil', to: 'b', status: 301 }
    expect(await verifyChain(p)).toEqual({ ok: false, firstBrokenIndex: 1 })
  })

  it('detects a tampered last step (currHash)', async () => {
    const p = clone(intact)
    p.steps[2]!.currHash = 'deadbeef'
    expect(await verifyChain(p)).toEqual({ ok: false, firstBrokenIndex: 2 })
  })

  it('detects broken linkage (tampered prevHash)', async () => {
    const p = clone(intact)
    p.steps[2]!.prevHash = 'deadbeef'
    expect(await verifyChain(p)).toEqual({ ok: false, firstBrokenIndex: 2 })
  })

  it('detects reordered steps', async () => {
    const p = clone(intact)
    ;[p.steps[1], p.steps[2]] = [p.steps[2]!, p.steps[1]!]
    const result = await verifyChain(p)
    expect(result.ok).toBe(false)
    expect(result.firstBrokenIndex).not.toBeNull()
  })

  it('detects a forged genesis (verification starts from proof.genesisHash)', async () => {
    const p = clone(intact)
    p.genesisHash = 'deadbeef'
    expect(await verifyChain(p)).toEqual({ ok: false, firstBrokenIndex: 0 })
  })
})
