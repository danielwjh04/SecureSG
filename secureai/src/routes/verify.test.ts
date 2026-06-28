import { describe, expect, it } from 'vitest'
import type { Proof, VerifyResult } from '../schemas/contract'
import { deriveGenesisHash, ProofBuilder } from '../audit/chain'
import { loadConfig } from '../config/env'
import { ParseError } from '../errors'
import { handleVerify } from './verify'

const config = loadConfig({})

async function freshProof(): Promise<Proof> {
  const genesis = await deriveGenesisHash(config.genesisSeed)
  const builder = new ProofBuilder(genesis)
  await builder.append('SKILL_INPUT', { hash: 'h0' })
  await builder.append('VERDICT', { verdict: 'ALLOW' })
  return builder.toProof()
}

function postVerify(body: unknown): Request {
  return new Request('https://secureai.test/api/verify', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

describe('handleVerify', () => {
  it('returns CHAIN_OK for an intact proof bound to the configured genesis', async () => {
    const proof = await freshProof()
    const response = await handleVerify(postVerify({ proof }), config)
    expect(response.status).toBe(200)
    const result = (await response.json()) as VerifyResult
    expect(result).toEqual({ status: 'CHAIN_OK', firstInvalidIndex: null })
  })

  it('returns CHAIN_BROKEN with the first invalid index for a tampered proof', async () => {
    const proof = await freshProof()
    proof.steps[1]!.payload = { verdict: 'BLOCK' }
    const response = await handleVerify(postVerify({ proof }), config)
    const result = (await response.json()) as VerifyResult
    expect(result).toEqual({ status: 'CHAIN_BROKEN', firstInvalidIndex: 1 })
  })

  it('rejects a forged genesis at index 0 before the per-link pass', async () => {
    const proof = await freshProof()
    proof.genesisHash = await deriveGenesisHash('not-the-configured-seed')
    const response = await handleVerify(postVerify({ proof }), config)
    const result = (await response.json()) as VerifyResult
    expect(result).toEqual({ status: 'CHAIN_BROKEN', firstInvalidIndex: 0 })
  })

  it('throws ParseError on invalid JSON', async () => {
    const request = new Request('https://secureai.test/api/verify', {
      method: 'POST',
      body: '{not json',
    })
    await expect(handleVerify(request, config)).rejects.toBeInstanceOf(ParseError)
  })

  it('throws ParseError on a body that fails schema validation', async () => {
    await expect(handleVerify(postVerify({ proof: { genesisHash: 1 } }), config)).rejects.toBeInstanceOf(
      ParseError,
    )
  })
})
