import { describe, expect, it } from 'vitest'
import type { Env } from '../config/env'
import type { ScanResult } from '../schemas/contract'
import { loadConfig } from '../config/env'
import { verifyChain } from '../audit/verify'
import { handleScan } from './scan'

const config = loadConfig({})

function post(body: unknown, raw?: string): Request {
  return new Request('https://secureai.test/api/scan', {
    method: 'POST',
    body: raw ?? JSON.stringify(body),
  })
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
