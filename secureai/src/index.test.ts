import { describe, expect, it } from 'vitest'
import type { Env } from './config/env'
import { MemoryStore, MemoryD1 } from './db/memory.test'
import worker from './index'

function req(path: string, method = 'POST', body?: unknown): Request {
  const init: RequestInit = { method }
  if (body !== undefined) {
    init.body = JSON.stringify(body)
  }
  return new Request(`https://secureai.test${path}`, init)
}

const baseEnv: Env = {}

describe('worker.fetch routing', () => {
  it('404s any non-/api/ path', async () => {
    const res = await worker.fetch(req('/', 'GET'), baseEnv)
    expect(res.status).toBe(404)
  })

  it('returns 500 when config fails to load', async () => {
    // An out-of-range var makes loadConfig throw ConfigError before any handler.
    const res = await worker.fetch(req('/api/scan'), { SCANNER_MAX_URLS: '0' })
    expect(res.status).toBe(500)
  })

  it('routes POST /api/scan to the scan handler (422 on empty body)', async () => {
    const res = await worker.fetch(req('/api/scan', 'POST', {}), baseEnv)
    expect(res.status).toBe(422)
  })

  it('rejects a non-POST /api/scan with 405', async () => {
    const res = await worker.fetch(req('/api/scan', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/guard to the guard handler (422 on empty body)', async () => {
    const res = await worker.fetch(req('/api/guard', 'POST', {}), baseEnv)
    expect(res.status).toBe(422)
  })

  it('rejects a non-POST /api/guard with 405', async () => {
    const res = await worker.fetch(req('/api/guard', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/signup to the signup handler (201 with a key)', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const res = await worker.fetch(req('/api/signup', 'POST', { email: 'router@example.com' }), {
      DB: d1,
    })
    expect(res.status).toBe(201)
    const body = (await res.json()) as { apiKey: string; tier: string }
    expect(body.tier).toBe('free')
  })

  it('rejects a non-POST /api/signup with 405', async () => {
    const res = await worker.fetch(req('/api/signup', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/verify and maps a malformed proof to 422', async () => {
    const res = await worker.fetch(req('/api/verify', 'POST', { nope: true }), baseEnv)
    expect(res.status).toBe(422)
  })

  it('rejects a non-POST /api/verify with 405', async () => {
    const res = await worker.fetch(req('/api/verify', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('404s an unknown /api/ path', async () => {
    const res = await worker.fetch(req('/api/unknown'), baseEnv)
    expect(res.status).toBe(404)
  })
})
