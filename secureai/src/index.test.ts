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

  it('routes POST /api/checkout and returns 503 when billing is unconfigured', async () => {
    const res = await worker.fetch(req('/api/checkout'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-POST /api/checkout with 405', async () => {
    const res = await worker.fetch(req('/api/checkout', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/portal and returns 503 when billing is unconfigured', async () => {
    const res = await worker.fetch(req('/api/portal'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-POST /api/portal with 405', async () => {
    const res = await worker.fetch(req('/api/portal', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/webhook and returns 503 when billing is unconfigured', async () => {
    const res = await worker.fetch(req('/api/webhook'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-POST /api/webhook with 405', async () => {
    const res = await worker.fetch(req('/api/webhook', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/register and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(
      req('/api/register', 'POST', { email: 'r@example.com', password: 'password123' }),
      baseEnv,
    )
    expect(res.status).toBe(503)
  })

  it('registers + logs in + reads /api/me through the worker with DB and a session secret', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const env: Env = { DB: d1, SESSION_SECRET: 'router-session-secret' }

    const reg = await worker.fetch(
      req('/api/register', 'POST', { email: 'router-auth@example.com', password: 'password123' }),
      env,
    )
    expect(reg.status).toBe(201)
    const cookie = reg.headers.get('Set-Cookie')?.split(';')[0] ?? ''
    expect(cookie).toContain('secureai_session=')

    const me = await worker.fetch(
      new Request('https://secureai.test/api/me', { headers: { Cookie: cookie } }),
      env,
    )
    expect(me.status).toBe(200)
    const body = (await me.json()) as { email: string; tier: string }
    expect(body.email).toBe('router-auth@example.com')
  })

  it('rejects a non-POST /api/register and non-GET /api/me with 405', async () => {
    const reg = await worker.fetch(req('/api/register', 'GET'), baseEnv)
    expect(reg.status).toBe(405)
    const me = await worker.fetch(req('/api/me', 'POST', {}), baseEnv)
    expect(me.status).toBe(405)
  })

  it('routes POST /api/login/verify and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(
      req('/api/login/verify', 'POST', { challengeId: 'x', code: '123456' }),
      baseEnv,
    )
    expect(res.status).toBe(503)
  })

  it('routes POST /api/login/resend and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/login/resend', 'POST', { challengeId: 'x' }), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-POST /api/login/verify and /api/login/resend with 405', async () => {
    expect((await worker.fetch(req('/api/login/verify', 'GET'), baseEnv)).status).toBe(405)
    expect((await worker.fetch(req('/api/login/resend', 'GET'), baseEnv)).status).toBe(405)
  })

  it('routes POST /api/login to a twoFactor challenge when RESEND_API_KEY is set', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const env: Env = { DB: d1, SESSION_SECRET: 'router-2fa-secret', RESEND_API_KEY: 're_test' }
    // Register defers verification to login: it sends no code and issues no
    // session (201 { registered: true }). The first login below sends the code.
    await worker.fetch(
      req('/api/register', 'POST', { email: 'router-2fa@example.com', password: 'password123' }),
      env,
    )
    // A separate fetch with a stubbed global fetch so the Resend call is captured.
    const sentTo: string[] = []
    const originalFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes('api.resend.com')) {
        sentTo.push(String((JSON.parse(String(init?.body)) as { to: string }).to))
        return new Response(null, { status: 200 })
      }
      return originalFetch(input, init)
    }) as typeof fetch
    try {
      const res = await worker.fetch(
        req('/api/login', 'POST', { email: 'router-2fa@example.com', password: 'password123' }),
        env,
      )
      expect(res.status).toBe(200)
      const body = (await res.json()) as { twoFactor?: boolean; email?: string }
      expect(body.twoFactor).toBe(true)
      expect(res.headers.get('Set-Cookie')).toBeNull()
      expect(sentTo).toContain('router-2fa@example.com')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('routes POST /api/logout to a 200 that clears the cookie (no DB needed)', async () => {
    const res = await worker.fetch(req('/api/logout', 'POST', {}), baseEnv)
    expect(res.status).toBe(200)
    expect(res.headers.get('Set-Cookie')).toContain('Max-Age=0')
  })

  it('routes GET /api/stats and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/stats', 'GET'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-GET /api/stats with 405', async () => {
    const res = await worker.fetch(req('/api/stats', 'POST', {}), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes GET /api/scans/recent and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/scans/recent', 'GET'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-GET /api/scans/recent with 405', async () => {
    const res = await worker.fetch(req('/api/scans/recent', 'POST', {}), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes GET /api/admin/overview and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/admin/overview', 'GET'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-GET /api/admin/overview with 405', async () => {
    const res = await worker.fetch(req('/api/admin/overview', 'POST', {}), baseEnv)
    expect(res.status).toBe(405)
  })

  it('returns 403 from /api/admin/overview for an authenticated non-admin', async () => {
    const store = new MemoryStore()
    const d1 = new MemoryD1(store) as unknown as D1Database
    const env: Env = { DB: d1, SESSION_SECRET: 'admin-router-secret' }
    const reg = await worker.fetch(
      req('/api/register', 'POST', { email: 'router-nonadmin@example.com', password: 'password123' }),
      env,
    )
    const cookie = reg.headers.get('Set-Cookie')?.split(';')[0] ?? ''
    const res = await worker.fetch(
      new Request('https://secureai.test/api/admin/overview', { headers: { Cookie: cookie } }),
      env,
    )
    expect(res.status).toBe(403)
  })

  it('routes GET /api/admin/threats and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/admin/threats', 'GET'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-GET /api/admin/threats with 405', async () => {
    const res = await worker.fetch(req('/api/admin/threats', 'POST', {}), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes GET /api/admin/scans/:id and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/admin/scans/abc123', 'GET'), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-GET /api/admin/scans/:id with 405', async () => {
    const res = await worker.fetch(req('/api/admin/scans/abc123', 'POST', {}), baseEnv)
    expect(res.status).toBe(405)
  })

  it('404s a bare /api/admin/scans/ with no id', async () => {
    const res = await worker.fetch(req('/api/admin/scans/', 'GET'), baseEnv)
    expect(res.status).toBe(404)
  })

  it('routes POST /api/admin/members/remove and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/admin/members/remove', 'POST', { userId: 'x' }), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-POST /api/admin/members/remove with 405', async () => {
    const res = await worker.fetch(req('/api/admin/members/remove', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/admin/members/tier and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/admin/members/tier', 'POST', { userId: 'x', tier: 'pro' }), baseEnv)
    expect(res.status).toBe(503)
  })

  it('rejects a non-POST /api/admin/members/tier with 405', async () => {
    const res = await worker.fetch(req('/api/admin/members/tier', 'GET'), baseEnv)
    expect(res.status).toBe(405)
  })

  it('routes POST /api/key/rotate and returns 503 when DB is unconfigured', async () => {
    const res = await worker.fetch(req('/api/key/rotate', 'POST', {}), baseEnv)
    expect(res.status).toBe(503)
  })

  it('routes POST /api/webhook to a 400 when the gateway is configured but the signature is bad', async () => {
    const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
    const env: Env = {
      DB: d1,
      STRIPE_SECRET_KEY: 'sk_test_dummy',
      STRIPE_WEBHOOK_SECRET: 'whsec_dummy',
    }
    const res = await worker.fetch(
      new Request('https://secureai.test/api/webhook', {
        method: 'POST',
        headers: { 'stripe-signature': 't=1,v1=bad' },
        body: '{"id":"evt_1"}',
      }),
      env,
    )
    expect(res.status).toBe(400)
  })
})
