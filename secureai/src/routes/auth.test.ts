import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuthDeps } from './auth'
import type { RateLimitKv } from '../middleware/rateLimit'
import { memoryDatabase } from '../db/memory.test'
import { createFreeUser } from '../db/accounts'
import { setUserRole } from '../db/admin'
import { loadConfig } from '../config/env'
import { SESSION_COOKIE_NAME } from '../auth/session'
import {
  handleKeyRotate,
  handleLogin,
  handleLogout,
  handleMe,
  handleRegister,
} from './auth'

// Keep the PBKDF2 cost at the spec floor so the suite stays fast. Disable the
// online HIBP leaked-password check so register tests make no network call
// (dedicated tests exercise the check with a stubbed fetch). Fixtures use
// 'Sapphire92' (3 character classes, not denylisted) to satisfy the default
// password policy.
const config = loadConfig({
  SCANNER_PBKDF2_ITERATIONS: '100000',
  SCANNER_PWNED_CHECK_ENABLED: 'false',
})
const SECRET = 'route-test-session-secret'

function deps(
  db: AuthDeps['db'],
  sessionSecret: string | null = SECRET,
  kv: AuthDeps['kv'] = null,
): AuthDeps {
  // The existing suite covers the no-2FA path (emailSender null = today's
  // behavior: login issues a session immediately). The 2FA path has its own
  // suite in auth.twofactor.test.ts with a fake sender. `kv` is null by default
  // (rate limit skipped); the rate-limit suite injects a fake store.
  return { db, sessionSecret, config, emailSender: null, kv }
}

function jsonReq(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://secureai.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

/** Extract the session cookie value from a response's Set-Cookie. */
function sessionCookieValue(res: Response): string | null {
  const setCookie = res.headers.get('Set-Cookie')
  if (setCookie === null) {
    return null
  }
  const match = new RegExp(`${SESSION_COOKIE_NAME}=([^;]*)`).exec(setCookie)
  return match?.[1] ?? null
}

describe('handleRegister', () => {
  it('creates a free user, returns 201 { user }, and sets a session cookie', async () => {
    const { db, store } = memoryDatabase()
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'new@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    expect(res.status).toBe(201)
    const body = (await res.json()) as { user: { email: string; tier: string } }
    expect(body.user).toEqual({ email: 'new@example.com', tier: 'free' })
    expect(sessionCookieValue(res)).not.toBeNull()
    expect(res.headers.get('Set-Cookie')).toContain('HttpOnly')
    // With no email provider, the account is verified at creation (no code can be
    // sent), so its session/key are immediately usable — exactly as before.
    const user = [...store.users.values()].find((u) => u.email === 'new@example.com')
    expect(user?.email_verified).toBe(1)
  })

  it('mints an API key behind the scenes (rotatable after register)', async () => {
    const { db } = memoryDatabase()
    await handleRegister(
      jsonReq('/api/register', { email: 'minted@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    // Logging in then rotating proves the account works end-to-end with a key.
    const login = await handleLogin(
      jsonReq('/api/login', { email: 'minted@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    const cookie = sessionCookieValue(login)
    const rotate = await handleKeyRotate(
      new Request('https://secureai.test/api/key/rotate', {
        method: 'POST',
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${cookie}` },
      }),
      deps(db),
    )
    expect(rotate.status).toBe(200)
    const body = (await rotate.json()) as { apiKey: string }
    expect(body.apiKey).toMatch(/^sk_secureai_/)
  })

  it('rejects a duplicate email with 409', async () => {
    const { db } = memoryDatabase()
    await handleRegister(
      jsonReq('/api/register', { email: 'dup@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'dup@example.com', password: 'Sapphire93' }),
      deps(db),
    )
    expect(res.status).toBe(409)
  })

  it('rejects an invalid body (short password) with 422', async () => {
    const { db } = memoryDatabase()
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'short@example.com', password: 'short' }),
      deps(db),
    )
    expect(res.status).toBe(422)
  })

  it('returns 503 when no session secret is configured', async () => {
    const { db } = memoryDatabase()
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'x@example.com', password: 'Sapphire92' }),
      deps(db, null),
    )
    expect(res.status).toBe(503)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'x@example.com', password: 'Sapphire92' }),
      deps(null),
    )
    expect(res.status).toBe(503)
  })

  it('maps a persistence fault to 500 without leaking internals', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true // the first DB read (existence check) throws
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'boom@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    expect(res.status).toBe(500)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('registration_failed')
  })

  it('rejects a non-JSON body with 422', async () => {
    const { db } = memoryDatabase()
    const req = new Request('https://secureai.test/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    })
    const res = await handleRegister(req, deps(db))
    expect(res.status).toBe(422)
  })
})

describe('handleLogin', () => {
  it('logs in with correct credentials → 200 { user } + cookie', async () => {
    const { db } = memoryDatabase()
    await handleRegister(
      jsonReq('/api/register', { email: 'li@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    const res = await handleLogin(
      jsonReq('/api/login', { email: 'li@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { user: { email: string; tier: string } }
    expect(body.user).toEqual({ email: 'li@example.com', tier: 'free' })
    expect(sessionCookieValue(res)).not.toBeNull()
  })

  it('rejects a wrong password with a generic 401', async () => {
    const { db } = memoryDatabase()
    await handleRegister(
      jsonReq('/api/register', { email: 'wp@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    const res = await handleLogin(
      jsonReq('/api/login', { email: 'wp@example.com', password: 'wrong-password' }),
      deps(db),
    )
    expect(res.status).toBe(401)
    const body = (await res.json()) as { error: string; message: string }
    expect(body.error).toBe('invalid_credentials')
  })

  it('rejects an unknown email with the SAME generic 401 (no field disclosure)', async () => {
    const { db } = memoryDatabase()
    await handleRegister(
      jsonReq('/api/register', { email: 'present@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    // Wrong password on a real account...
    const wrongPw = await handleLogin(
      jsonReq('/api/login', { email: 'present@example.com', password: 'bad-password' }),
      deps(db),
    )
    // ...and an entirely unknown email both return the identical body/status,
    // so the response cannot be used to enumerate which accounts exist.
    const unknown = await handleLogin(
      jsonReq('/api/login', { email: 'nobody@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    expect(wrongPw.status).toBe(401)
    expect(unknown.status).toBe(401)
    expect(await unknown.json()).toEqual(await wrongPw.json())
  })

  it('rejects login for an API-key-only account (no password) with 401', async () => {
    const { db } = memoryDatabase()
    await createFreeUser(db, 'keyonly@example.com')
    const res = await handleLogin(
      jsonReq('/api/login', { email: 'keyonly@example.com', password: 'whatever-1' }),
      deps(db),
    )
    expect(res.status).toBe(401)
  })

  it('maps a persistence fault during lookup to 500', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true
    const res = await handleLogin(
      jsonReq('/api/login', { email: 'fault@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    expect(res.status).toBe(500)
  })

  it('returns 503 when the account store or session secret is absent', async () => {
    const { db } = memoryDatabase()
    expect(
      (await handleLogin(jsonReq('/api/login', { email: 'a@b.com', password: 'Sapphire92' }), deps(null)))
        .status,
    ).toBe(503)
    expect(
      (
        await handleLogin(
          jsonReq('/api/login', { email: 'a@b.com', password: 'Sapphire92' }),
          deps(db, null),
        )
      ).status,
    ).toBe(503)
  })
})

describe('handleLogout', () => {
  it('returns 200 and clears the cookie (Max-Age=0)', async () => {
    const res = handleLogout()
    expect(res.status).toBe(200)
    expect(res.headers.get('Set-Cookie')).toContain('Max-Age=0')
  })
})

describe('handleMe', () => {
  it('returns the profile via a session cookie', async () => {
    const { db } = memoryDatabase()
    const reg = await handleRegister(
      jsonReq('/api/register', { email: 'me@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    const cookie = sessionCookieValue(reg)
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${cookie}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as {
      email: string
      tier: string
      createdAt: string
      apiKeyPrefix: string | null
    }
    expect(body.email).toBe('me@example.com')
    expect(body.tier).toBe('free')
    expect(typeof body.createdAt).toBe('string')
    expect(body.apiKeyPrefix).toBe('sk_secureai_')
  })

  it('round-trips the names supplied at registration through /api/me', async () => {
    const { db } = memoryDatabase()
    const reg = await handleRegister(
      jsonReq('/api/register', {
        firstName: 'Daniel',
        lastName: 'Wong',
        email: 'named@example.com',
        password: 'Sapphire92',
      }),
      deps(db),
    )
    const cookie = sessionCookieValue(reg)
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${cookie}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { firstName: string | null; lastName: string | null }
    expect(body.firstName).toBe('Daniel')
    expect(body.lastName).toBe('Wong')
  })

  it('returns null names for an account registered without them', async () => {
    const { db } = memoryDatabase()
    const reg = await handleRegister(
      jsonReq('/api/register', { email: 'noname-me@example.com', password: 'Sapphire92' }),
      deps(db),
    )
    const cookie = sessionCookieValue(reg)
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${cookie}` },
      }),
      deps(db),
    )
    const body = (await res.json()) as { firstName: string | null; lastName: string | null }
    expect(body.firstName).toBeNull()
    expect(body.lastName).toBeNull()
  })

  it('returns the profile via a Bearer API key', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'bearer-me@example.com')
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${apiKey}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { email: string }
    expect(body.email).toBe('bearer-me@example.com')
  })

  it('returns isAdmin: false for a non-admin email', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'plain@example.com')
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${apiKey}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { isAdmin: boolean }
    expect(body.isAdmin).toBe(false)
  })

  it('returns isAdmin: true when the email is in config.adminEmails', async () => {
    const { db } = memoryDatabase()
    const adminConfig = loadConfig({ SCANNER_ADMIN_EMAILS: 'boss@example.com' })
    const { apiKey } = await createFreeUser(db, 'boss@example.com')
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${apiKey}` },
      }),
      { db, sessionSecret: SECRET, config: adminConfig, emailSender: null, kv: null },
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { isAdmin: boolean }
    expect(body.isAdmin).toBe(true)
  })

  it('returns role member + isAdmin/isOwner false for a plain account', async () => {
    const { db } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'plainrole@example.com')
    const res = await handleMe(
      new Request('https://secureai.test/api/me', { headers: { Authorization: `Bearer ${apiKey}` } }),
      deps(db),
    )
    const body = (await res.json()) as { role: string; isAdmin: boolean; isOwner: boolean }
    expect(body).toMatchObject({ role: 'member', isAdmin: false, isOwner: false })
  })

  it('returns role admin + isAdmin true / isOwner false for a granted admin', async () => {
    const { db } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'adminrole@example.com')
    await setUserRole(db, user.id, 'admin')
    const res = await handleMe(
      new Request('https://secureai.test/api/me', { headers: { Authorization: `Bearer ${apiKey}` } }),
      deps(db),
    )
    const body = (await res.json()) as { role: string; isAdmin: boolean; isOwner: boolean }
    expect(body).toMatchObject({ role: 'admin', isAdmin: true, isOwner: false })
  })

  it('returns role owner + isAdmin/isOwner true for an allowlisted email', async () => {
    const { db } = memoryDatabase()
    const ownerConfig = loadConfig({ SCANNER_ADMIN_EMAILS: 'boss@example.com' })
    const { apiKey } = await createFreeUser(db, 'boss@example.com')
    const res = await handleMe(
      new Request('https://secureai.test/api/me', { headers: { Authorization: `Bearer ${apiKey}` } }),
      { db, sessionSecret: SECRET, config: ownerConfig, emailSender: null, kv: null },
    )
    const body = (await res.json()) as { role: string; isAdmin: boolean; isOwner: boolean }
    expect(body).toMatchObject({ role: 'owner', isAdmin: true, isOwner: true })
  })

  it('returns 401 when unauthenticated', async () => {
    const { db } = memoryDatabase()
    const res = await handleMe(new Request('https://secureai.test/api/me'), deps(db))
    expect(res.status).toBe(401)
  })

  it('returns 401 when a Bearer key resolves but the user row is gone', async () => {
    const { db, store } = memoryDatabase()
    const { user, apiKey } = await createFreeUser(db, 'vanish@example.com')
    store.users.delete(user.id)
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${apiKey}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleMe(new Request('https://secureai.test/api/me'), deps(null))
    expect(res.status).toBe(503)
  })

  it('maps a persistence fault to 500', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'mefault@example.com')
    store.failNext = true
    const res = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${apiKey}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(500)
  })
})

describe('handleKeyRotate', () => {
  it('deactivates the old key and returns a working new one (shown once)', async () => {
    const { db } = memoryDatabase()
    const { apiKey: oldKey } = await createFreeUser(db, 'rot@example.com')

    const res = await handleKeyRotate(
      new Request('https://secureai.test/api/key/rotate', {
        method: 'POST',
        headers: { Authorization: `Bearer ${oldKey}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(200)
    const body = (await res.json()) as { apiKey: string }
    expect(body.apiKey).toMatch(/^sk_secureai_/)

    // The new key authenticates /api/me; the old one no longer does.
    const meNew = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${body.apiKey}` },
      }),
      deps(db),
    )
    expect(meNew.status).toBe(200)
    const meOld = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Authorization: `Bearer ${oldKey}` },
      }),
      deps(db),
    )
    expect(meOld.status).toBe(401)
  })

  it('returns 401 when unauthenticated', async () => {
    const { db } = memoryDatabase()
    const res = await handleKeyRotate(
      new Request('https://secureai.test/api/key/rotate', { method: 'POST' }),
      deps(db),
    )
    expect(res.status).toBe(401)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleKeyRotate(
      new Request('https://secureai.test/api/key/rotate', { method: 'POST' }),
      deps(null),
    )
    expect(res.status).toBe(503)
  })

  it('maps a persistence fault during rotation to 500', async () => {
    const { db, store } = memoryDatabase()
    const { apiKey } = await createFreeUser(db, 'rotfault@example.com')
    // Auth succeeds (first read), then the revoke write throws.
    let calls = 0
    const original = store.execute.bind(store)
    store.execute = (sql: string, params: readonly unknown[]) => {
      calls += 1
      if (calls === 1 && sql.includes("status = 'revoked'")) {
        throw new Error('injected revoke failure')
      }
      return original(sql, params)
    }
    const res = await handleKeyRotate(
      new Request('https://secureai.test/api/key/rotate', {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}` },
      }),
      deps(db),
    )
    expect(res.status).toBe(500)
  })
})

/** A tiny in-memory KV fake for the rate-limit tests. */
function fakeKv(): RateLimitKv {
  const store = new Map<string, string>()
  return {
    get: async (key) => store.get(key) ?? null,
    put: async (key, value) => {
      store.set(key, value)
    },
  }
}

describe('auth rate limiting', () => {
  // A config with a low per-IP auth cap so the 429 is reached in a few calls.
  const cappedConfig = loadConfig({
    SCANNER_PBKDF2_ITERATIONS: '100000',
    SCANNER_PWNED_CHECK_ENABLED: 'false',
    SCANNER_AUTH_RATE_PER_HOUR: '2',
  })

  it('returns 429 on /api/login once the per-IP hourly cap is exceeded', async () => {
    const { db } = memoryDatabase()
    const d: AuthDeps = {
      db,
      sessionSecret: SECRET,
      config: cappedConfig,
      emailSender: null,
      kv: fakeKv(),
    }
    const attempt = (): Promise<Response> =>
      handleLogin(
        jsonReq('/api/login', { email: 'rl@example.com', password: 'Sapphire92' }, { 'CF-Connecting-IP': '5.5.5.5' }),
        d,
      )
    // Unknown account → 401 each, but every attempt is counted; the 3rd is over the cap of 2.
    expect((await attempt()).status).toBe(401)
    expect((await attempt()).status).toBe(401)
    expect((await attempt()).status).toBe(429)
  })

  it('keys the cap per IP, so a different IP is unaffected', async () => {
    const { db } = memoryDatabase()
    const kv = fakeKv()
    const d: AuthDeps = { db, sessionSecret: SECRET, config: cappedConfig, emailSender: null, kv }
    const hit = (ip: string): Promise<Response> =>
      handleLogin(
        jsonReq('/api/login', { email: 'rl2@example.com', password: 'Sapphire92' }, { 'CF-Connecting-IP': ip }),
        d,
      )
    await hit('6.6.6.6')
    await hit('6.6.6.6')
    expect((await hit('6.6.6.6')).status).toBe(429)
    // A fresh IP still has its own budget.
    expect((await hit('7.7.7.7')).status).toBe(401)
  })

  it('skips the limit entirely when no KV is configured', async () => {
    const { db } = memoryDatabase()
    const d: AuthDeps = {
      db,
      sessionSecret: SECRET,
      config: cappedConfig,
      emailSender: null,
      kv: null,
    }
    for (let i = 0; i < 5; i += 1) {
      const res = await handleLogin(
        jsonReq('/api/login', { email: 'nolimit@example.com', password: 'Sapphire92' }),
        d,
      )
      // Never 429 — always the normal invalid-credentials path.
      expect(res.status).toBe(401)
    }
  })
})

describe('handleRegister password policy', () => {
  it('rejects a weak password (too few character classes) with 422', async () => {
    const { db } = memoryDatabase()
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'weak@example.com', password: 'alllowercase' }),
      deps(db),
    )
    expect(res.status).toBe(422)
    const body = (await res.json()) as { error: string }
    expect(body.error).toBe('weak_password')
  })

  it('rejects a common denylisted password with 422', async () => {
    const { db } = memoryDatabase()
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'common@example.com', password: 'Password123' }),
      deps(db),
    )
    // 'password123' is on the denylist (matched case-insensitively).
    expect(res.status).toBe(422)
    expect(((await res.json()) as { error: string }).error).toBe('weak_password')
  })

  it('rejects a breached password via the HIBP check with 422', async () => {
    const { db } = memoryDatabase()
    const pwnedConfig = loadConfig({
      SCANNER_PBKDF2_ITERATIONS: '100000',
      SCANNER_PWNED_CHECK_ENABLED: 'true',
    })
    // Stub HIBP to report the password's suffix as breached.
    const password = 'Sapphire92'
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password))
    const hash = [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(`${hash.slice(5)}:99`, { status: 200 })),
    )
    const d: AuthDeps = { db, sessionSecret: SECRET, config: pwnedConfig, emailSender: null, kv: null }
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'breached@example.com', password }),
      d,
    )
    expect(res.status).toBe(422)
    expect(((await res.json()) as { error: string }).error).toBe('breached_password')
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})
