import { describe, expect, it } from 'vitest'
import type { AuthDeps } from './auth'
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

// Keep the PBKDF2 cost at the spec floor so the suite stays fast.
const config = loadConfig({ SCANNER_PBKDF2_ITERATIONS: '100000' })
const SECRET = 'route-test-session-secret'

function deps(db: AuthDeps['db'], sessionSecret: string | null = SECRET): AuthDeps {
  // The existing suite covers the no-2FA path (emailSender null = today's
  // behavior: login issues a session immediately). The 2FA path has its own
  // suite in auth.twofactor.test.ts with a fake sender.
  return { db, sessionSecret, config, emailSender: null }
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
      jsonReq('/api/register', { email: 'new@example.com', password: 'password123' }),
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
      jsonReq('/api/register', { email: 'minted@example.com', password: 'password123' }),
      deps(db),
    )
    // Logging in then rotating proves the account works end-to-end with a key.
    const login = await handleLogin(
      jsonReq('/api/login', { email: 'minted@example.com', password: 'password123' }),
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
      jsonReq('/api/register', { email: 'dup@example.com', password: 'password123' }),
      deps(db),
    )
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'dup@example.com', password: 'otherpass1' }),
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
      jsonReq('/api/register', { email: 'x@example.com', password: 'password123' }),
      deps(db, null),
    )
    expect(res.status).toBe(503)
  })

  it('returns 503 when the account store is absent', async () => {
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'x@example.com', password: 'password123' }),
      deps(null),
    )
    expect(res.status).toBe(503)
  })

  it('maps a persistence fault to 500 without leaking internals', async () => {
    const { db, store } = memoryDatabase()
    store.failNext = true // the first DB read (existence check) throws
    const res = await handleRegister(
      jsonReq('/api/register', { email: 'boom@example.com', password: 'password123' }),
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
      jsonReq('/api/register', { email: 'li@example.com', password: 'password123' }),
      deps(db),
    )
    const res = await handleLogin(
      jsonReq('/api/login', { email: 'li@example.com', password: 'password123' }),
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
      jsonReq('/api/register', { email: 'wp@example.com', password: 'password123' }),
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
      jsonReq('/api/register', { email: 'present@example.com', password: 'password123' }),
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
      jsonReq('/api/login', { email: 'nobody@example.com', password: 'password123' }),
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
      jsonReq('/api/login', { email: 'fault@example.com', password: 'password123' }),
      deps(db),
    )
    expect(res.status).toBe(500)
  })

  it('returns 503 when the account store or session secret is absent', async () => {
    const { db } = memoryDatabase()
    expect(
      (await handleLogin(jsonReq('/api/login', { email: 'a@b.com', password: 'password123' }), deps(null)))
        .status,
    ).toBe(503)
    expect(
      (
        await handleLogin(
          jsonReq('/api/login', { email: 'a@b.com', password: 'password123' }),
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
      jsonReq('/api/register', { email: 'me@example.com', password: 'password123' }),
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
      { db, sessionSecret: SECRET, config: adminConfig, emailSender: null },
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
      { db, sessionSecret: SECRET, config: ownerConfig, emailSender: null },
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
