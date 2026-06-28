/**
 * Email two-factor login flow: the password-success → emailed-code → verify
 * path that activates ONLY when an EmailSender is configured. The no-sender path
 * (today's immediate-session behavior) is covered in auth.test.ts.
 */

import { describe, expect, it } from 'vitest'
import type { AuthDeps } from './auth'
import type { EmailMessage, EmailSender } from '../email/sender'
import { memoryDatabase } from '../db/memory.test'
import type { Database } from '../db/database'
import { loadConfig } from '../config/env'
import { SESSION_COOKIE_NAME } from '../auth/session'
import { handleLogin, handleLoginResend, handleLoginVerify, handleMe, handleRegister } from './auth'

const config = loadConfig({ SCANNER_PBKDF2_ITERATIONS: '100000' })
const SECRET = 'twofactor-test-secret'

/** An EmailSender that records every sent message (no network). */
class FakeEmailSender implements EmailSender {
  public readonly sent: EmailMessage[] = []
  public failNext = false
  public async send(message: EmailMessage): Promise<void> {
    if (this.failNext) {
      this.failNext = false
      const { EmailError } = await import('../errors')
      throw new EmailError('injected email failure')
    }
    this.sent.push(message)
  }
}

function deps(
  db: Database | null,
  emailSender: EmailSender | null,
  sessionSecret: string | null = SECRET,
): AuthDeps {
  return { db, sessionSecret, config, emailSender }
}

function jsonReq(path: string, body: unknown): Request {
  return new Request(`https://secureai.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function sessionCookieValue(res: Response): string | null {
  const setCookie = res.headers.get('Set-Cookie')
  if (setCookie === null) {
    return null
  }
  const match = new RegExp(`${SESSION_COOKIE_NAME}=([^;]*)`).exec(setCookie)
  return match?.[1] ?? null
}

/** The 6-digit code is embedded verbatim in the email text; pull it back out. */
function codeFromMessage(message: EmailMessage): string {
  const match = /\b([0-9]{6})\b/.exec(message.text)
  if (match === null) {
    throw new Error('no 6-digit code found in email text')
  }
  return match[1] as string
}

/** Register an account so a password login can succeed. */
async function registerAccount(db: Database, email = 'tf@example.com'): Promise<void> {
  await handleRegister(jsonReq('/api/register', { email, password: 'password123' }), deps(db, null))
}

describe('handleLogin with an email sender (2FA active)', () => {
  it('returns twoFactor + masked email, sends the code, and sets NO session cookie', async () => {
    const { db } = memoryDatabase()
    await registerAccount(db, 'zuriel@gmail.com')
    const sender = new FakeEmailSender()

    const res = await handleLogin(
      jsonReq('/api/login', { email: 'zuriel@gmail.com', password: 'password123' }),
      deps(db, sender),
    )

    expect(res.status).toBe(200)
    const body = (await res.json()) as { twoFactor: boolean; challengeId: string; email: string }
    expect(body.twoFactor).toBe(true)
    expect(typeof body.challengeId).toBe('string')
    expect(body.email).toBe('z***@gmail.com')
    // No session cookie yet — the session is withheld until verify.
    expect(sessionCookieValue(res)).toBeNull()
    // The code was emailed to the real address.
    expect(sender.sent).toHaveLength(1)
    expect(sender.sent[0]?.to).toBe('zuriel@gmail.com')
    expect(sender.sent[0]?.subject).toBe('Your SecureAI sign-in code')
    expect(codeFromMessage(sender.sent[0] as EmailMessage)).toMatch(/^[0-9]{6}$/)
  })

  it('persists exactly one challenge and invalidates a prior one on a re-login', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()

    await handleLogin(jsonReq('/api/login', { email: 'tf@example.com', password: 'password123' }), deps(db, sender))
    const firstId = [...store.otpChallenges.keys()][0]
    await handleLogin(jsonReq('/api/login', { email: 'tf@example.com', password: 'password123' }), deps(db, sender))

    expect(store.otpChallenges.size).toBe(1)
    expect(store.otpChallenges.has(firstId as string)).toBe(false)
  })

  it('still returns a generic 401 for a wrong password (no challenge, no email)', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()

    const res = await handleLogin(
      jsonReq('/api/login', { email: 'tf@example.com', password: 'wrong-pass' }),
      deps(db, sender),
    )
    expect(res.status).toBe(401)
    expect(sender.sent).toHaveLength(0)
    expect(store.otpChallenges.size).toBe(0)
  })

  it('returns 502 and issues NO session when the email send fails', async () => {
    const { db } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    sender.failNext = true

    const res = await handleLogin(
      jsonReq('/api/login', { email: 'tf@example.com', password: 'password123' }),
      deps(db, sender),
    )
    expect(res.status).toBe(502)
    expect(sessionCookieValue(res)).toBeNull()
  })
})

/** Run the login step and return the challenge id + the emailed code. */
async function startChallenge(
  db: Database,
  sender: FakeEmailSender,
  email = 'tf@example.com',
): Promise<{ challengeId: string; code: string }> {
  const res = await handleLogin(jsonReq('/api/login', { email, password: 'password123' }), deps(db, sender))
  const body = (await res.json()) as { challengeId: string }
  const code = codeFromMessage(sender.sent[sender.sent.length - 1] as EmailMessage)
  return { challengeId: body.challengeId, code }
}

describe('handleLoginVerify', () => {
  it('issues the session and { user } on the correct code, then spends the challenge', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    const { challengeId, code } = await startChallenge(db, sender)

    const res = await handleLoginVerify(jsonReq('/api/login/verify', { challengeId, code }), deps(db, sender))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { user: { email: string; tier: string } }
    expect(body.user).toEqual({ email: 'tf@example.com', tier: 'free' })
    expect(sessionCookieValue(res)).not.toBeNull()
    // Single-use: the challenge is gone, so a replay of the same code 401s.
    expect(store.otpChallenges.size).toBe(0)
    const replay = await handleLoginVerify(
      jsonReq('/api/login/verify', { challengeId, code }),
      deps(db, sender),
    )
    expect(replay.status).toBe(401)
  })

  it('rejects a wrong code with 401 and increments the attempt counter', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    const { challengeId, code } = await startChallenge(db, sender)
    const wrong = code === '000000' ? '000001' : '000000'

    const res = await handleLoginVerify(jsonReq('/api/login/verify', { challengeId, code: wrong }), deps(db, sender))
    expect(res.status).toBe(401)
    expect(store.otpChallenges.get(challengeId)?.attempts).toBe(1)
  })

  it('rejects an over-attempts challenge with 401 (and spends it)', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    const { challengeId, code } = await startChallenge(db, sender)
    // Drive attempts to the configured cap.
    const challenge = store.otpChallenges.get(challengeId)
    if (challenge !== undefined) {
      challenge.attempts = config.otpMaxAttempts
    }
    // Even the CORRECT code is now rejected, and the stale challenge is deleted.
    const res = await handleLoginVerify(jsonReq('/api/login/verify', { challengeId, code }), deps(db, sender))
    expect(res.status).toBe(401)
    expect(store.otpChallenges.size).toBe(0)
  })

  it('rejects an expired challenge with 401 (and spends it)', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    const { challengeId, code } = await startChallenge(db, sender)
    const challenge = store.otpChallenges.get(challengeId)
    if (challenge !== undefined) {
      challenge.expires_at = new Date(Date.now() - 1000).toISOString()
    }
    const res = await handleLoginVerify(jsonReq('/api/login/verify', { challengeId, code }), deps(db, sender))
    expect(res.status).toBe(401)
    expect(store.otpChallenges.size).toBe(0)
  })

  it('rejects an unknown challenge id with a generic 401', async () => {
    const { db } = memoryDatabase()
    const sender = new FakeEmailSender()
    const res = await handleLoginVerify(
      jsonReq('/api/login/verify', { challengeId: 'nope', code: '123456' }),
      deps(db, sender),
    )
    expect(res.status).toBe(401)
  })

  it('rejects a malformed code (not 6 digits) with 422', async () => {
    const { db } = memoryDatabase()
    const sender = new FakeEmailSender()
    const res = await handleLoginVerify(
      jsonReq('/api/login/verify', { challengeId: 'x', code: '12ab' }),
      deps(db, sender),
    )
    expect(res.status).toBe(422)
  })

  it('returns 503 when DB or session secret is absent', async () => {
    const { db } = memoryDatabase()
    const sender = new FakeEmailSender()
    expect(
      (await handleLoginVerify(jsonReq('/api/login/verify', { challengeId: 'x', code: '123456' }), deps(null, sender)))
        .status,
    ).toBe(503)
    expect(
      (
        await handleLoginVerify(
          jsonReq('/api/login/verify', { challengeId: 'x', code: '123456' }),
          deps(db, sender, null),
        )
      ).status,
    ).toBe(503)
  })
})

describe('handleLoginResend', () => {
  it('rotates to a fresh code on the same user and resends the email', async () => {
    const { db, store } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    const { challengeId, code: firstCode } = await startChallenge(db, sender)

    const res = await handleLoginResend(jsonReq('/api/login/resend', { challengeId }), deps(db, sender))
    expect(res.status).toBe(200)
    const body = (await res.json()) as { challengeId: string }
    expect(typeof body.challengeId).toBe('string')

    // Exactly one live challenge remains; a second email went out.
    expect(store.otpChallenges.size).toBe(1)
    expect(sender.sent).toHaveLength(2)

    // The OLD challenge id no longer verifies; the freshly emailed code does.
    const newCode = codeFromMessage(sender.sent[1] as EmailMessage)
    const stale = await handleLoginVerify(
      jsonReq('/api/login/verify', { challengeId, code: firstCode }),
      deps(db, sender),
    )
    expect(stale.status).toBe(401)
    const ok = await handleLoginVerify(
      jsonReq('/api/login/verify', { challengeId: body.challengeId, code: newCode }),
      deps(db, sender),
    )
    expect(ok.status).toBe(200)
  })

  it('rejects an unknown challenge id with a generic 401', async () => {
    const { db } = memoryDatabase()
    const sender = new FakeEmailSender()
    const res = await handleLoginResend(jsonReq('/api/login/resend', { challengeId: 'nope' }), deps(db, sender))
    expect(res.status).toBe(401)
  })

  it('returns 503 when no email provider is configured', async () => {
    const { db } = memoryDatabase()
    const res = await handleLoginResend(jsonReq('/api/login/resend', { challengeId: 'x' }), deps(db, null))
    expect(res.status).toBe(503)
  })

  it('returns 502 when the resend email fails', async () => {
    const { db } = memoryDatabase()
    await registerAccount(db)
    const sender = new FakeEmailSender()
    const { challengeId } = await startChallenge(db, sender)
    sender.failNext = true
    const res = await handleLoginResend(jsonReq('/api/login/resend', { challengeId }), deps(db, sender))
    expect(res.status).toBe(502)
  })
})

describe('handleRegister with an email sender (verification deferred to login)', () => {
  it('creates an UNVERIFIED account, sends NO code, issues NO session, and returns 201 { registered }', async () => {
    const { db, store } = memoryDatabase()
    const sender = new FakeEmailSender()

    const res = await handleRegister(
      jsonReq('/api/register', { email: 'zuriel@gmail.com', password: 'password123' }),
      deps(db, sender),
    )

    // Register now defers verification to the first login: 201 { registered: true }.
    expect(res.status).toBe(201)
    const body = (await res.json()) as { registered: boolean }
    expect(body).toEqual({ registered: true })
    // No session cookie — the account is not usable until the first login verifies.
    expect(sessionCookieValue(res)).toBeNull()
    // The user row exists but is UNVERIFIED.
    const user = [...store.users.values()].find((u) => u.email === 'zuriel@gmail.com')
    expect(user?.email_verified).toBe(0)
    // No challenge was opened and no code was emailed at signup.
    expect(store.otpChallenges.size).toBe(0)
    expect(sender.sent).toHaveLength(0)
  })

  it("an UNVERIFIED registrant's API key does not authenticate, but the first login verifies it", async () => {
    const { db, store } = memoryDatabase()
    const sender = new FakeEmailSender()
    await handleRegister(jsonReq('/api/register', { email: 'gate@example.com', password: 'password123' }), deps(db, sender))

    // Rotate is unreachable without a session; mint a key directly to assert the
    // verified gate on the API-key path (the account is unverified post-register).
    const { rotateApiKey } = await import('../db/accounts')
    const { findUserByApiKey } = await import('../db/accounts')
    const user = [...store.users.values()].find((u) => u.email === 'gate@example.com')
    const apiKey = await rotateApiKey(db, user?.id as string)
    expect(await findUserByApiKey(db, apiKey)).toBeNull()

    // The first login opens the single emailed code; verifying it makes the
    // account usable and the key resolves.
    const { challengeId, code } = await startChallenge(db, sender, 'gate@example.com')
    const verify = await handleLoginVerify(jsonReq('/api/login/verify', { challengeId, code }), deps(db, sender))
    expect(verify.status).toBe(200)
    expect(await findUserByApiKey(db, apiKey)).toEqual({ userId: user?.id, tier: 'free' })
  })

  it('full path: register → login sends the single code → verify flips email_verified, issues a session, and /api/me works', async () => {
    const { db, store } = memoryDatabase()
    const sender = new FakeEmailSender()
    await handleRegister(jsonReq('/api/register', { email: 'flow@example.com', password: 'password123' }), deps(db, sender))

    // Register sent nothing; the first login opens the one challenge and emails the code.
    expect(sender.sent).toHaveLength(0)
    const login = await handleLogin(jsonReq('/api/login', { email: 'flow@example.com', password: 'password123' }), deps(db, sender))
    expect(login.status).toBe(200)
    const loginBody = (await login.json()) as { twoFactor: boolean; challengeId: string }
    expect(loginBody.twoFactor).toBe(true)
    expect(sessionCookieValue(login)).toBeNull()
    expect(sender.sent).toHaveLength(1)

    const challengeId = loginBody.challengeId
    const code = codeFromMessage(sender.sent[sender.sent.length - 1] as EmailMessage)
    const verify = await handleLoginVerify(jsonReq('/api/login/verify', { challengeId, code }), deps(db, sender))
    expect(verify.status).toBe(200)
    const cookie = sessionCookieValue(verify)
    expect(cookie).not.toBeNull()

    const user = [...store.users.values()].find((u) => u.email === 'flow@example.com')
    expect(user?.email_verified).toBe(1)

    // The freshly minted session cookie authenticates /api/me.
    const me = await handleMe(
      new Request('https://secureai.test/api/me', {
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${cookie}` },
      }),
      deps(db, sender),
    )
    expect(me.status).toBe(200)
    const profile = (await me.json()) as { email: string }
    expect(profile.email).toBe('flow@example.com')
  })

  it('rejects a duplicate email with 409 (and still sends no code)', async () => {
    const { db, store } = memoryDatabase()
    const sender = new FakeEmailSender()
    await handleRegister(jsonReq('/api/register', { email: 'dupe@example.com', password: 'password123' }), deps(db, sender))

    const res = await handleRegister(
      jsonReq('/api/register', { email: 'dupe@example.com', password: 'otherpass1' }),
      deps(db, sender),
    )
    expect(res.status).toBe(409)
    // Neither register opened a challenge or sent an email.
    expect(store.otpChallenges.size).toBe(0)
    expect(sender.sent).toHaveLength(0)
  })
})
