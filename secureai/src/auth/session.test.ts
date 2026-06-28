import { describe, expect, it } from 'vitest'
import {
  SESSION_COOKIE_NAME,
  buildClearedSessionCookie,
  buildSessionCookie,
  readSessionCookie,
  signSession,
  verifySession,
} from './session'

const SECRET = 'test-session-secret-please-change'
const NOW = 1_700_000_000
const TTL = 3600

describe('signSession / verifySession', () => {
  it('round-trips a valid, unexpired token to its user id', async () => {
    const token = await signSession('user-123', NOW, TTL, SECRET)
    expect(await verifySession(token, NOW, SECRET)).toBe('user-123')
  })

  it('still verifies just before expiry, fails exactly at/after expiry', async () => {
    const token = await signSession('u', NOW, TTL, SECRET)
    expect(await verifySession(token, NOW + TTL - 1, SECRET)).toBe('u')
    expect(await verifySession(token, NOW + TTL, SECRET)).toBeNull()
    expect(await verifySession(token, NOW + TTL + 1, SECRET)).toBeNull()
  })

  it('returns null under the wrong secret', async () => {
    const token = await signSession('u', NOW, TTL, SECRET)
    expect(await verifySession(token, NOW, 'a-different-secret')).toBeNull()
  })

  it('returns null when the payload is tampered', async () => {
    const token = await signSession('victim', NOW, TTL, SECRET)
    const [payload, sig] = token.split('.')
    // Re-encode a different user id but keep the original signature.
    const forgedPayload = btoa('attacker.9999999999')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    expect(await verifySession(`${forgedPayload}.${sig}`, NOW, SECRET)).toBeNull()
    // Sanity: the untampered token still verifies.
    expect(await verifySession(`${payload}.${sig}`, NOW, SECRET)).toBe('victim')
  })

  it('returns null when the signature is tampered', async () => {
    const token = await signSession('u', NOW, TTL, SECRET)
    const [payload] = token.split('.')
    expect(await verifySession(`${payload}.deadbeef`, NOW, SECRET)).toBeNull()
  })

  it('returns null for structurally malformed tokens', async () => {
    expect(await verifySession('no-separator', NOW, SECRET)).toBeNull()
    expect(await verifySession('.sigonly', NOW, SECRET)).toBeNull()
    expect(await verifySession('payloadonly.', NOW, SECRET)).toBeNull()
    expect(await verifySession('', NOW, SECRET)).toBeNull()
  })
})

describe('cookie helpers', () => {
  it('builds a session cookie with the required flags', () => {
    const cookie = buildSessionCookie('tok123', TTL)
    expect(cookie.startsWith(`${SESSION_COOKIE_NAME}=tok123;`)).toBe(true)
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('Secure')
    expect(cookie).toContain('SameSite=Lax')
    expect(cookie).toContain('Path=/')
    expect(cookie).toContain(`Max-Age=${TTL}`)
  })

  it('builds a cleared cookie with Max-Age=0', () => {
    const cookie = buildClearedSessionCookie()
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=;`)
    expect(cookie).toContain('Max-Age=0')
  })

  it('reads the session token out of a Cookie header', () => {
    const req = new Request('https://x.test', {
      headers: { Cookie: `other=1; ${SESSION_COOKIE_NAME}=abc.def; another=2` },
    })
    expect(readSessionCookie(req)).toBe('abc.def')
  })

  it('returns null when the session cookie is absent', () => {
    const req = new Request('https://x.test', { headers: { Cookie: 'other=1' } })
    expect(readSessionCookie(req)).toBeNull()
  })

  it('returns null when there is no Cookie header at all', () => {
    expect(readSessionCookie(new Request('https://x.test'))).toBeNull()
  })

  it('a freshly built cookie round-trips through readSessionCookie + verifySession', async () => {
    const token = await signSession('rt-user', NOW, TTL, SECRET)
    const cookie = buildSessionCookie(token, TTL)
    const value = cookie.split(';')[0]?.split('=')[1] ?? ''
    const req = new Request('https://x.test', { headers: { Cookie: `${SESSION_COOKIE_NAME}=${value}` } })
    const read = readSessionCookie(req)
    expect(read).toBe(token)
    expect(await verifySession(read ?? '', NOW, SECRET)).toBe('rt-user')
  })
})
