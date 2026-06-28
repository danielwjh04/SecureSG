import { describe, expect, it } from 'vitest'
import { hashPassword, verifyPassword } from './password'

const ITERATIONS = 100_000

describe('hashPassword / verifyPassword', () => {
  it('round-trips a correct password', async () => {
    const stored = await hashPassword('correct horse battery staple', ITERATIONS)
    expect(await verifyPassword('correct horse battery staple', stored)).toBe(true)
  })

  it('rejects a wrong password', async () => {
    const stored = await hashPassword('s3cret-password', ITERATIONS)
    expect(await verifyPassword('not-the-password', stored)).toBe(false)
  })

  it('produces the documented pbkdf2$<iters>$<salt>$<hash> format', async () => {
    const stored = await hashPassword('abcdefgh', ITERATIONS)
    const parts = stored.split('$')
    expect(parts).toHaveLength(4)
    expect(parts[0]).toBe('pbkdf2')
    expect(Number(parts[1])).toBe(ITERATIONS)
    expect((parts[2] ?? '').length).toBeGreaterThan(0)
    expect((parts[3] ?? '').length).toBeGreaterThan(0)
  })

  it('uses a fresh random salt so equal passwords hash differently', async () => {
    const a = await hashPassword('same-password', ITERATIONS)
    const b = await hashPassword('same-password', ITERATIONS)
    expect(a).not.toBe(b)
    // ...yet both verify.
    expect(await verifyPassword('same-password', a)).toBe(true)
    expect(await verifyPassword('same-password', b)).toBe(true)
  })

  it('verifies against the iteration count embedded in the stored hash', async () => {
    // A hash made with more iterations still verifies (params are self-describing).
    const stored = await hashPassword('iter-test', 150_000)
    expect(stored.split('$')[1]).toBe('150000')
    expect(await verifyPassword('iter-test', stored)).toBe(true)
  })

  it('fails closed (false) on a malformed stored hash', async () => {
    expect(await verifyPassword('x', 'not-a-valid-hash')).toBe(false)
    expect(await verifyPassword('x', 'pbkdf2$abc$salt$hash')).toBe(false)
    expect(await verifyPassword('x', 'scrypt$100000$c2FsdA$aGFzaA')).toBe(false)
    expect(await verifyPassword('x', '')).toBe(false)
  })

  it('never stores the plaintext password', async () => {
    const stored = await hashPassword('plaintext-secret-123', ITERATIONS)
    expect(stored).not.toContain('plaintext-secret-123')
  })
})
