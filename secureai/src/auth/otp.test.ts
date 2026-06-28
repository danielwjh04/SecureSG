import { describe, expect, it } from 'vitest'
import { generateCode, hashCode, verifyCode } from './otp'

describe('generateCode', () => {
  it('always returns a 6-digit numeric string', () => {
    for (let i = 0; i < 2000; i += 1) {
      const code = generateCode()
      expect(code).toMatch(/^[0-9]{6}$/)
      expect(code).toHaveLength(6)
    }
  })

  it('preserves leading zeros (zero-padded to 6 chars)', () => {
    // Over many draws some low codes must appear; assert every one stays 6 chars
    // (a naive Number→String would drop the padding for values < 100000).
    let sawLow = false
    for (let i = 0; i < 20000; i += 1) {
      const code = generateCode()
      expect(code).toHaveLength(6)
      if (Number(code) < 100000) {
        sawLow = true
      }
    }
    expect(sawLow).toBe(true)
  })

  it('is reasonably unbiased: every leading digit 0-9 appears over many draws', () => {
    // A modulo-biased generator over a 2^32 space would skew, but the leading
    // digit is uniform enough that all ten values must show up in 20k draws.
    const seen = new Set<string>()
    for (let i = 0; i < 20000; i += 1) {
      seen.add(generateCode().charAt(0))
    }
    expect(seen.size).toBe(10)
  })
})

describe('hashCode / verifyCode', () => {
  it('hashes to a 64-char lowercase hex SHA-256 digest', async () => {
    const hash = await hashCode('123456')
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('is deterministic for the same code', async () => {
    expect(await hashCode('042317')).toBe(await hashCode('042317'))
  })

  it('produces different hashes for different codes', async () => {
    expect(await hashCode('111111')).not.toBe(await hashCode('111112'))
  })

  it('verifies a matching code against its hash', async () => {
    const hash = await hashCode('654321')
    expect(await verifyCode('654321', hash)).toBe(true)
  })

  it('rejects a non-matching code', async () => {
    const hash = await hashCode('654321')
    expect(await verifyCode('654320', hash)).toBe(false)
  })

  it('rejects a code against a malformed (wrong-length) stored hash', async () => {
    expect(await verifyCode('123456', 'deadbeef')).toBe(false)
  })
})
