import { describe, expect, it } from 'vitest'
import { assessPasswordStrength } from './passwordPolicy'
import { COMMON_PASSWORDS } from '../rules/commonPasswords'

describe('assessPasswordStrength', () => {
  it('accepts a password meeting the required character-class count', () => {
    // lowercase + uppercase + digit + symbol = 4 classes.
    expect(assessPasswordStrength('Tr0ub4dour&3', 3)).toEqual({ ok: true })
  })

  it('rejects a password with too few character classes', () => {
    // All lowercase = 1 class; require 3.
    const result = assessPasswordStrength('justlowercase', 3)
    expect(result.ok).toBe(false)
    expect(result.reason).toMatch(/at least 3/)
  })

  it('counts exactly the classes present against the threshold', () => {
    // lowercase + digit = 2 classes; passes when only 2 are required...
    expect(assessPasswordStrength('abcdef12', 2)).toEqual({ ok: true })
    // ...and fails when 3 are required.
    expect(assessPasswordStrength('abcdef12', 3).ok).toBe(false)
  })

  it('rejects a common-denylist password regardless of class count', () => {
    const result = assessPasswordStrength('password123', 1)
    expect(result.ok).toBe(false)
    expect(result.reason).toMatch(/too common/)
  })

  it('matches the denylist case-insensitively', () => {
    expect(assessPasswordStrength('PassWord123', 1).ok).toBe(false)
  })

  it('treats every shipped denylist entry as rejected', () => {
    for (const entry of COMMON_PASSWORDS) {
      expect(assessPasswordStrength(entry, 1).ok).toBe(false)
    }
  })
})
