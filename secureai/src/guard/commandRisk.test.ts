import { describe, expect, it } from 'vitest'
import { commandTouchesSensitivePath } from './commandRisk'

const MARKERS = new Set(['.ssh/id_rsa', '.env', 'secret', 'credentials'])

describe('commandTouchesSensitivePath', () => {
  it('returns true for a multi-segment marker in a real secret path', () => {
    expect(commandTouchesSensitivePath('cat ~/.ssh/id_rsa', MARKERS)).toBe(true)
  })

  it('returns true for a dotfile marker bounded by a space and end of string', () => {
    expect(commandTouchesSensitivePath('cat .env', MARKERS)).toBe(true)
  })

  it('returns true when marker is bounded by a space and a dot', () => {
    expect(commandTouchesSensitivePath('cat secret.txt', MARKERS)).toBe(true)
  })

  it('returns false for a marker appearing inside a longer alphanumeric word (no false positive)', () => {
    expect(commandTouchesSensitivePath('cat secretariat.md', MARKERS)).toBe(false)
  })

  it('returns true for a Windows-style path after backslash normalization', () => {
    expect(commandTouchesSensitivePath('type C:\\Users\\me\\.ssh\\id_rsa', MARKERS)).toBe(true)
  })

  it('returns false for an empty marker set', () => {
    expect(commandTouchesSensitivePath('cat ~/.ssh/id_rsa', new Set())).toBe(false)
  })

  it('returns false for an empty command', () => {
    expect(commandTouchesSensitivePath('', MARKERS)).toBe(false)
  })

  it('returns true when marker appears as the whole argument (boundary at both ends)', () => {
    expect(commandTouchesSensitivePath('ls credentials', MARKERS)).toBe(true)
  })

  it('returns false for a benign command with no marker', () => {
    expect(commandTouchesSensitivePath('cat README.md', MARKERS)).toBe(false)
  })

  it('returns true for an uppercase path that normalizes to match', () => {
    expect(commandTouchesSensitivePath('cat /home/user/.ENV', MARKERS)).toBe(true)
  })
})
