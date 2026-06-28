import { describe, expect, it } from 'vitest'
import { relativeTime } from './format'

describe('relativeTime', () => {
  const now = Date.parse('2026-06-28T12:00:00.000Z')

  it('reads "just now" within the first minute', () => {
    expect(relativeTime('2026-06-28T11:59:30.000Z', now)).toBe('just now')
  })

  it('reads minutes, hours, and days within a week', () => {
    expect(relativeTime('2026-06-28T11:58:00.000Z', now)).toBe('2m ago')
    expect(relativeTime('2026-06-28T10:00:00.000Z', now)).toBe('2h ago')
    expect(relativeTime('2026-06-25T12:00:00.000Z', now)).toBe('3d ago')
  })

  it('falls back to an absolute date beyond a week', () => {
    // A scan two weeks old is no longer "Nd ago"; it shows a calendar date.
    expect(relativeTime('2026-06-10T12:00:00.000Z', now)).not.toMatch(/ago/)
    expect(relativeTime('2026-06-10T12:00:00.000Z', now)).toMatch(/2026/)
  })

  it('clamps a future timestamp (clock skew) to "just now"', () => {
    expect(relativeTime('2026-06-28T12:05:00.000Z', now)).toBe('just now')
  })

  it('returns an unparseable timestamp verbatim instead of "NaN ago"', () => {
    expect(relativeTime('not-a-date', now)).toBe('not-a-date')
  })
})
