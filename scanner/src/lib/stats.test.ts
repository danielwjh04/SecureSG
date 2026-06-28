// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { zeroFillDaily } from './stats'
import type { StatsDay } from '../api/types'

function day(day: string, scans: number, blocks: number): StatsDay {
  return { day, scans, allows: scans - blocks, reviews: 0, blocks, flagged: blocks }
}

describe('zeroFillDaily', () => {
  const now = new Date('2026-06-28T00:00:00.000Z')

  it('produces a dense window of the requested length ending today', () => {
    const filled = zeroFillDaily([], 30, now)

    expect(filled).toHaveLength(30)
    expect(filled[0].day).toBe('2026-05-30') // 29 days before today
    expect(filled[filled.length - 1].day).toBe('2026-06-28')
  })

  it('zero-fills missing days and keeps server rows that fall in the window', () => {
    const filled = zeroFillDaily([day('2026-06-27', 5, 2)], 30, now)

    const present = filled.find((row) => row.day === '2026-06-27')
    expect(present).toEqual(day('2026-06-27', 5, 2))

    // A day with no server row is a real zero, not undefined.
    const missing = filled.find((row) => row.day === '2026-06-26')
    expect(missing).toEqual({
      day: '2026-06-26',
      scans: 0,
      allows: 0,
      reviews: 0,
      blocks: 0,
      flagged: 0,
    })
  })

  it('drops server rows that fall outside the trailing window', () => {
    const filled = zeroFillDaily([day('2026-01-01', 9, 9)], 30, now)

    expect(filled.some((row) => row.day === '2026-01-01')).toBe(false)
    expect(filled).toHaveLength(30)
  })

  it('returns days in chronological order', () => {
    const filled = zeroFillDaily([], 5, now)
    const days = filled.map((row) => row.day)

    expect(days).toEqual([...days].sort())
  })
})
