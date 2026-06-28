import { describe, expect, it } from 'vitest'
import { escalate, mapProbabilityToVerdict, SEVERITY } from './verdict'

describe('escalate', () => {
  it('returns the more severe verdict', () => {
    expect(escalate('ALLOW', 'BLOCK')).toBe('BLOCK')
    expect(escalate('BLOCK', 'ALLOW')).toBe('BLOCK')
    expect(escalate('ALLOW', 'HUMAN_APPROVAL_REQUIRED')).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('keeps the baseline on ties (tighten-only)', () => {
    expect(escalate('HUMAN_APPROVAL_REQUIRED', 'HUMAN_APPROVAL_REQUIRED')).toBe(
      'HUMAN_APPROVAL_REQUIRED',
    )
  })

  it('never relaxes a prior BLOCK', () => {
    expect(escalate('BLOCK', 'HUMAN_APPROVAL_REQUIRED')).toBe('BLOCK')
  })

  it('orders ALLOW < HUMAN_APPROVAL_REQUIRED < BLOCK', () => {
    expect(SEVERITY.ALLOW).toBeLessThan(SEVERITY.HUMAN_APPROVAL_REQUIRED)
    expect(SEVERITY.HUMAN_APPROVAL_REQUIRED).toBeLessThan(SEVERITY.BLOCK)
  })
})

describe('mapProbabilityToVerdict', () => {
  const review = 0.3
  const block = 0.7

  it('maps below review to ALLOW', () => {
    expect(mapProbabilityToVerdict(0.0, review, block)).toBe('ALLOW')
    expect(mapProbabilityToVerdict(0.29, review, block)).toBe('ALLOW')
  })

  it('maps [review, block) to HUMAN_APPROVAL_REQUIRED', () => {
    expect(mapProbabilityToVerdict(0.3, review, block)).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(mapProbabilityToVerdict(0.69, review, block)).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('maps >= block to BLOCK', () => {
    expect(mapProbabilityToVerdict(0.7, review, block)).toBe('BLOCK')
    expect(mapProbabilityToVerdict(1.0, review, block)).toBe('BLOCK')
  })
})
