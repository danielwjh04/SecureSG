import { describe, expect, it } from 'vitest'
import { SCAN_STEP_LABELS } from '../config'
import { initialScanState, scanReducer } from './scanMachine'
import type { ScanState } from './scanMachine'
import type { ScanResult } from '../api/types'

const RESULT = { verdict: 'ALLOW' } as unknown as ScanResult

const scanning = (stepIndex: number): ScanState => ({
  phase: 'scanning',
  stepIndex,
  labels: SCAN_STEP_LABELS,
})

describe('initialScanState', () => {
  it('starts idle', () => {
    expect(initialScanState).toEqual({ phase: 'idle' })
  })
})

describe('start', () => {
  it('enters scanning at step 0 with the configured labels from idle', () => {
    const next = scanReducer(initialScanState, { type: 'start' })
    expect(next).toEqual({ phase: 'scanning', stepIndex: 0, labels: SCAN_STEP_LABELS })
  })

  it('restarts from done', () => {
    const next = scanReducer({ phase: 'done', result: RESULT }, { type: 'start' })
    expect(next).toEqual({ phase: 'scanning', stepIndex: 0, labels: SCAN_STEP_LABELS })
  })

  it('restarts from error', () => {
    const next = scanReducer({ phase: 'error', message: 'x' }, { type: 'start' })
    expect(next).toEqual({ phase: 'scanning', stepIndex: 0, labels: SCAN_STEP_LABELS })
  })
})

describe('advance', () => {
  it('increments the step index while scanning', () => {
    const next = scanReducer(scanning(0), { type: 'advance' })
    expect(next).toEqual(scanning(1))
  })

  it('holds on the penultimate (judge) stage, never the final stage', () => {
    const hold = SCAN_STEP_LABELS.length - 2
    // Advancing AT the hold stage stays put...
    expect(scanReducer(scanning(hold), { type: 'advance' })).toEqual(scanning(hold))
    // ...and advancing one stage earlier reaches exactly the hold stage, never
    // the final "Sealing proof chain" stage (which would look frozen).
    expect(scanReducer(scanning(hold - 1), { type: 'advance' })).toEqual(scanning(hold))
  })

  it('is a no-op outside scanning', () => {
    expect(scanReducer(initialScanState, { type: 'advance' })).toEqual(initialScanState)
    const done: ScanState = { phase: 'done', result: RESULT }
    expect(scanReducer(done, { type: 'advance' })).toBe(done)
  })
})

describe('resolve', () => {
  it('moves scanning to done with the result', () => {
    const next = scanReducer(scanning(2), { type: 'resolve', result: RESULT })
    expect(next).toEqual({ phase: 'done', result: RESULT })
  })

  it('is ignored from idle, done, and error', () => {
    expect(scanReducer(initialScanState, { type: 'resolve', result: RESULT })).toEqual(
      initialScanState,
    )
    const done: ScanState = { phase: 'done', result: RESULT }
    expect(scanReducer(done, { type: 'resolve', result: RESULT })).toBe(done)
    const error: ScanState = { phase: 'error', message: 'x' }
    expect(scanReducer(error, { type: 'resolve', result: RESULT })).toBe(error)
  })
})

describe('fail', () => {
  it('moves scanning to error with the message', () => {
    const next = scanReducer(scanning(3), { type: 'fail', message: 'boom' })
    expect(next).toEqual({ phase: 'error', message: 'boom' })
  })

  it('is ignored from idle, done, and error', () => {
    expect(scanReducer(initialScanState, { type: 'fail', message: 'm' })).toEqual(
      initialScanState,
    )
    const done: ScanState = { phase: 'done', result: RESULT }
    expect(scanReducer(done, { type: 'fail', message: 'm' })).toBe(done)
    const error: ScanState = { phase: 'error', message: 'prior' }
    expect(scanReducer(error, { type: 'fail', message: 'm' })).toBe(error)
  })
})

describe('reset', () => {
  it('returns to idle from any phase', () => {
    expect(scanReducer(scanning(2), { type: 'reset' })).toEqual({ phase: 'idle' })
    expect(scanReducer({ phase: 'done', result: RESULT }, { type: 'reset' })).toEqual({
      phase: 'idle',
    })
    expect(scanReducer({ phase: 'error', message: 'x' }, { type: 'reset' })).toEqual({
      phase: 'idle',
    })
  })
})
