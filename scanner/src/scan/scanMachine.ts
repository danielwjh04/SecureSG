/**
 * The pure state machine that drives a scan's lifecycle. Kept free of effects so
 * it can be exhaustively unit-tested: `useScan` owns the timers and the fetch,
 * this module owns only the transitions.
 */

import { SCAN_STEP_LABELS } from '../config'
import type { ScanResult } from '../api/types'

/** The scan UI's discriminated state. */
export type ScanState =
  | { phase: 'idle' }
  | { phase: 'scanning'; stepIndex: number; labels: readonly string[] }
  | { phase: 'done'; result: ScanResult }
  | { phase: 'error'; message: string }

/** Events the machine reacts to. */
export type ScanAction =
  | { type: 'start' }
  | { type: 'advance' }
  | { type: 'resolve'; result: ScanResult }
  | { type: 'fail'; message: string }
  | { type: 'reset' }

/** The machine's resting state before any scan is requested. */
export const initialScanState: ScanState = { phase: 'idle' }

/**
 * Apply one action to the scan state.
 *
 * Transition rules:
 *   - `start` (from any phase) → `scanning` at step 0 with the configured labels.
 *   - `advance` (only while `scanning`) → next step, but it HOLDS on the
 *     penultimate ("judge") stage rather than the terminal "seal" stage. The
 *     judge is the genuinely slow step (the live model call), so a multi-second
 *     hold there reads as active work; holding on the final stage instead looked
 *     frozen. The terminal stage resolves into the result view, not the stepper.
 *   - `resolve` / `fail` (only while `scanning`) → `done` / `error`. Ignored
 *     otherwise so a late-arriving settle after a `reset` cannot resurrect state.
 *   - `reset` (from any phase) → `idle`.
 * Any non-applicable action returns the current state unchanged.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function scanReducer(state: ScanState, action: ScanAction): ScanState {
  switch (action.type) {
    case 'start':
      return { phase: 'scanning', stepIndex: 0, labels: SCAN_STEP_LABELS }
    case 'advance': {
      if (state.phase !== 'scanning') return state
      // Never advance past the penultimate stage on the timer; `holdIndex` stays
      // >= 0 for short pipelines.
      const holdIndex = Math.max(0, state.labels.length - 2)
      return {
        phase: 'scanning',
        labels: state.labels,
        stepIndex: Math.min(state.stepIndex + 1, holdIndex),
      }
    }
    case 'resolve':
      if (state.phase !== 'scanning') return state
      return { phase: 'done', result: action.result }
    case 'fail':
      if (state.phase !== 'scanning') return state
      return { phase: 'error', message: action.message }
    case 'reset':
      return { phase: 'idle' }
  }
}
