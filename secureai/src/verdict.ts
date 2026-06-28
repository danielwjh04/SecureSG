/**
 * Verdict severity ordering and the two safety-critical verdict operations:
 * `escalate` (tighten-only) and `mapProbabilityToVerdict`. Kept at the package
 * root because both the pipeline and the scan orchestrator depend on it.
 */

import type { Verdict } from './schemas/contract'

/** Total order on verdicts: ALLOW < HUMAN_APPROVAL_REQUIRED < BLOCK. */
export const SEVERITY: Readonly<Record<Verdict, number>> = {
  ALLOW: 0,
  HUMAN_APPROVAL_REQUIRED: 1,
  BLOCK: 2,
}

/**
 * Tighten-only escalation: return the more severe of `baseline` and
 * `candidate`. Ties keep `baseline`. This is the core invariant that lets every
 * pipeline stage only ever raise caution, never relax a prior BLOCK.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function escalate(baseline: Verdict, candidate: Verdict): Verdict {
  return SEVERITY[candidate] > SEVERITY[baseline] ? candidate : baseline
}

/**
 * Map an injection probability to a verdict using configured thresholds:
 * `p >= block` → BLOCK, `p >= review` → HUMAN_APPROVAL_REQUIRED, else ALLOW.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function mapProbabilityToVerdict(
  p: number,
  review: number,
  block: number,
): Verdict {
  if (p >= block) {
    return 'BLOCK'
  }
  if (p >= review) {
    return 'HUMAN_APPROVAL_REQUIRED'
  }
  return 'ALLOW'
}
