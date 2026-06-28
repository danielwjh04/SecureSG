/**
 * Single forward-pass verifier for a proof chain. Runs in both the Worker
 * (`/api/verify`) and the browser (client-side re-verification with no network
 * round-trip). Because both sides import the same {@link canonicalPayload} and
 * {@link computeLinkHash}, byte-parity is automatic.
 */

import type { Proof } from '../schemas/contract'
import { canonicalPayload, computeLinkHash } from './chain'

/** The outcome of a forward-pass chain verification. */
export interface ChainVerification {
  ok: boolean
  firstBrokenIndex: number | null
}

/**
 * Verify a proof chain in a single forward pass from the genesis hash. For each
 * step, in order:
 *   1. if `step.prevHash` ≠ the expected previous hash → broken at `step.index`
 *      (catches tampered linkage, reordering, insertion/deletion);
 *   2. recompute `currHash` from the expected previous hash and the step's
 *      `(index, kind, payload)`; if it ≠ `step.currHash` → broken at
 *      `step.index` (catches a tampered payload or a tampered `currHash`);
 *   3. otherwise advance the expected previous hash to `step.currHash`.
 *
 * Verification deliberately starts from `proof.genesisHash` (not an external
 * seed). A caller that wants to bind the proof to a known seed compares
 * `proof.genesisHash` to `deriveGenesisHash(seed)` separately.
 *
 * Time complexity: O(n) — one digest per step, no nested rescans.
 * Space complexity: O(1) beyond the input.
 */
export async function verifyChain(proof: Proof): Promise<ChainVerification> {
  let expectedPrev = proof.genesisHash
  for (const step of proof.steps) {
    if (step.prevHash !== expectedPrev) {
      return { ok: false, firstBrokenIndex: step.index }
    }
    const payloadBytes = canonicalPayload({
      index: step.index,
      kind: step.kind,
      payload: step.payload,
    })
    const recomputed = await computeLinkHash(expectedPrev, payloadBytes)
    if (recomputed !== step.currHash) {
      return { ok: false, firstBrokenIndex: step.index }
    }
    expectedPrev = step.currHash
  }
  return { ok: true, firstBrokenIndex: null }
}
