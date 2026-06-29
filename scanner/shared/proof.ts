/**
 * Proof builder and verifier, the tamper-evident hash chain over scan evidence.
 *
 * Port of `secureSG/audit/chain.py` (append) and `secureSG/audit/verifier.py`
 * (single forward-pass verify) to TypeScript + Web Crypto. The builder lives in
 * the Worker; `verifyChain` runs in both the Worker (`/api/verify`) and the
 * browser (client-side re-verification with no network round-trip). Because both
 * sides import this exact module, byte-parity is TS↔TS and automatic.
 *
 * Determinism contract: the same sequence of `(kind, payload)` appends always
 * produces the same hashes. Nothing time-varying (no `Date.now`, no random) may
 * enter a payload; per-response timestamps live outside the chain
 * (`ScanResult.scannedAt`).
 */

import type { Proof, ProofStep, ProofStepKind } from './contract'
import { canonicalJson } from './canonical'
import { computeLinkHash } from './hash'
import { ProofError } from './errors'

const textEncoder = new TextEncoder()

/** The hashable identity of a step: its index, kind, and payload only. */
interface CanonicalStepInput {
  index: number
  kind: ProofStepKind
  payload: Record<string, string | number | boolean>
}

/**
 * Serialize a step's hashable identity to canonical bytes.
 *
 * Fields are enumerated explicitly, never spread from a wider object, so the
 * chain-linkage fields (`prevHash`, `currHash`) can never leak into the hashed
 * payload. This mirrors `canonical_payload` in the Python reference.
 *
 * Time complexity: O(k log k) in the payload key count (canonical key sort).
 * Space complexity: O(s) in the serialized size.
 *
 * @param step - The index, kind, and payload of a step.
 * @returns UTF-8 canonical bytes ready to feed into `computeLinkHash`.
 */
export function canonicalPayload(step: CanonicalStepInput): Uint8Array {
  const canonical = canonicalJson({
    index: step.index,
    kind: step.kind,
    payload: step.payload,
  })
  return textEncoder.encode(canonical)
}

/**
 * Append-only builder for a proof chain.
 *
 * The first appended step links to the genesis hash; every subsequent step
 * links to its predecessor's `currHash`. `headHash` tracks the tail in O(1) so
 * the chain tip is never recomputed by scanning the array.
 */
export class ProofBuilder {
  private readonly _genesisHash: string
  private readonly _steps: ProofStep[] = []
  private _headHash: string

  /**
   * @param genesisHash - The chain's genesis hash. The caller derives it once
   *   via `deriveGenesisHash(seed)` so the seed (a config value) lives outside
   *   this pure builder.
   */
  public constructor(genesisHash: string) {
    this._genesisHash = genesisHash
    this._headHash = genesisHash
  }

  /**
   * Append a step and return its `currHash`.
   *
   * Idempotent in the sense that replaying the identical append sequence on a
   * fresh builder yields an identical chain, there is no hidden time/random
   * input. The index is assigned monotonically from the current length.
   *
   * Time complexity: O(k log k + p), canonical key sort plus the digest over
   *   the payload bytes. Space complexity: O(p) for the hash buffer.
   *
   * @param kind - The provenance tag for this step.
   * @param payload - JSON-safe, float-free record (strings/ints/bools only).
   * @returns The newly appended step's `currHash`.
   */
  public async append(
    kind: ProofStepKind,
    payload: Record<string, string | number | boolean>,
  ): Promise<string> {
    const index = this._steps.length
    const prevHash = this._headHash
    const payloadBytes = canonicalPayload({ index, kind, payload })
    const currHash = await computeLinkHash(prevHash, payloadBytes)
    this._steps.push({ index, kind, payload, prevHash, currHash })
    this._headHash = currHash
    return currHash
  }

  /** The chain's genesis hash (the `prevHash` of step 0). */
  public get genesisHash(): string {
    return this._genesisHash
  }

  /** A defensive copy of the steps appended so far, in order. */
  public get steps(): ProofStep[] {
    return [...this._steps]
  }

  /** The current chain tip, genesis when empty, else the last `currHash`. */
  public get headHash(): string {
    return this._headHash
  }

  /**
   * Snapshot the builder as an immutable {@link Proof}.
   *
   * Time complexity: O(n) in the step count (array copy).
   * Space complexity: O(n).
   *
   * @returns The proof: genesis hash, ordered steps, and head hash.
   * @throws {ProofError} If no steps have been appended (an empty proof has no
   *   evidence and would silently "verify", fail loud instead).
   */
  public toProof(): Proof {
    if (this._steps.length === 0) {
      throw new ProofError('cannot snapshot a proof with zero steps')
    }
    return {
      genesisHash: this._genesisHash,
      steps: [...this._steps],
      headHash: this._headHash,
    }
  }
}

/** The outcome of a forward-pass chain verification. */
interface ChainVerification {
  ok: boolean
  firstBrokenIndex: number | null
}

/**
 * Verify a proof chain in a single forward pass from the genesis hash.
 *
 * Mirrors `secureSG/audit/verifier.py`: for each step in order,
 *   1. if `step.prevHash` ≠ the expected previous hash → broken at `step.index`
 *      (catches tampered linkage, reordering, insertion/deletion);
 *   2. recompute `currHash` from the expected previous hash and the step's
 *      `(index, kind, payload)`; if it ≠ `step.currHash` → broken at
 *      `step.index` (catches a tampered payload or a tampered `currHash`);
 *   3. otherwise advance the expected previous hash to `step.currHash`.
 * Returns the first broken index, or `null` when the whole chain is intact.
 *
 * Verification deliberately starts from `proof.genesisHash` (not a trusted
 * external seed) and walks the steps; a caller that wants to bind the proof to a
 * known seed compares `proof.genesisHash` to `deriveGenesisHash(seed)`
 * separately.
 *
 * Time complexity: O(n), one digest per step, no nested rescans.
 * Space complexity: O(1) beyond the input (the expected-prev cursor).
 *
 * @param proof - The proof to verify.
 * @returns `{ ok, firstBrokenIndex }`. `ok` is true and `firstBrokenIndex` is
 *   null exactly when every link is intact.
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

export type { ChainVerification }
