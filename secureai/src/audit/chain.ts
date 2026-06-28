/**
 * The tamper-evident proof chain: SHA-256 primitives, canonical JSON, and the
 * append-only {@link ProofBuilder}. Port of the proven scanner `shared/{hash,
 * canonical,proof}` modules, consolidated into one audit module.
 *
 * Determinism contract: the same sequence of `(kind, payload)` appends always
 * produces the same hashes. Nothing time-varying (no `Date.now`, no random) may
 * enter a payload; per-response timestamps live outside the chain. Because the
 * exact same code runs in the Worker and the browser, re-verification is
 * byte-identical and needs no network round-trip.
 *
 * The algorithm is pinned to SHA-256 — never weakened to MD5/SHA-1.
 */

import type { Proof, ProofStep, ProofStepKind } from '../schemas/contract'
import { CanonicalizationError, ProofError } from '../errors'

const HASH_ALGORITHM = 'SHA-256'
const textEncoder = new TextEncoder()

// ----------------------------------------------------------------- hashing ---

/**
 * Lowercase-hex-encode a digest.
 *
 * Time complexity: O(n) in the byte count. Space complexity: O(n).
 */
export function hexEncode(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Compute the next link: `sha256( utf8(prevHash) ++ payload )`, lowercase hex.
 * The previous hash is concatenated before the payload, byte-for-byte matching
 * the canonical chain definition.
 *
 * Time complexity: O(p) in the digested byte length. Space complexity: O(p).
 */
export async function computeLinkHash(
  prevHash: string,
  payload: Uint8Array,
): Promise<string> {
  const prefix = textEncoder.encode(prevHash)
  const buffer = new Uint8Array(prefix.length + payload.length)
  buffer.set(prefix, 0)
  buffer.set(payload, prefix.length)
  const digest = await crypto.subtle.digest(HASH_ALGORITHM, buffer)
  return hexEncode(digest)
}

/**
 * Derive the genesis link hash from a configured seed: `sha256(utf8(seed))`,
 * lowercase hex. Changing the seed starts a new, independent chain.
 *
 * Time complexity: O(n) in len(seed). Space complexity: O(n).
 */
export async function deriveGenesisHash(seed: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    HASH_ALGORITHM,
    textEncoder.encode(seed),
  )
  return hexEncode(digest)
}

// --------------------------------------------------------------- canonical ---

/**
 * Serialize a JSON value to its canonical string form: object keys sorted
 * lexicographically at every level, compact `,`/`:` separators, arrays in
 * order. Matches Python `json.dumps(sort_keys=True, separators=(",",":"))`.
 * Rejects non-JSON-safe input loudly rather than emitting divergent bytes.
 *
 * Time complexity: O(n log n) in total key count. Space complexity: O(d + s).
 *
 * @throws {CanonicalizationError} On undefined/function/symbol/bigint or a
 *   non-finite number.
 */
export function canonicalJson(value: unknown): string {
  return serialize(value)
}

function serialize(value: unknown): string {
  if (value === null) {
    return 'null'
  }
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value)
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(
          `non-finite number is not JSON-safe: ${String(value)}`,
        )
      }
      return JSON.stringify(value)
    case 'object':
      break
    default:
      throw new CanonicalizationError(
        `value of type ${typeof value} is not JSON-safe`,
      )
  }
  if (Array.isArray(value)) {
    return `[${value.map((element) => serialize(element)).join(',')}]`
  }
  const record = value as Record<string, unknown>
  const sortedKeys = Object.keys(record).sort()
  const members = sortedKeys.map((key) => {
    const serializedKey = JSON.stringify(key)
    const serializedValue = serialize(record[key])
    return `${serializedKey}:${serializedValue}`
  })
  return `{${members.join(',')}}`
}

// ------------------------------------------------------------------- proof ---

/** The hashable identity of a step: its index, kind, and payload only. */
interface CanonicalStepInput {
  index: number
  kind: ProofStepKind
  payload: Record<string, string | number | boolean>
}

/**
 * Serialize a step's hashable identity to canonical bytes. Fields are
 * enumerated explicitly — never spread from a wider object — so the linkage
 * fields (`prevHash`, `currHash`) can never leak into the hashed payload.
 *
 * Time complexity: O(k log k) in payload key count. Space complexity: O(s).
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
 * Append-only builder for a proof chain. The first appended step links to the
 * genesis hash; every subsequent step links to its predecessor's `currHash`.
 * `headHash` tracks the tail in O(1) so the tip is never recomputed by scanning.
 */
export class ProofBuilder {
  private readonly _genesisHash: string
  private readonly _steps: ProofStep[] = []
  private _headHash: string

  /**
   * @param genesisHash - The chain's genesis hash. The caller derives it once
   *   via `deriveGenesisHash(seed)` so the seed (config) lives outside this
   *   pure builder.
   */
  public constructor(genesisHash: string) {
    this._genesisHash = genesisHash
    this._headHash = genesisHash
  }

  /**
   * Append a step and return its `currHash`. Replaying the identical append
   * sequence on a fresh builder yields an identical chain (no hidden time/random
   * input). The index is assigned monotonically from the current length.
   *
   * Time complexity: O(k log k + p). Space complexity: O(p).
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

  /** The current chain tip — genesis when empty, else the last `currHash`. */
  public get headHash(): string {
    return this._headHash
  }

  /**
   * Snapshot the builder as an immutable {@link Proof}.
   *
   * Time complexity: O(n). Space complexity: O(n).
   *
   * @throws {ProofError} If no steps have been appended (an empty proof has no
   *   evidence and would silently "verify").
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
