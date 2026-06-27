/**
 * Canonical JSON serialization for hash-stable proof payloads.
 *
 * The proof is built in the Worker and re-verified in the browser, so both must
 * hash byte-identical bytes. `JSON.stringify` does not sort object keys, so its
 * output depends on insertion order — unusable for a hash. This module emits the
 * canonical form that matches Python's
 * `json.dumps(value, sort_keys=True, separators=(",", ":"))`
 * (see `secureSG/audit/chain.py:canonical_payload`): keys sorted at every level,
 * compact `,` and `:` separators with no spaces, arrays left in order.
 *
 * Scope is deliberately restricted to JSON-safe primitives so the output can
 * never silently diverge (no `undefined`, no functions, no NaN/Infinity, no
 * `Date`). Floats are permitted by the type system but are intentionally not
 * produced by the proof layer — payloads serialize floats as strings upstream.
 */

import { CanonicalizationError } from '../worker/errors'

/**
 * Serialize a JSON value to its canonical string form: object keys sorted
 * lexicographically (by UTF-16 code unit, matching `Array.prototype.sort`'s
 * default and Python's `sort_keys` for ASCII keys) at every nesting level,
 * compact `,`/`:` separators, arrays preserved in order.
 *
 * Rejects non-JSON-safe inputs loudly (fail-loud, per the engineering rules)
 * rather than emitting bytes that would silently differ between runtimes.
 *
 * Time complexity: O(n log n) where n is the total number of object keys across
 *   all nesting levels (the dominant cost is sorting keys at each object).
 * Space complexity: O(d + s) where d is the maximum nesting depth (recursion)
 *   and s is the length of the produced string.
 *
 * @param value - The value to canonicalize. Must be JSON-safe.
 * @returns The canonical JSON string.
 * @throws {CanonicalizationError} If `value` contains a non-JSON-safe element
 *   (undefined, function, symbol, bigint, or a non-finite number).
 */
export function canonicalJson(value: unknown): string {
  return serialize(value)
}

/**
 * Recursive worker for {@link canonicalJson}.
 *
 * Time complexity: O(k log k) at each object for the key sort, summed over the
 *   tree. Space complexity: O(depth) for the call stack.
 */
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
      // JSON.stringify produces the canonical numeric form (no trailing zeros,
      // exponent form for large/small magnitudes) — identical for a given
      // double across V8 runtimes. Integers (the only numbers the proof layer
      // emits) render without a fractional part.
      return JSON.stringify(value)
    case 'object':
      break
    default:
      // undefined, function, symbol, bigint.
      throw new CanonicalizationError(
        `value of type ${typeof value} is not JSON-safe`,
      )
  }

  if (Array.isArray(value)) {
    // Arrays keep insertion order; only object keys are sorted.
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
