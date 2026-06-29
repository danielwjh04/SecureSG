// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { canonicalJson } from './canonical'
import { CanonicalizationError } from './errors'

describe('canonicalJson', () => {
  it('sorts object keys lexicographically', () => {
    expect(canonicalJson({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}')
  })

  it('uses compact separators with no whitespace', () => {
    const output = canonicalJson({ a: 1, b: 'x' })
    expect(output).toBe('{"a":1,"b":"x"}')
    expect(output).not.toContain(' ')
    expect(output).not.toContain('\n')
  })

  it('sorts keys recursively in nested objects', () => {
    const value = { z: { d: 1, a: { y: 2, x: 1 } }, a: 0 }
    expect(canonicalJson(value)).toBe('{"a":0,"z":{"a":{"x":1,"y":2},"d":1}}')
  })

  it('sorts keys of objects nested inside arrays', () => {
    const value = { items: [{ b: 1, a: 2 }, { d: 4, c: 3 }] }
    expect(canonicalJson(value)).toBe(
      '{"items":[{"a":2,"b":1},{"c":3,"d":4}]}',
    )
  })

  it('preserves array element order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]')
    expect(canonicalJson(['b', 'a', 'c'])).toBe('["b","a","c"]')
  })

  it('is deterministic regardless of insertion order', () => {
    const first = canonicalJson({ x: 1, y: 2, z: { m: 1, n: 2 } })
    const second = canonicalJson({ z: { n: 2, m: 1 }, y: 2, x: 1 })
    expect(first).toBe(second)
  })

  it('matches the Python json.dumps(sort_keys, compact-separators) form', () => {
    // Reference: json.dumps({"index":0,"kind":"VERDICT","payload":{"b":"y","a":"x"}},
    //   sort_keys=True, separators=(",", ":"))
    const value = { index: 0, kind: 'VERDICT', payload: { b: 'y', a: 'x' } }
    expect(canonicalJson(value)).toBe(
      '{"index":0,"kind":"VERDICT","payload":{"a":"x","b":"y"}}',
    )
  })

  it('serializes the JSON primitives', () => {
    expect(canonicalJson('hi')).toBe('"hi"')
    expect(canonicalJson(42)).toBe('42')
    expect(canonicalJson(true)).toBe('true')
    expect(canonicalJson(false)).toBe('false')
    expect(canonicalJson(null)).toBe('null')
  })

  it('escapes strings like JSON', () => {
    expect(canonicalJson('a"b\\c')).toBe('"a\\"b\\\\c"')
  })

  it('rejects non-finite numbers (fail loud)', () => {
    expect(() => canonicalJson(Number.NaN)).toThrow(CanonicalizationError)
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(
      CanonicalizationError,
    )
  })

  it('rejects non-JSON-safe values (fail loud)', () => {
    expect(() => canonicalJson(undefined)).toThrow(CanonicalizationError)
    expect(() => canonicalJson(() => 0)).toThrow(CanonicalizationError)
    expect(() => canonicalJson(10n)).toThrow(CanonicalizationError)
  })
})
