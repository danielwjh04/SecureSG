import { describe, expect, it } from 'vitest'
import { getScanContent, putScanContent, type ObjectStore } from './r2'

/** In-memory R2 fake exposing its map; values are read back via a `text()` body. */
function fakeStore(): ObjectStore & { map: Map<string, string> } {
  const map = new Map<string, string>()
  return {
    map,
    put: async (key, value) => {
      map.set(key, value)
    },
    get: async (key) => {
      const value = map.get(key)
      return value === undefined ? null : { text: async () => value }
    },
  }
}

describe('r2 scan-content offload', () => {
  it('round-trips full content keyed by scan id', async () => {
    const store = fakeStore()
    await putScanContent(store, 'scan-1', 'the full untruncated payload')
    expect(store.map.has('scan-content/scan-1')).toBe(true)
    expect(await getScanContent(store, 'scan-1')).toBe('the full untruncated payload')
  })

  it('returns null for a missing object', async () => {
    expect(await getScanContent(fakeStore(), 'absent')).toBeNull()
  })

  it('swallows a put failure (best-effort; D1 preview remains the record)', async () => {
    const store: ObjectStore = {
      put: async () => {
        throw new Error('r2 down')
      },
      get: async () => null,
    }
    await expect(putScanContent(store, 'scan-1', 'x')).resolves.toBeUndefined()
  })

  it('fails open to null on a get error', async () => {
    const store: ObjectStore = {
      put: async () => undefined,
      get: async () => {
        throw new Error('r2 down')
      },
    }
    expect(await getScanContent(store, 'scan-1')).toBeNull()
  })
})
