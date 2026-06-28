import { afterEach, describe, expect, it, vi } from 'vitest'
import { isPasswordBreached } from './breachCheck'

const encoder = new TextEncoder()

/** Uppercase-hex SHA-1, mirroring the module's internal hashing, for fixtures. */
async function sha1Upper(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', encoder.encode(value))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('isPasswordBreached', () => {
  it('returns true when the hash suffix appears in the range response, sending only the 5-char prefix', async () => {
    const password = 'hunter2breach'
    const hash = await sha1Upper(password)
    const prefix = hash.slice(0, 5)
    const suffix = hash.slice(5)

    let requestedUrl = ''
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        requestedUrl = url
        // The breached entry plus an unrelated one, in HIBP's `SUFFIX:count` shape.
        return new Response(`00000000000000000000000000000000000:9\n${suffix}:42`, { status: 200 })
      }),
    )

    expect(await isPasswordBreached(password, 2500)).toBe(true)
    // k-anonymity: only the 5-char prefix is sent; the suffix never leaves the Worker.
    expect(requestedUrl.endsWith(prefix)).toBe(true)
    expect(requestedUrl).not.toContain(suffix)
  })

  it('returns false when the suffix is absent from the range response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1', { status: 200 })),
    )
    expect(await isPasswordBreached('a-unique-passphrase-9173', 2500)).toBe(false)
  })

  it('fails OPEN (false) on a non-200 response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('rate limited', { status: 429 })))
    expect(await isPasswordBreached('whatever', 2500)).toBe(false)
  })

  it('fails OPEN (false) when the fetch throws (timeout / network)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('aborted')
      }),
    )
    expect(await isPasswordBreached('whatever', 2500)).toBe(false)
  })
})
