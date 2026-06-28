// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { RedirectResolutionError } from '../errors'
import {
  assertSafeUrl,
  isPrivateOrLoopbackHost,
  isRawIpLiteral,
  traceRedirects,
  type RedirectTraceConfig,
  type SsrfConfig,
} from './redirects'

// https-only, matching the documented SCANNER_ALLOWED_SCHEMES default.
const SSRF_CONFIG: SsrfConfig = { allowedSchemes: new Set(['https']) }

/** Convenience: parse and assert in one step so tests read as URL strings. */
function assert(urlString: string): void {
  assertSafeUrl(new URL(urlString), SSRF_CONFIG)
}

describe('assertSafeUrl — scheme', () => {
  it('accepts a normal https URL', () => {
    expect(() => assert('https://example.com/path')).not.toThrow()
  })

  it('rejects http (not in the allowed scheme set)', () => {
    expect(() => assert('http://example.com/path')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects non-web schemes (ftp, file, data, gopher)', () => {
    expect(() => assert('ftp://example.com/x')).toThrow(RedirectResolutionError)
    expect(() => assert('file:///etc/passwd')).toThrow(RedirectResolutionError)
    expect(() => assert('gopher://example.com/')).toThrow(
      RedirectResolutionError,
    )
  })
})

describe('assertSafeUrl — raw IP literals', () => {
  it('rejects a raw IPv4 literal host', () => {
    expect(() => assert('https://93.184.216.34/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects a raw IPv6 literal host', () => {
    expect(() => assert('https://[2001:db8::1]/')).toThrow(
      RedirectResolutionError,
    )
  })
})

describe('assertSafeUrl — private / loopback / link-local', () => {
  it('rejects RFC1918 10.0.0.0/8', () => {
    expect(() => assert('https://10.1.2.3/')).toThrow(RedirectResolutionError)
  })

  it('rejects RFC1918 172.16.0.0/12', () => {
    expect(() => assert('https://172.16.5.5/')).toThrow(RedirectResolutionError)
    expect(() => assert('https://172.31.255.255/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects RFC1918 192.168.0.0/16 (a private range)', () => {
    expect(() => assert('https://192.168.1.1/')).toThrow(RedirectResolutionError)
  })

  it('rejects IPv4 loopback 127.0.0.0/8', () => {
    expect(() => assert('https://127.0.0.1/')).toThrow(RedirectResolutionError)
  })

  it('rejects IPv4 link-local 169.254.0.0/16', () => {
    expect(() => assert('https://169.254.1.1/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects the cloud metadata IP 169.254.169.254', () => {
    // The single most important SSRF target: the link-local metadata endpoint.
    expect(() => assert('https://169.254.169.254/latest/meta-data/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects IPv6 loopback ::1', () => {
    expect(() => assert('https://[::1]/')).toThrow(RedirectResolutionError)
  })

  it('rejects IPv6 link-local fe80::/10', () => {
    expect(() => assert('https://[fe80::1]/')).toThrow(RedirectResolutionError)
  })
})

describe('assertSafeUrl — internal hostnames', () => {
  it('rejects localhost', () => {
    expect(() => assert('https://localhost/')).toThrow(RedirectResolutionError)
  })

  it('rejects *.internal', () => {
    expect(() => assert('https://api.internal/')).toThrow(
      RedirectResolutionError,
    )
  })

  it('rejects *.local', () => {
    expect(() => assert('https://printer.local/')).toThrow(
      RedirectResolutionError,
    )
  })
})

describe('assertSafeUrl — accepts legitimate public https', () => {
  it('accepts a normal public hostname with a port and path', () => {
    expect(() => assert('https://example.com:443/a/b?c=d')).not.toThrow()
  })

  it('accepts a subdomain that merely contains the word internal', () => {
    // ".internal" is a suffix check; "internal-docs.example.com" must pass.
    expect(() => assert('https://internal-docs.example.com/')).not.toThrow()
  })
})

describe('isRawIpLiteral', () => {
  it('recognizes IPv4 dotted-quads', () => {
    expect(isRawIpLiteral('8.8.8.8')).toBe(true)
    expect(isRawIpLiteral('192.168.0.1')).toBe(true)
  })

  it('recognizes the metadata IP literal 169.254.169.254', () => {
    expect(isRawIpLiteral('169.254.169.254')).toBe(true)
  })

  it('recognizes IPv6 literals by their colon', () => {
    expect(isRawIpLiteral('::1')).toBe(true)
    expect(isRawIpLiteral('fe80::1')).toBe(true)
  })

  it('rejects malformed dotted-quads with out-of-range octets', () => {
    expect(isRawIpLiteral('256.0.0.1')).toBe(false)
    expect(isRawIpLiteral('1.2.3')).toBe(false)
  })

  it('returns false for DNS names', () => {
    expect(isRawIpLiteral('example.com')).toBe(false)
    expect(isRawIpLiteral('a.b.c.d.example')).toBe(false)
  })
})

describe('isPrivateOrLoopbackHost', () => {
  it('flags private IPv4 ranges (loopback, link-local, RFC1918)', () => {
    expect(isPrivateOrLoopbackHost('10.0.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('172.20.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('192.168.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('127.0.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('169.254.0.1')).toBe(true)
    expect(isPrivateOrLoopbackHost('169.254.169.254')).toBe(true)
  })

  it('does NOT flag public IPv4 just outside the private ranges', () => {
    // 172.15.x and 172.32.x are public (the private band is only 172.16–172.31).
    expect(isPrivateOrLoopbackHost('172.15.0.1')).toBe(false)
    expect(isPrivateOrLoopbackHost('172.32.0.1')).toBe(false)
    expect(isPrivateOrLoopbackHost('8.8.8.8')).toBe(false)
  })

  it('flags internal names and IPv6 loopback/link-local', () => {
    expect(isPrivateOrLoopbackHost('localhost')).toBe(true)
    expect(isPrivateOrLoopbackHost('svc.internal')).toBe(true)
    expect(isPrivateOrLoopbackHost('host.local')).toBe(true)
    expect(isPrivateOrLoopbackHost('::1')).toBe(true)
    expect(isPrivateOrLoopbackHost('fe80::abcd')).toBe(true)
  })

  it('does NOT flag ordinary public hostnames', () => {
    expect(isPrivateOrLoopbackHost('example.com')).toBe(false)
    expect(isPrivateOrLoopbackHost('cdn.example.org')).toBe(false)
  })
})

// --- redirect tracer -------------------------------------------------------
//
// These tests drive `traceRedirects` with a MOCK fetch so cascades are
// deterministic and no real network is touched. The SSRF cases exercise the
// real (in-module) `assertSafeUrl` — that is the one integration point we keep
// live.

/** A small, fixed config so cap behavior is exercised at low hop counts. */
const TRACE_CONFIG: RedirectTraceConfig = {
  maxRedirectHops: 3,
  redirectTimeoutMs: 1000,
  allowedSchemes: new Set(['https']),
}

/**
 * Build a mock `fetch` from a routing table of `url -> {status, location}`.
 * A `location` makes the URL a 302 redirect; its absence makes it a final 200.
 * An unrouted URL throws, surfacing accidental over-fetching.
 */
function mockFetch(
  routes: Record<string, { status: number; location?: string }>,
): typeof fetch {
  const impl = async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    const route = routes[url]
    if (route === undefined) {
      throw new Error(`unexpected fetch for ${url}`)
    }
    const headers = new Headers()
    if (route.location !== undefined) {
      headers.set('Location', route.location)
    }
    return new Response(null, { status: route.status, headers })
  }
  return impl as unknown as typeof fetch
}

describe('traceRedirects', () => {
  it('follows N hops to a final 200 and reports the final URL', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'https://b.example/' },
      'https://b.example/': { status: 301, location: 'https://c.example/' },
      'https://c.example/': { status: 200 },
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.origin).toBe('https://a.example/')
    expect(chain.finalUrl).toBe('https://c.example/')
    expect(chain.hops.map((h) => [h.from, h.to])).toEqual([
      ['https://a.example/', 'https://b.example/'],
      ['https://b.example/', 'https://c.example/'],
    ])
    expect(chain.hops.every((h) => !h.dangerous)).toBe(true)
    expect(chain.dangerousHopIndex).toBeNull()
    expect(chain.depthExceeded).toBe(false)
    expect(chain.loopDetected).toBe(false)
  })

  it('resolves a relative Location against the current URL', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/start': { status: 302, location: '/next' },
      'https://a.example/next': { status: 200 },
    })

    const chain = await traceRedirects(
      'https://a.example/start',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.hops[0]?.to).toBe('https://a.example/next')
    expect(chain.finalUrl).toBe('https://a.example/next')
    expect(chain.loopDetected).toBe(false)
  })

  it('stops at maxRedirectHops and flags depthExceeded on an endless cascade', async () => {
    // Every URL redirects to the next: the cascade never terminates on its own.
    const endless: typeof fetch = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      const n = Number(new URL(url).searchParams.get('n') ?? '0')
      const headers = new Headers()
      headers.set('Location', `https://hop.example/?n=${n + 1}`)
      return Promise.resolve(new Response(null, { status: 302, headers }))
    }) as unknown as typeof fetch

    const chain = await traceRedirects(
      'https://hop.example/?n=0',
      TRACE_CONFIG,
      endless,
    )

    expect(chain.depthExceeded).toBe(true)
    expect(chain.loopDetected).toBe(false)
    // Exactly `maxRedirectHops` redirects were followed before the cap fired.
    expect(chain.hops).toHaveLength(TRACE_CONFIG.maxRedirectHops)
    expect(chain.dangerousHopIndex).toBeNull()
  })

  it('detects an A->B->A loop and flags loopDetected', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'https://b.example/' },
      'https://b.example/': { status: 302, location: 'https://a.example/' },
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.loopDetected).toBe(true)
    expect(chain.depthExceeded).toBe(false)
    expect(chain.dangerousHopIndex).toBeNull()
    // A->B and B->A were recorded; the second return to A tripped the guard.
    expect(chain.hops.map((h) => [h.from, h.to])).toEqual([
      ['https://a.example/', 'https://b.example/'],
      ['https://b.example/', 'https://a.example/'],
    ])
  })

  it('applies the SSRF guard: a public host redirecting to a private one is marked dangerous and stops', async () => {
    // A public origin hops to an RFC1918 private address. The guard must refuse
    // to fetch the private destination and record it as a dangerous hop.
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'http://10.0.0.5/' },
      // The private URL must NEVER be fetched; routing it would over-fetch.
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.dangerousHopIndex).toBe(1)
    const dangerous = chain.hops[1]
    expect(dangerous?.dangerous).toBe(true)
    expect(dangerous?.from).toBe('http://10.0.0.5/')
    expect(dangerous?.reason).not.toBeNull()
    // Tracing halted at the dangerous hop; no further hops were recorded.
    expect(chain.hops).toHaveLength(2)
    expect(chain.depthExceeded).toBe(false)
    expect(chain.loopDetected).toBe(false)
  })

  it('applies the SSRF guard: a hop to loopback 127.0.0.1 is marked dangerous and stops', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'http://127.0.0.1/' },
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.dangerousHopIndex).toBe(1)
    expect(chain.hops[1]?.dangerous).toBe(true)
    expect(chain.hops[1]?.from).toBe('http://127.0.0.1/')
    expect(chain.hops).toHaveLength(2)
  })

  it('applies the SSRF guard: a hop to a link-local address is marked dangerous and stops', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'http://169.254.10.10/' },
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.dangerousHopIndex).toBe(1)
    expect(chain.hops[1]?.dangerous).toBe(true)
    expect(chain.hops[1]?.from).toBe('http://169.254.10.10/')
  })

  it('applies the SSRF guard: a hop to the cloud metadata IP 169.254.169.254 is marked dangerous and stops', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': {
        status: 302,
        location: 'http://169.254.169.254/latest/meta-data/',
      },
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.dangerousHopIndex).toBe(1)
    const dangerous = chain.hops[1]
    expect(dangerous?.dangerous).toBe(true)
    expect(dangerous?.from).toBe('http://169.254.169.254/latest/meta-data/')
    expect(dangerous?.reason).not.toBeNull()
    expect(chain.hops).toHaveLength(2)
  })

  it('rejects a redirect to a disallowed scheme by treating the hop as dangerous', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'ftp://a.example/file' },
    })

    const chain = await traceRedirects(
      'https://a.example/',
      TRACE_CONFIG,
      fetchImpl,
    )

    expect(chain.dangerousHopIndex).toBe(1)
    expect(chain.hops[1]?.dangerous).toBe(true)
  })

  it('fails closed by raising RedirectResolutionError on a transport failure', async () => {
    const failing: typeof fetch = (() =>
      Promise.reject(new TypeError('network down'))) as unknown as typeof fetch

    await expect(
      traceRedirects('https://a.example/', TRACE_CONFIG, failing),
    ).rejects.toBeInstanceOf(RedirectResolutionError)
  })
})
