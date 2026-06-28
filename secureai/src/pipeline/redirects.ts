/**
 * Manual redirect-cascade tracer with its co-located SSRF guard.
 *
 * A skill's links are followed hop-by-hop with `redirect: 'manual'` so the
 * scanner sees every intermediate destination — the exact surface a redirect
 * laundering attack hides behind. Every hop URL is run through the SSRF guard
 * *before* it is fetched, the cascade is bounded by a configured depth cap, and
 * a normalized-URL set catches loops. Nothing here trusts the network to
 * terminate on its own.
 *
 * The SSRF guard lives in this module (not a separate file) because it belongs
 * with the tracer: it is the per-hop admission control the tracer cannot run a
 * single fetch without. The Worker follows redirect cascades by issuing real
 * subrequests; without the guard, an attacker-controlled redirect could point
 * the Worker at an internal address (cloud metadata, RFC1918 ranges, loopback)
 * to exfiltrate data or pivot inside the network. Cloudflare Workers cannot
 * inspect the *resolved* IP of a fetch, so enforcement is hostname- and
 * scheme-based:
 *
 *   - scheme must be in `config.allowedSchemes` (https-only by default);
 *   - the host must not be a raw IPv4/IPv6 literal (bypasses name-based policy);
 *   - the host must not be a private (RFC1918), loopback, link-local, or
 *     internal-only name (`localhost`, `*.internal`, `*.local`).
 *
 * RESIDUAL LIMITATION — DNS rebinding: a *public* hostname can still resolve to
 * a private IP at fetch time, and the Worker has no visibility into that
 * resolution, so these literal/name checks cannot catch it. This is inherent to
 * the Workers runtime. The compensating control is that the scanner never pulls
 * attacker page *content* itself — Exa (a sandboxed external fetcher) does — so
 * the blast radius of a rebind is limited to a redirect HEAD/GET against an
 * internal address with no response body surfaced to the client. Document, do
 * not pretend to fully solve.
 *
 * Fail-closed posture: a hop that the SSRF guard rejects is recorded as a
 * dangerous hop and the cascade stops (we never fetch it). A genuine transport
 * failure (network error / timeout) cannot be resolved into a verdict here, so
 * it is raised as `RedirectResolutionError` for the orchestrator to escalate —
 * it is never swallowed into a "clean" chain.
 *
 * Config is passed in by the caller; the allowed-scheme set, hop cap, and
 * timeout are never hardcoded here.
 */

import type { LinkChain, RedirectHop } from '../schemas/contract'
import { RedirectResolutionError } from '../errors'

/**
 * The slice of runtime config the SSRF guard depends on. The full config object
 * structurally satisfies this interface.
 */
export interface SsrfConfig {
  /**
   * Allowed URL schemes (lowercase, no trailing colon), e.g. `["https"]`.
   * A `ReadonlySet` so membership is O(1) and the set cannot be mutated through
   * this reference.
   */
  readonly allowedSchemes: ReadonlySet<string>
}

/**
 * The slice of runtime config the redirect tracer needs. Declared structurally
 * so the module stays decoupled from the full config and is trivially testable;
 * the real config object satisfies this shape.
 */
export interface RedirectTraceConfig {
  /** Maximum number of redirect hops to follow before declaring depth exceeded. */
  maxRedirectHops: number
  /** Per-hop fetch timeout in milliseconds (drives `AbortSignal.timeout`). */
  redirectTimeoutMs: number
  /**
   * Allowlisted URL schemes for the per-hop SSRF guard (e.g. `new Set(["https"])`).
   * Structurally satisfies {@link SsrfConfig} so it can be passed straight to
   * `assertSafeUrl`.
   */
  allowedSchemes: ReadonlySet<string>
}

/** RFC1918 private ranges, expressed as first-octet (and second-octet) tests. */
const PRIVATE_10_OCTET = 10
const PRIVATE_172_OCTET = 172
const PRIVATE_172_SECOND_MIN = 16
const PRIVATE_172_SECOND_MAX = 31
const PRIVATE_192_FIRST_OCTET = 192
const PRIVATE_192_SECOND_OCTET = 168
const LOOPBACK_OCTET = 127
const LINK_LOCAL_FIRST_OCTET = 169
const LINK_LOCAL_SECOND_OCTET = 254
const IPV4_OCTET_COUNT = 4
const OCTET_MIN = 0
const OCTET_MAX = 255

/**
 * Hostnames that always resolve to the local or an internal-only namespace and
 * must never be fetched, regardless of resolution. Lowercase. A `Set` for O(1)
 * membership.
 */
const INTERNAL_EXACT_HOSTS: ReadonlySet<string> = new Set(['localhost'])

/**
 * Internal-only TLD suffixes. Any host ending in one of these is internal by
 * convention (`*.internal` for cloud VPCs, `*.local` for mDNS). Includes the
 * leading dot so a host equal to the bare suffix is not matched as a subdomain.
 */
const INTERNAL_SUFFIXES: readonly string[] = ['.internal', '.local']

/** A bare IPv4 dotted-quad, e.g. `192.168.0.1`. Anchored to the whole host. */
const IPV4_LITERAL = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** HTTP status codes that carry a `Location` redirect. */
const REDIRECT_STATUS_MIN = 300
const REDIRECT_STATUS_MAX = 399

/**
 * Assert that a URL is safe for the Worker to fetch. Throws on any violation;
 * returns nothing on success (the guard's value is the absence of an exception).
 *
 * Order of checks (cheapest, most categorical first):
 *   1. scheme allowlist (rejects http, ftp, file, gopher, data, …);
 *   2. raw IP literal rejection (an IP host bypasses name-based policy entirely);
 *   3. private / loopback / link-local / internal-name rejection.
 *
 * The raw-IP-literal rejection in step 2 covers the cloud metadata address
 * `169.254.169.254` (a link-local literal) — it is refused before any name-based
 * check even runs.
 *
 * Time complexity: O(1) — a fixed number of set lookups, a bounded regex on the
 *   host, and constant suffix comparisons. No scan over the URL length.
 * Space complexity: O(1).
 *
 * @param url - The fully-parsed candidate URL (origin or a redirect target).
 * @param config - The {@link SsrfConfig} slice (allowed schemes).
 * @throws {RedirectResolutionError} If the scheme is disallowed, the host is a
 *   raw IP literal, or the host is private/loopback/link-local/internal.
 */
export function assertSafeUrl(url: URL, config: SsrfConfig): void {
  // `URL.protocol` includes the trailing colon ("https:"); normalize to "https".
  const scheme = url.protocol.replace(/:$/, '').toLowerCase()
  if (!config.allowedSchemes.has(scheme)) {
    throw new RedirectResolutionError(
      `disallowed URL scheme '${scheme}' for ${url.href}`,
    )
  }

  // `URL.hostname` already strips the port and lowercases; for IPv6 it is the
  // bracketed-content form without brackets (e.g. "::1").
  const host = url.hostname.toLowerCase()

  if (isRawIpLiteral(host)) {
    throw new RedirectResolutionError(
      `raw IP literal host is not allowed: ${host}`,
    )
  }

  if (isPrivateOrLoopbackHost(host)) {
    throw new RedirectResolutionError(
      `private/loopback/link-local/internal host is not allowed: ${host}`,
    )
  }
}

/**
 * Report whether `host` is a raw IPv4 or IPv6 literal (as opposed to a DNS
 * name). Raw IP hosts are rejected outright because they sidestep every
 * name-based policy below.
 *
 * IPv4: a valid dotted-quad with each octet in 0..255.
 * IPv6: any host containing a colon. `URL.hostname` only yields a colon for an
 *   IPv6 address (it has already removed the surrounding brackets and the port),
 *   so a single colon test is sufficient and unambiguous for parsed URLs.
 *
 * Time complexity: O(1) — bounded regex + constant comparisons. Space: O(1).
 *
 * @param host - Lowercase hostname from a parsed URL.
 * @returns `true` if the host is a raw IP literal.
 */
export function isRawIpLiteral(host: string): boolean {
  if (host.includes(':')) {
    // IPv6 literal (e.g. "::1", "fe80::1", "2001:db8::1"). For a parsed URL the
    // only source of a colon in hostname is an IPv6 address.
    return true
  }
  return parseIpv4Octets(host) !== null
}

/**
 * Report whether `host` is private (RFC1918), loopback, link-local, or an
 * internal-only name. Covers both IPv4 literals (by octet ranges) and DNS names
 * (`localhost`, `*.internal`, `*.local`) and the canonical IPv6 loopback/
 * link-local forms.
 *
 * IPv4 ranges rejected:
 *   - 10.0.0.0/8        (RFC1918)
 *   - 172.16.0.0/12     (RFC1918, second octet 16..31)
 *   - 192.168.0.0/16    (RFC1918)
 *   - 127.0.0.0/8       (loopback)
 *   - 169.254.0.0/16    (link-local)
 * IPv6 forms rejected: `::1` (loopback), `fe80::/10` link-local prefixes.
 * Names rejected: `localhost`, and any host ending in `.internal` / `.local`.
 *
 * Time complexity: O(1) — constant octet/prefix/suffix comparisons. Space: O(1).
 *
 * @param host - Lowercase hostname from a parsed URL.
 * @returns `true` if the host is private/loopback/link-local/internal.
 */
export function isPrivateOrLoopbackHost(host: string): boolean {
  if (INTERNAL_EXACT_HOSTS.has(host)) {
    return true
  }
  for (const suffix of INTERNAL_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return true
    }
  }

  if (host.includes(':')) {
    return isPrivateIpv6(host)
  }

  const octets = parseIpv4Octets(host)
  if (octets !== null) {
    return isPrivateIpv4(octets)
  }

  return false
}

/**
 * Parse a host into four validated IPv4 octets, or `null` if it is not a
 * well-formed dotted-quad. Each octet must be 0..255 with no leading-zero
 * ambiguity beyond what `Number` tolerates; out-of-range values yield `null`.
 *
 * Time complexity: O(1) — fixed-size match and four bounded conversions.
 * Space complexity: O(1) (a 4-element tuple).
 */
function parseIpv4Octets(
  host: string,
): readonly [number, number, number, number] | null {
  const match = IPV4_LITERAL.exec(host)
  if (match === null) {
    return null
  }
  const octets: number[] = []
  for (let i = 1; i <= IPV4_OCTET_COUNT; i += 1) {
    const part = match[i]
    if (part === undefined) {
      return null
    }
    const value = Number(part)
    if (
      !Number.isInteger(value) ||
      value < OCTET_MIN ||
      value > OCTET_MAX
    ) {
      return null
    }
    octets.push(value)
  }
  return [octets[0]!, octets[1]!, octets[2]!, octets[3]!]
}

/**
 * Decide whether a validated IPv4 octet tuple falls in a private/loopback/
 * link-local range.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function isPrivateIpv4(
  octets: readonly [number, number, number, number],
): boolean {
  const [first, second] = octets
  if (first === PRIVATE_10_OCTET) {
    return true
  }
  if (
    first === PRIVATE_172_OCTET &&
    second >= PRIVATE_172_SECOND_MIN &&
    second <= PRIVATE_172_SECOND_MAX
  ) {
    return true
  }
  if (first === PRIVATE_192_FIRST_OCTET && second === PRIVATE_192_SECOND_OCTET) {
    return true
  }
  if (first === LOOPBACK_OCTET) {
    return true
  }
  if (first === LINK_LOCAL_FIRST_OCTET && second === LINK_LOCAL_SECOND_OCTET) {
    return true
  }
  return false
}

/**
 * Decide whether an IPv6 literal host is loopback or link-local. Operates on
 * the bracket-free, lowercased form produced by `URL.hostname`.
 *
 * Recognizes:
 *   - `::1` loopback (and its uncompressed form `0:0:0:0:0:0:0:1`);
 *   - `fe80::/10` link-local, i.e. any address whose first hextet is in
 *     `fe80`..`febf`. We test the documented `fe8`/`fe9`/`fea`/`feb` prefixes,
 *     which exactly cover that /10 for the leading hextet.
 *
 * Time complexity: O(1) — constant prefix/equality checks. Space: O(1).
 */
function isPrivateIpv6(host: string): boolean {
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') {
    return true
  }
  return (
    host.startsWith('fe8') ||
    host.startsWith('fe9') ||
    host.startsWith('fea') ||
    host.startsWith('feb')
  )
}

/**
 * Normalize a URL for loop detection.
 *
 * Uses the WHATWG URL serialization (`href`), which canonicalizes scheme/host
 * casing, default ports, and path so that two textually different spellings of
 * the same location collide in the visited set.
 *
 * Time complexity: O(m) in URL length. Space complexity: O(m).
 *
 * @param url - An absolute URL string.
 * @returns The canonical serialized form.
 */
function normalizeUrl(url: string): string {
  return new URL(url).href
}

/** Outcome of resolving a 3xx response's `Location` header. */
type LocationResolution =
  | { kind: 'none' }
  | { kind: 'resolved'; url: string }
  | { kind: 'malformed'; raw: string }

/**
 * Read the `Location` header of a 3xx response and resolve it against the URL
 * that produced the response (relative redirects are legal and common).
 *
 * A malformed `Location` is reported as `malformed` (never thrown) so the
 * caller can record it as a dangerous, terminal hop — fail-closed, not a raw
 * `TypeError` escaping the tracer.
 *
 * Time complexity: O(m) in the resolved URL length. Space complexity: O(m).
 *
 * @param response - The hop response (already known to be a 3xx).
 * @param currentUrl - The absolute URL the response was fetched from.
 * @returns A {@link LocationResolution} discriminated on whether a `Location`
 *   was present and parseable.
 */
function resolveLocation(
  response: Response,
  currentUrl: string,
): LocationResolution {
  const location = response.headers.get('Location')
  if (location === null || location.length === 0) {
    return { kind: 'none' }
  }
  // Resolve relative Locations against the current URL; absolute ones pass
  // through unchanged.
  try {
    return { kind: 'resolved', url: new URL(location, currentUrl).href }
  } catch {
    return { kind: 'malformed', raw: location }
  }
}

/**
 * Trace a URL's redirect cascade hop-by-hop, with SSRF guards, a depth cap,
 * and loop detection.
 *
 * Algorithm (single forward walk, no rescans):
 *   1. Run `assertSafeUrl` on the current URL. If it throws, record a dangerous
 *      hop carrying the guard's reason and stop (the URL is never fetched).
 *   2. If the current URL was already visited, set `loopDetected` and stop.
 *   3. Fetch with `redirect: 'manual'` and a per-hop abort timeout. A transport
 *      failure raises `RedirectResolutionError` (fail-closed — never resolves to
 *      a clean chain).
 *   4. If the status is not a 3xx with a usable `Location`, the current URL is
 *      final — stop.
 *   5. Otherwise record the hop, advance to the resolved Location, and repeat.
 *      Exceeding `maxRedirectHops` sets `depthExceeded` and stops.
 *
 * Time complexity: O(h) where h = number of hops (≤ `maxRedirectHops`); one
 *   fetch per hop, one set lookup per hop. Space complexity: O(h) for the hop
 *   list and the visited set.
 *
 * @param startUrl - The origin URL extracted from the skill.
 * @param config - Depth cap and per-hop timeout.
 * @param fetchImpl - Injected fetch (defaults to global `fetch`); tests pass a
 *   mock to drive deterministic cascades.
 * @returns The traced {@link LinkChain}: origin, hops, final URL, first
 *   dangerous hop index (or null), and the depth/loop flags.
 * @throws {RedirectResolutionError} On a transport failure or timeout while
 *   fetching a hop.
 */
export async function traceRedirects(
  startUrl: string,
  config: RedirectTraceConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<LinkChain> {
  const hops: RedirectHop[] = []
  const visited = new Set<string>()
  let dangerousHopIndex: number | null = null
  let depthExceeded = false
  let loopDetected = false

  let currentUrl = startUrl

  // The loop is bounded by `maxRedirectHops`: each iteration either terminates
  // the cascade (final/dangerous/loop) or consumes one hop budget. The extra
  // `<=` lets us detect the *overflow* iteration so `depthExceeded` is set
  // exactly when a further redirect would push past the cap.
  for (let hopCount = 0; ; hopCount += 1) {
    // 1. SSRF guard BEFORE any network access. A rejection is terminal and
    //    dangerous; we record it and never fetch the URL.
    try {
      assertSafeUrl(new URL(currentUrl), config)
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : String(error)
      dangerousHopIndex = hops.length
      hops.push({
        from: currentUrl,
        to: currentUrl,
        status: 0,
        dangerous: true,
        reason,
      })
      break
    }

    // 2. Loop detection on the normalized form (before fetching again).
    const normalized = normalizeUrl(currentUrl)
    if (visited.has(normalized)) {
      loopDetected = true
      break
    }
    visited.add(normalized)

    // 3. Depth cap: if we have already followed `maxRedirectHops` redirects and
    //    are about to follow another, stop and flag depth exceeded.
    if (hopCount >= config.maxRedirectHops) {
      depthExceeded = true
      break
    }

    // 4. Fetch the current URL without auto-following redirects. A transport
    //    failure is fail-closed: it cannot yield a clean chain.
    let response: Response
    try {
      response = await fetchImpl(currentUrl, {
        redirect: 'manual',
        signal: AbortSignal.timeout(config.redirectTimeoutMs),
      })
    } catch (error: unknown) {
      const cause = error instanceof Error ? error.constructor.name : 'unknown'
      throw new RedirectResolutionError(
        `fetch failed while tracing redirect hop ${hops.length} ` +
          `(${currentUrl}): ${cause}`,
        { cause: error },
      )
    }

    // 5. Non-redirect status (or a 3xx with no Location) means the current URL
    //    is the final destination — terminate.
    const isRedirect =
      response.status >= REDIRECT_STATUS_MIN &&
      response.status <= REDIRECT_STATUS_MAX
    if (!isRedirect) {
      break
    }
    const resolution = resolveLocation(response, currentUrl)
    if (resolution.kind === 'none') {
      break
    }
    if (resolution.kind === 'malformed') {
      // A redirect we cannot parse cannot be followed safely — record it as a
      // dangerous, terminal hop (fail-closed) rather than guessing.
      dangerousHopIndex = hops.length
      hops.push({
        from: currentUrl,
        to: resolution.raw,
        status: response.status,
        dangerous: true,
        reason: `malformed Location header: ${resolution.raw}`,
      })
      break
    }

    // 6. Record the hop and advance.
    hops.push({
      from: currentUrl,
      to: resolution.url,
      status: response.status,
      dangerous: false,
      reason: null,
    })
    currentUrl = resolution.url
  }

  return {
    origin: startUrl,
    hops,
    finalUrl: currentUrl,
    dangerousHopIndex,
    depthExceeded,
    loopDetected,
  }
}
