/**
 * Edge verdict cache — a low-latency KV layer in front of the pure
 * {@link runScan} compute (CLAUDE.md lists a verdict cache as an O(1) runtime
 * target).
 *
 * It caches the COMPUTATION ONLY, never the per-caller side effects. A repeated
 * identical scan (e.g. the Guard re-checking the same tool call) returns the
 * previously-computed {@link ScanResult} without re-tracing redirects or
 * re-running the AI stage. Auth, the daily-cap check, usage metering, and the
 * scan-history insert STILL run for the current caller on a cache HIT — those
 * decisions live in the route, not here; this module's sole job is to resolve
 * the cached-or-fresh result.
 *
 * The cache key is `scan:v1:` + sha256(canonical(request)), where `canonical`
 * is the sorted-key JSON of just the scannable inputs ({content?, sourceUrl?}),
 * so two requests with the same scannable content share an entry regardless of
 * field ordering or unrelated wrapper fields.
 *
 * Proof integrity: the cached value is the full serialized `ScanResult`. On a
 * HIT the route stamps a FRESH `scannedAt` at the edge; `scannedAt` lives
 * OUTSIDE the hashed proof, so re-stamping it leaves the proof (and `headHash`)
 * byte-identical and still verifiable.
 *
 * Security tradeoff (documented): the TTL is short. The cache serves identical
 * content for the window, so a denylist/indicator change made mid-window could
 * be briefly masked until the entry expires. A short TTL bounds that window;
 * `verdictCacheTtlSeconds = 0` disables the cache entirely.
 */

import type { ScanRequest, ScanResult } from '../schemas/contract'
import { canonicalJson } from '../audit/chain'

/** Namespaced, versioned prefix for every verdict-cache key. */
const CACHE_KEY_PREFIX = 'scan:v1:'

const textEncoder = new TextEncoder()

/**
 * The minimal Cloudflare KV surface the verdict cache uses: a string `get` and a
 * `put` with an optional `expirationTtl`. Declared structurally (rather than
 * depending on the full `KVNamespace` type) so a test can inject a tiny
 * `{ get, put }` fake, mirroring {@link ../pipeline/indicators.IndicatorKv}.
 */
export interface VerdictCacheKv {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/**
 * Lowercase-hex SHA-256 of a UTF-8 string, matching the audit chain's hashing
 * approach. Used to derive a fixed-length, collision-resistant cache key from
 * the (possibly large) canonical request bytes.
 *
 * Time complexity: O(n) in `value` byte length. Space complexity: O(n).
 */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  const view = new Uint8Array(digest)
  let hex = ''
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Derive the cache key for a scan request: `scan:v1:` + sha256 of the canonical
 * JSON of ONLY the scannable inputs. Building the canonical object explicitly
 * (never spreading the raw request) means an unrelated wrapper field can never
 * perturb the key, and key ordering is normalized by {@link canonicalJson}.
 *
 * Time complexity: O(n) in the request byte length. Space complexity: O(n).
 *
 * @param request - The validated scan request.
 * @returns The namespaced cache key.
 */
export async function cacheKeyForRequest(request: ScanRequest): Promise<string> {
  // Only present fields enter the canonical object: `canonicalJson` rejects an
  // explicit `undefined` value, and an absent field must not perturb the key.
  const scannable: Record<string, string> = {}
  if (request.content !== undefined) {
    scannable['content'] = request.content
  }
  if (request.sourceUrl !== undefined) {
    scannable['sourceUrl'] = request.sourceUrl
  }
  return CACHE_KEY_PREFIX + (await sha256Hex(canonicalJson(scannable)))
}

/**
 * Parse a cached KV value back into a {@link ScanResult}. A value that is not
 * valid JSON (a truncated / corrupt entry) is treated as a MISS by returning
 * `null` — the route then recomputes — rather than throwing; a stale-cache
 * corruption must never fail an otherwise-valid scan.
 *
 * Time complexity: O(n) in the value length. Space complexity: O(n).
 */
function parseCached(value: string): ScanResult | null {
  try {
    return JSON.parse(value) as ScanResult
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    console.warn(`[verdictCache] discarding unparseable cache entry (${className})`)
    return null
  }
}

/**
 * Resolve a scan to its {@link ScanResult}, serving from the verdict cache when
 * one is available and recomputing (then populating the cache) on a miss.
 *
 * Resolution:
 *   - Cache disabled (no KV, or `ttlSeconds <= 0`): always run `compute()`; no
 *     KV access at all.
 *   - HIT: return the cached result with a FRESH `scannedAt` stamped from
 *     `freshScannedAt` (the proof is unchanged because `scannedAt` is outside
 *     it). `cached` is `true`.
 *   - MISS: run `compute()`, write the serialized result to KV with
 *     `expirationTtl = ttlSeconds`, and return it. `cached` is `false`.
 *
 * The function does NOT meter, record history, or enforce caps — those are the
 * caller's per-request responsibilities and must run on a HIT just as on a MISS.
 * Only the `compute()` (i.e. `runScan`) work is skipped on a HIT.
 *
 * Idempotency: the PUT is keyed by the content hash, so a concurrent miss simply
 * overwrites an identical value — never corrupting the entry.
 *
 * Time complexity: one KV read (+ one KV write on a miss) plus `compute()` on a
 *   miss. Space complexity: O(result size).
 *
 * @param request - The validated scan request (keys the cache).
 * @param kv - The verdict-cache KV namespace, or `null` when unbound.
 * @param ttlSeconds - The cache TTL; `0` (or negative) disables the cache.
 * @param freshScannedAt - The edge timestamp to stamp on the returned result.
 * @param compute - Runs the real scan (`runScan`) on a miss. Must already be
 *   bound to a `scannedAt`; this function overwrites it with `freshScannedAt`
 *   so the returned timestamp is always the current edge time.
 * @returns The resolved result and whether it came from the cache.
 */
export async function resolveCachedScan(
  request: ScanRequest,
  kv: VerdictCacheKv | null,
  ttlSeconds: number,
  freshScannedAt: string,
  compute: () => Promise<ScanResult>,
): Promise<{ result: ScanResult; cached: boolean }> {
  if (kv === null || ttlSeconds <= 0) {
    const result = await compute()
    return { result, cached: false }
  }

  const key = await cacheKeyForRequest(request)

  const hit = await kv.get(key)
  if (hit !== null) {
    const parsed = parseCached(hit)
    if (parsed !== null) {
      // Stamp a fresh edge timestamp; `scannedAt` is outside the hashed proof,
      // so the proof stays valid.
      return { result: { ...parsed, scannedAt: freshScannedAt }, cached: true }
    }
  }

  const result = await compute()
  await kv.put(key, JSON.stringify(result), { expirationTtl: ttlSeconds })
  return { result, cached: false }
}
