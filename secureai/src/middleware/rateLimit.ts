/**
 * Per-client fixed-window rate limiting over Cloudflare KV — the shared abuse
 * bound behind the public auth and contact endpoints. Extracted from the contact
 * route's original limiter so a single, tested implementation backs every
 * caller (CLAUDE.md §1, DRY).
 *
 * Window model: a fixed clock-hour bucket keyed by `floor(now / 3600)`, so each
 * identity gets `limit` requests per hour against a given key prefix; the KV
 * entry carries a one-hour TTL so a stale bucket self-expires (no cleanup pass).
 * Read-check-write means a benign race under concurrency can only UNDER-count by
 * a hair (two reads seeing the same value) — acceptable for an anti-abuse bound,
 * and it never over-counts a legitimate caller. A corrupt/non-numeric counter
 * fails CLOSED (treated as the cap) so a poisoned entry cannot lift the limit.
 */

/** Seconds in one hour — the window length and the KV entry TTL. */
const SECONDS_PER_HOUR = 3600

/** Cloudflare's true-client-IP header, used to key per-IP limits. */
const CLIENT_IP_HEADER = 'CF-Connecting-IP'

/** Key segment used when no client IP is present (one shared bucket). */
const UNKNOWN_IP = 'unknown'

/**
 * The minimal Cloudflare KV surface a rate limit needs: a string `get` and a
 * `put` with an optional `expirationTtl`. Declared structurally (rather than
 * depending on the full `KVNamespace` type) so a test can inject a tiny
 * `{ get, put }` fake.
 */
export interface RateLimitKv {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/**
 * Resolve the client IP from the `CF-Connecting-IP` header, or a shared
 * `unknown` bucket when it is absent/blank. The IP only keys the rate limit; it
 * is never stored or logged.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function clientIp(request: Request): string {
  const ip = request.headers.get(CLIENT_IP_HEADER)?.trim()
  return ip !== undefined && ip.length > 0 ? ip : UNKNOWN_IP
}

/**
 * Enforce a per-identity hourly cap against KV, returning `true` when the request
 * is within budget (and recording it) or `false` when the cap is already reached.
 *
 * The key is `${keyPrefix}${identity}:${bucket}` where `bucket = floor(now /
 * 3600)`. `keyPrefix` should be a namespaced, versioned literal (e.g.
 * `auth:login:v1:`) so distinct endpoints never share a counter.
 *
 * Time complexity: O(1) — one KV read + one KV write. Space complexity: O(1).
 *
 * @param kv - The rate-limit store (non-null; the caller skips this on `null`).
 * @param keyPrefix - Namespaced, versioned key prefix identifying the endpoint.
 * @param identity - The per-caller key (e.g. client IP) within the namespace.
 * @param limit - The max requests per hour for this identity.
 * @param nowSeconds - The current edge time in whole seconds (bucket selector).
 * @returns `true` if within budget (request recorded), else `false`.
 */
export async function withinHourlyLimit(
  kv: RateLimitKv,
  keyPrefix: string,
  identity: string,
  limit: number,
  nowSeconds: number,
): Promise<boolean> {
  const bucket = Math.floor(nowSeconds / SECONDS_PER_HOUR)
  const key = `${keyPrefix}${identity}:${bucket}`
  const raw = await kv.get(key)
  const used = raw === null ? 0 : Number.parseInt(raw, 10)
  // A corrupt/non-numeric entry fails closed: treat it as the cap so a poisoned
  // counter cannot be used to lift the limit.
  const current = Number.isFinite(used) && used >= 0 ? used : limit
  if (current >= limit) {
    return false
  }
  await kv.put(key, String(current + 1), { expirationTtl: SECONDS_PER_HOUR })
  return true
}
